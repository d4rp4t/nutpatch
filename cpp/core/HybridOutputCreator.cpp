//
// Created by d4rp4t on 10/04/2026.
//
// we're operating on ulong type, but some parameters must be compatible with javascript's bigint

#include <algorithm>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <mutex>

#include "crypto.h"
extern "C" {
#include "../vendor/trezor/memzero.h"
}
#include "HybridOutputCreator.hpp"
#include "NativeOutputData.hpp"
#include "NitroP2PKOptions.hpp"
#include "Keyset.hpp"

namespace margelo::nitro::nutpatch {

    static std::once_flag crypto_init_flag;

    HybridOutputCreator::HybridOutputCreator() : HybridObject(TAG) {
        std::call_once(crypto_init_flag, []() {
            crypto_init();
        });
    }

    static constexpr char HEX[] = "0123456789abcdef";
    // matches cashu-ts MAX_SECRET_LENGTH (Nutshell default mint_max_secret_length).
    static constexpr size_t MAX_SECRET_LENGTH = 1024;

    static std::string bytes_to_hex(const uint8_t* data, size_t len) {
        std::string result(len * 2, '\0');
        for (size_t i = 0; i < len; i++) {
            result[i * 2]     = HEX[data[i] >> 4];
            result[i * 2 + 1] = HEX[data[i] & 0xF];
        }
        return result;
    }

    static size_t utf8_code_points(const std::string& s) {
        size_t count = 0;
        for (size_t i = 0; i < s.size(); ) {
            const unsigned char c = static_cast<unsigned char>(s[i]);
            size_t step;
            if ((c & 0x80) == 0x00) step = 1;
            else if ((c & 0xE0) == 0xC0) step = 2;
            else if ((c & 0xF0) == 0xE0) step = 3;
            else if ((c & 0xF8) == 0xF0) step = 4;
            else step = 1; // invalid lead byte — count as one
            
            // Check if string abruptly ends with incomplete sequence
            if (i + step > s.size()) {
                count += s.size() - i; // Count remaining bytes as individual characters
                break;
            }
            
            i += step;
            count++;
        }
        return count;
    }

    // RAII helper: zeros a memory region when it goes out of scope (including on throw)
    class ZeroGuard {
        void*  ptr_;
        size_t len_;
    public:
        ZeroGuard(void* p, size_t n) : ptr_(p), len_(n) {}
        ~ZeroGuard() { memzero(ptr_, len_); }
        ZeroGuard(const ZeroGuard&)            = delete;
        ZeroGuard& operator=(const ZeroGuard&) = delete;
    };

    static void generate_scalar(uint8_t* out32) {
        if (seckey_generate(out32) != CRYPTO_OK)
            throw std::runtime_error("seckey_generate failed");
    }

    // builds a descending list of available denominations from keyset
    static std::vector<uint32_t> parseDenominations(const Keyset& keyset) {
        std::vector<uint32_t> denoms;
        denoms.reserve(keyset.keys.size());
        for (const auto& [k, _] : keyset.keys)
            denoms.push_back(static_cast<uint32_t>(std::stoul(k)));
        std::sort(denoms.begin(), denoms.end(), std::greater<uint32_t>());
        return denoms;
    }

    // greedy split, mirrors cashu-ts splitAmount().
    // if customSplit is provided: non-zero values are used first, remainder filled greedily.
    static std::vector<uint32_t> splitAmounts(
        uint64_t amount,
        const Keyset& keyset,
        const std::optional<std::vector<uint64_t>>& customSplit
    ) {
        std::vector<uint32_t> result;

        if (customSplit.has_value()) {
            uint64_t customSum = 0;
            for (uint64_t v : customSplit.value()) {
                if (v == 0) continue;
                // cashu-ts rejects custom amounts not present as keyset keys.
                if (keyset.keys.find(std::to_string(v)) == keyset.keys.end())
                    throw std::runtime_error("Provided amount preferences do not match the amounts of the mint keyset.");
                result.push_back(static_cast<uint32_t>(v));
                if (UINT64_MAX - customSum < v)
                    throw std::runtime_error("Split sum integer overflow");
                customSum += v;
            }
            if (customSum > amount)
                throw std::runtime_error("Split is greater than total amount");
            if (customSum == amount)
                return result;
            amount -= customSum;
        }

        const auto denoms = parseDenominations(keyset);
        if (denoms.empty())
            throw std::runtime_error("Cannot split amount, keyset is inactive or contains no keys");

        for (const uint32_t denom : denoms) {
            uint64_t count = amount / denom;
            for (uint64_t i = 0; i < count; i++)
                result.push_back(denom);
            amount -= count * denom;
            if (amount == 0) break;
        }
        if (amount != 0)
            throw std::runtime_error("Unable to split remaining amount with available denominations");

        return result;
    }


    NativeOutputData HybridOutputCreator::createSingleRandomData(
        uint64_t amount,
        const std::string& keysetId
    ) {
        uint8_t raw[32];  ZeroGuard zg_raw(raw, sizeof(raw));
        generate_scalar(raw);
        std::string secret_hex = bytes_to_hex(raw, 32);

        uint8_t r[32], B_[33];  ZeroGuard zg_r(r, sizeof(r));
        generate_scalar(r);

        if (blind(reinterpret_cast<const uint8_t*>(secret_hex.data()),
                  secret_hex.size(), r, B_) != CRYPTO_OK)
            throw std::runtime_error("blind() failed");

        return NativeOutputData(
            NativeBlindedMessage(amount, bytes_to_hex(B_, 33), keysetId),
            bytes_to_hex(r, 32),
            secret_hex,
            ""
        );
    }

    std::vector<NativeOutputData> HybridOutputCreator::createRandomData(
        uint64_t amount,
        const Keyset& keyset,
        const std::optional<std::vector<uint64_t>>& customSplit
    ) {
        const auto amounts = splitAmounts(amount, keyset, customSplit);
        std::vector<NativeOutputData> result;
        result.reserve(amounts.size());
        for (uint32_t a : amounts)
            result.push_back(createSingleRandomData(a, keyset.id));
        return result;
    }


    static std::string escape_json_string(const std::string& s) {
        std::string out;
        out.reserve(s.size() + 4);
        for (char c : s) {
            switch (c) {
                case '"': out += "\\\""; break;
                case '\\': out += "\\\\"; break;
                case '\b': out += "\\b"; break;
                case '\f': out += "\\f"; break;
                case '\n': out += "\\n"; break;
                case '\r': out += "\\r"; break;
                case '\t': out += "\\t"; break;
                default:
                    if (static_cast<unsigned char>(c) <= 0x1f) {
                        char buf[8];
                        snprintf(buf, sizeof(buf), "\\u%04x", c);
                        out += buf;
                    } else {
                        out += c;
                    }
                    break;
            }
        }
        return out;
    }

    static std::string buildP2PKSecret(
        const std::string& nonce_hex,
        const NitroP2PKOptions& opts
    ) {
        const bool is_htlc = opts.hashlock.has_value() && !opts.hashlock.value().empty();
        const std::string& kind = is_htlc ? "HTLC" : "P2PK";
        const std::string& data = is_htlc ? escape_json_string(opts.hashlock.value()) : escape_json_string(opts.pubkeys[0]);

        std::string tags = "[";
        bool first = true;
        auto append_tag = [&](const std::string& tag) {
            if (!first) tags += ',';
            tags += tag;
            first = false;
        };

        // locktime — only if valid non-negative integer
        if (opts.locktime.has_value()) {
            double raw = opts.locktime.value();
            int64_t lt = static_cast<int64_t>(raw);
            constexpr int64_t JS_SAFE_INT_MAX = (1LL << 53) - 1;
            if (raw >= 0.0 && static_cast<double>(lt) == raw && lt <= JS_SAFE_INT_MAX)
                append_tag("[\"locktime\",\"" + std::to_string(lt) + "\"]");
        }

        const size_t pubkeys_start = is_htlc ? 0 : 1;
        if (opts.pubkeys.size() > pubkeys_start) {
            std::string tag = "[\"pubkeys\"";
            for (size_t i = pubkeys_start; i < opts.pubkeys.size(); i++) {
                tag += ",\"";
                tag += escape_json_string(opts.pubkeys[i]);
                tag += '"';
            }
            tag += ']';
            append_tag(tag);

            // n_sigs only when > 1
            uint64_t n_sigs = opts.requiredSignatures.has_value()
                ? static_cast<uint64_t>(opts.requiredSignatures.value())
                : 1;
            if (n_sigs > 1)
                append_tag("[\"n_sigs\",\"" + std::to_string(n_sigs) + "\"]");
        }

        // refund keys
        if (opts.refundKeys.has_value() && !opts.refundKeys.value().empty()) {
            std::string tag = "[\"refund\"";
            for (const auto& key : opts.refundKeys.value()) {
                tag += ",\"";
                tag += escape_json_string(key);
                tag += '"';
            }
            tag += ']';
            append_tag(tag);

            // n_sigs_refund only when > 1
            uint64_t n_sigs_r = opts.requiredRefundSignatures.has_value()
                ? static_cast<uint64_t>(opts.requiredRefundSignatures.value())
                : 1;
            if (n_sigs_r > 1)
                append_tag("[\"n_sigs_refund\",\"" + std::to_string(n_sigs_r) + "\"]");
        }

        // sigflag — only when SIG_ALL (SIG_INPUTS is default, not serialized)
        if (opts.sigFlag.has_value() && opts.sigFlag.value() == "SIG_ALL")
            append_tag("[\"sigflag\",\"SIG_ALL\"]");

        // additionalTags appended at end
        if (opts.additionalTags.has_value()) {
            for (const auto& tag_arr : opts.additionalTags.value()) {
                if (tag_arr.empty()) continue;
                std::string tag = "[\"" + escape_json_string(tag_arr[0]) + "\"";
                for (size_t i = 1; i < tag_arr.size(); i++) {
                    tag += ",\"";
                    tag += escape_json_string(tag_arr[i]);
                    tag += '"';
                }
                tag += ']';
                append_tag(tag);
            }
        }

        tags += ']';

        std::string secret;
        secret.reserve(64 + data.size() + tags.size());
        secret += "[\"";
        secret += kind;
        secret += "\",{\"nonce\":\"";
        secret += nonce_hex;
        secret += "\",\"data\":\"";
        secret += data;
        secret += "\",\"tags\":";
        secret += tags;
        secret += "}]";
        return secret;
    }

    static int hex_nibble(char c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    }

    static bool hex_to_fixed_bytes(const std::string& hex, uint8_t* out, size_t expected_bytes) {
        if (hex.size() != expected_bytes * 2) return false;
        for (size_t i = 0; i < expected_bytes; i++) {
            int hi = hex_nibble(hex[i * 2]);
            int lo = hex_nibble(hex[i * 2 + 1]);
            if (hi < 0 || lo < 0) return false;
            out[i] = static_cast<uint8_t>((hi << 4) | lo);
        }
        return true;
    }

    // If blindKeys is set, blinds opts.pubkeys (and refundKeys) in place,
    // clears the flag to prevent double-blinding, and returns hex(E).
    // Returns empty string when blinding is not requested.
    static std::string apply_p2bk_blinding(NitroP2PKOptions& opts) {
        if (!opts.blindKeys.has_value() || !opts.blindKeys.value()) return "";

        const size_t numLock   = opts.pubkeys.size();
        const size_t numRefund = opts.refundKeys.has_value()
                                 ? opts.refundKeys.value().size() : 0;
        const size_t total = numLock + numRefund;
        opts.blindKeys = false;
        if (total == 0) return "";
        if (total > 256)
            throw std::runtime_error("P2BK: at most 256 pubkeys supported");

        std::vector<uint8_t> flat(total * 33);
        for (size_t i = 0; i < numLock; i++) {
            if (!hex_to_fixed_bytes(opts.pubkeys[i], flat.data() + i * 33, 33))
                throw std::runtime_error("P2BK: pubkeys[" + std::to_string(i) +
                                         "] must be a 66-char hex string");
        }
        if (numRefund > 0) {
            const auto& rk = opts.refundKeys.value();
            for (size_t i = 0; i < numRefund; i++) {
                if (!hex_to_fixed_bytes(rk[i], flat.data() + (numLock + i) * 33, 33))
                    throw std::runtime_error("P2BK: refundKeys[" + std::to_string(i) +
                                             "] must be a 66-char hex string");
            }
        }

        std::vector<uint8_t> blinded_flat(total * 33);
        uint8_t E_out[33];

        crypto_err_t err = derive_p2bk_blinded_pubkeys(
            flat.data(), total, nullptr, blinded_flat.data(), E_out);
        if (err != CRYPTO_OK) {
            memzero(blinded_flat.data(), blinded_flat.size());
            memzero(E_out, sizeof(E_out));
            throw std::runtime_error("derive_p2bk_blinded_pubkeys failed");
        }

        for (size_t i = 0; i < numLock; i++)
            opts.pubkeys[i] = bytes_to_hex(blinded_flat.data() + i * 33, 33);
        if (numRefund > 0) {
            auto& rk = opts.refundKeys.value();
            for (size_t i = 0; i < numRefund; i++)
                rk[i] = bytes_to_hex(blinded_flat.data() + (numLock + i) * 33, 33);
        }
        return bytes_to_hex(E_out, 33);
    }

    // Core P2PK output builder. Caller must pass a fully-prepared `p2pk`
    // (already blinded if applicable) and the matching `ephemeralE`.
    static NativeOutputData buildP2PKOutput(
        const NitroP2PKOptions& p2pk,
        uint64_t amount,
        const std::string& keysetId,
        const std::string& ephemeralE
    ) {
        if (p2pk.pubkeys.empty())
            throw std::runtime_error("P2PK requires at least one pubkey");

        uint8_t nonce_raw[32];  ZeroGuard zg_nonce(nonce_raw, sizeof(nonce_raw));
        generate_scalar(nonce_raw);
        const std::string json_secret = buildP2PKSecret(bytes_to_hex(nonce_raw, 32), p2pk);

        const size_t char_count = utf8_code_points(json_secret);
        if (char_count > MAX_SECRET_LENGTH)
            throw std::runtime_error("Secret too long (" + std::to_string(char_count) +
                                     " characters), maximum is " + std::to_string(MAX_SECRET_LENGTH));

        uint8_t r[32], B_[33];  ZeroGuard zg_r(r, sizeof(r));
        generate_scalar(r);

        if (blind(reinterpret_cast<const uint8_t*>(json_secret.data()),
                  json_secret.size(), r, B_) != CRYPTO_OK)
            throw std::runtime_error("blind() failed");

        return NativeOutputData(
            NativeBlindedMessage(amount, bytes_to_hex(B_, 33), keysetId),
            bytes_to_hex(r, 32),
            json_secret,
            ephemeralE
        );
    }

    NativeOutputData HybridOutputCreator::createSingleP2PKData(
        const NitroP2PKOptions& p2pk,
        uint64_t amount,
        const std::string& keysetId
    ) {
        NitroP2PKOptions prepared = p2pk;
        const std::string ephemeralE = apply_p2bk_blinding(prepared);
        return buildP2PKOutput(prepared, amount, keysetId, ephemeralE);
    }

    std::vector<NativeOutputData> HybridOutputCreator::createP2PKData(
        const NitroP2PKOptions& p2pk,
        uint64_t amount,
        const Keyset& keyset,
        const std::optional<std::vector<uint64_t>>& customSplit
    ) {
        const auto amounts = splitAmounts(amount, keyset, customSplit);
        std::vector<NativeOutputData> result;
        result.reserve(amounts.size());
        for (uint32_t a : amounts) {
            NitroP2PKOptions prepared = p2pk;
            const std::string ephemeralE = apply_p2bk_blinding(prepared);
            result.push_back(buildP2PKOutput(prepared, a, keyset.id, ephemeralE));
        }
        return result;
    }

    NativeOutputData HybridOutputCreator::createSingleDeterministicData(
        uint64_t amount,
        const std::shared_ptr<ArrayBuffer>& seed,
        uint64_t counter,
        const std::string& keysetId
    ) {
        const uint8_t* seed_data = static_cast<const uint8_t*>(seed->data());
        size_t         seed_len  = seed->size();

        uint8_t secret_bytes[32];  ZeroGuard zg_s(secret_bytes, sizeof(secret_bytes));
        if (derive_secret(seed_data, seed_len, keysetId.c_str(), counter, secret_bytes) != CRYPTO_OK)
            throw std::runtime_error("derive_secret failed");

        std::string secret_hex = bytes_to_hex(secret_bytes, 32);

        uint8_t r[32];  ZeroGuard zg_r(r, sizeof(r));
        if (derive_blinding_factor(seed_data, seed_len, keysetId.c_str(), counter, r) != CRYPTO_OK)
            throw std::runtime_error("derive_blinding_factor failed");

        uint8_t B_[33];
        if (blind(reinterpret_cast<const uint8_t*>(secret_hex.data()), secret_hex.size(), r, B_) != CRYPTO_OK)
            throw std::runtime_error("blind() failed");

        return NativeOutputData(
            NativeBlindedMessage(amount, bytes_to_hex(B_, 33), keysetId),
            bytes_to_hex(r, 32),
            secret_hex,
            ""
        );
    }

    std::vector<NativeOutputData> HybridOutputCreator::createDeterministicData(
        uint64_t amount,
        const std::shared_ptr<ArrayBuffer>& seed,
        uint64_t counter,
        const Keyset& keyset,
        const std::optional<std::vector<uint64_t>>& customSplit
    ) {
        const auto amounts = splitAmounts(amount, keyset, customSplit);
        std::vector<NativeOutputData> result;
        result.reserve(amounts.size());
        for (size_t i = 0; i < amounts.size(); i++)
            result.push_back(createSingleDeterministicData(amounts[i], seed, counter + i, keyset.id));
        return result;
    }

} // namespace margelo::nitro::nutpatch
