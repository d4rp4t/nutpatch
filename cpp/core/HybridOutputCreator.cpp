//
// Created by d4rp4t on 10/04/2026.
//
// we're operating on ulong type, but some parameters must be compatible with javascript's bigint

#include <algorithm>
#include <cstdint>
#include <optional>
#include <stdexcept>

#include "crypto.h"
#include "HybridOutputCreator.hpp"
#include "NativeOutputData.hpp"
#include "NitroP2PKOptions.hpp"
#include "Keyset.hpp"

namespace margelo::nitro::nutpatch {

    static constexpr char HEX[] = "0123456789abcdef";

    static std::string bytes_to_hex(const uint8_t* data, size_t len) {
        std::string result(len * 2, '\0');
        for (size_t i = 0; i < len; i++) {
            result[i * 2]     = HEX[data[i] >> 4];
            result[i * 2 + 1] = HEX[data[i] & 0xF];
        }
        return result;
    }

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
                result.push_back(static_cast<uint32_t>(v));
                customSum += v;
            }
            if (customSum > amount)
                throw std::runtime_error("Split exceeds total amount");
            if (customSum == amount)
                return result;
            amount -= customSum;
        }

        const auto denoms = parseDenominations(keyset);
        if (denoms.empty())
            throw std::runtime_error("Keyset has no keys");

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
        uint8_t raw[32];
        generate_scalar(raw);
        std::string secret_hex = bytes_to_hex(raw, 32);

        uint8_t r[32], B_[33];
        generate_scalar(r);

        crypto_err_t err = blind(
            reinterpret_cast<const uint8_t*>(secret_hex.data()),
            secret_hex.size(),
            r,
            B_
        );
        if (err != CRYPTO_OK)
            throw std::runtime_error("blind() failed");

        return NativeOutputData(
            BlindedMessage(amount, bytes_to_hex(B_, 33), keysetId),
            bytes_to_hex(r, 32),
            secret_hex
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


    static std::string buildP2PKSecret(
        const std::string& nonce_hex,
        const NitroP2PKOptions& opts
    ) {
        const std::string& data = opts.pubkeys[0];

        std::string tags = "[";
        bool first = true;
        auto append_tag = [&](const std::string& tag) {
            if (!first) tags += ',';
            tags += tag;
            first = false;
        };

        // locktime — only if valid integer >= 0
        if (opts.locktime.has_value()) {
            int64_t lt = static_cast<int64_t>(opts.locktime.value());
            if (lt >= 0) {
                append_tag("[\"locktime\",\"" + std::to_string(lt) + "\"]");
            }
        }

        // additional pubkeys (all pubkeys after first)
        if (opts.pubkeys.size() > 1) {
            std::string tag = "[\"pubkeys\"";
            for (size_t i = 1; i < opts.pubkeys.size(); i++) {
                tag += ",\"";
                tag += opts.pubkeys[i];
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
                tag += key;
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

        // hashlock
        if (opts.hashlock.has_value() && !opts.hashlock.value().empty())
            append_tag("[\"hashlock\",\"" + opts.hashlock.value() + "\"]");

        tags += ']';

        std::string secret;
        secret.reserve(64 + data.size() + tags.size());
        secret += "[\"P2PK\",{\"nonce\":\"";
        secret += nonce_hex;
        secret += "\",\"data\":\"";
        secret += data;
        secret += "\",\"tags\":";
        secret += tags;
        secret += "}]";
        return secret;
    }

    NativeOutputData HybridOutputCreator::createSingleP2PKData(
        const NitroP2PKOptions& p2pk,
        uint64_t amount,
        const std::string& keysetId
    ) {
        if (p2pk.pubkeys.empty())
            throw std::runtime_error("P2PK requires at least one pubkey");

        uint8_t nonce_raw[32];
        generate_scalar(nonce_raw);
        const std::string json_secret = buildP2PKSecret(bytes_to_hex(nonce_raw, 32), p2pk);

        uint8_t r[32], B_[33];
        generate_scalar(r);

        // blind the UTF-8 bytes of the JSON string, same as cashu-ts TextEncoder.encode(jsonStr)
        crypto_err_t err = blind(
            reinterpret_cast<const uint8_t*>(json_secret.data()),
            json_secret.size(),
            r,
            B_
        );
        if (err != CRYPTO_OK)
            throw std::runtime_error("blind() failed");

        return NativeOutputData(
            BlindedMessage(amount, bytes_to_hex(B_, 33), keysetId),
            bytes_to_hex(r, 32),
            json_secret
        );
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
        for (uint32_t a : amounts)
            result.push_back(createSingleP2PKData(p2pk, a, keyset.id));
        return result;
    }

    std::vector<NativeOutputData> HybridOutputCreator::createDeterministicData(
        uint64_t amount,
        const std::shared_ptr<ArrayBuffer>& seed,
        uint64_t counter,
        const Keyset& keyset,
        const std::optional<std::vector<uint64_t>>& customSplit
    ) {
        throw std::runtime_error("not implemented");
    }

    NativeOutputData HybridOutputCreator::createSingleDeterministicData(
        uint64_t amount,
        const std::shared_ptr<ArrayBuffer>& seed,
        uint64_t counter,
        const std::string& keysetId
    ) {
        throw std::runtime_error("not implemented");
    }

} // namespace margelo::nitro::nutpatch
