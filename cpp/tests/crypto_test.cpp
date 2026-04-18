#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <string>

extern "C" {
#include "crypto.h"
}

namespace {

std::string bytes_to_hex(const uint8_t* data, size_t len) {
    static constexpr char HEX[] = "0123456789abcdef";
    std::string out(len * 2, '\0');
    for (size_t i = 0; i < len; ++i) {
        out[2 * i]     = HEX[data[i] >> 4];
        out[2 * i + 1] = HEX[data[i] & 0xF];
    }
    return out;
}

std::vector<uint8_t> hex_to_bytes(const std::string& hex) {
    std::vector<uint8_t> out(hex.size() / 2);
    for (size_t i = 0; i < out.size(); ++i) {
        auto nibble = [&](char c) -> uint8_t {
            if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
            if (c >= 'a' && c <= 'f') return static_cast<uint8_t>(c - 'a' + 10);
            if (c >= 'A' && c <= 'F') return static_cast<uint8_t>(c - 'A' + 10);
            return 0;
        };
        out[i] = static_cast<uint8_t>((nibble(hex[2 * i]) << 4) | nibble(hex[2 * i + 1]));
    }
    return out;
}

class CryptoEnv : public ::testing::Environment {
public:
    void SetUp() override  { crypto_init(); }
    void TearDown() override { crypto_free(); }
};

const auto* kCryptoEnv = ::testing::AddGlobalTestEnvironment(new CryptoEnv);

} // namespace

TEST(HashToCurve, ZeroInputVector) {
    auto msg = hex_to_bytes("0000000000000000000000000000000000000000000000000000000000000000");
    uint8_t out[33];
    ASSERT_EQ(hash_to_curve(msg.data(), msg.size(), out), CRYPTO_OK);
    EXPECT_EQ(bytes_to_hex(out, 33),
              "024cce997d3b518f739663b757deaec95bcd9473c30a14ac2fd04023a739d1a725");
}

TEST(HashToCurve, OneInputVector) {
    auto msg = hex_to_bytes("0000000000000000000000000000000000000000000000000000000000000001");
    uint8_t out[33];
    ASSERT_EQ(hash_to_curve(msg.data(), msg.size(), out), CRYPTO_OK);
    EXPECT_EQ(bytes_to_hex(out, 33),
              "022e7158e11c9506f1aa4248bf531298daa7febd6194f003edcd9b93ade6253acf");
}

TEST(HashToCurve, Deterministic) {
    const uint8_t msg[] = "cashu";
    uint8_t a[33], b[33];
    ASSERT_EQ(hash_to_curve(msg, sizeof(msg) - 1, a), CRYPTO_OK);
    ASSERT_EQ(hash_to_curve(msg, sizeof(msg) - 1, b), CRYPTO_OK);
    EXPECT_EQ(std::memcmp(a, b, 33), 0);
}

TEST(Blind, KnownVectorRIsOne) {
    const char* msg = "test_message";
    uint8_t r[32] = {0};
    r[31] = 0x01;
    uint8_t B_[33];
    ASSERT_EQ(blind(reinterpret_cast<const uint8_t*>(msg), std::strlen(msg), r, B_), CRYPTO_OK);
    EXPECT_EQ(bytes_to_hex(B_, 33),
              "025cc16fe33b953e2ace39653efb3e7a7049711ae1d8a2f7a9108753f1cdea742b");
}

TEST(BDHKE, BlindSignUnblindRoundtrip) {
    // deterministic mint key = 0x00..01 so the ceremony is reproducible.
    uint8_t a[32] = {0};
    a[31] = 0x01;

    // A = a*G (compressed) — generator point for scalar 1.
    const auto A_bytes = hex_to_bytes(
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
    ASSERT_EQ(A_bytes.size(), 33u);

    const char* secret = "cashu-bdhke-test";
    uint8_t r[32] = {0};
    r[31] = 0x02;

    uint8_t B_[33];
    ASSERT_EQ(blind(reinterpret_cast<const uint8_t*>(secret), std::strlen(secret), r, B_),
              CRYPTO_OK);

    uint8_t C_[33];
    ASSERT_EQ(create_blind_signature(B_, a, C_), CRYPTO_OK);

    uint8_t C[33];
    ASSERT_EQ(unblind(C_, r, A_bytes.data(), C), CRYPTO_OK);

    // C must be a valid compressed point (02/03 prefix) and not the identity.
    EXPECT_TRUE(C[0] == 0x02 || C[0] == 0x03);
    bool all_zero = true;
    for (size_t i = 1; i < 33; ++i) all_zero &= (C[i] == 0);
    EXPECT_FALSE(all_zero);
}

// -----------------------------------------------------------------------------
// NUT-13 — deterministic derivation
// -----------------------------------------------------------------------------
TEST(DeriveBlindingFactor, NUT13RegressionVector) {
    // Test vector lifted from cashu-ts test/crypto/NUT13.test.ts
    const std::string seed_str = "test seed for regression";
    const char* keyset_id =
        "01abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567";
    uint8_t r[32];
    ASSERT_EQ(derive_blinding_factor(
                  reinterpret_cast<const uint8_t*>(seed_str.data()),
                  seed_str.size(),
                  keyset_id,
                  197,
                  r),
              CRYPTO_OK);
    EXPECT_EQ(bytes_to_hex(r, 32),
              "008464578dd0553eda2793249681ca2996587a6118b0974bf295fc946b4e5911");
}

TEST(DeriveSecret, DiffersFromBlindingFactor) {
    const std::string seed_str = "the same seed";
    const char* keyset_id = "0100000000000000000000000000000000000000000000000000000000000000";
    uint8_t s[32], r[32];
    ASSERT_EQ(derive_secret(reinterpret_cast<const uint8_t*>(seed_str.data()),
                             seed_str.size(), keyset_id, 0, s),
              CRYPTO_OK);
    ASSERT_EQ(derive_blinding_factor(reinterpret_cast<const uint8_t*>(seed_str.data()),
                                       seed_str.size(), keyset_id, 0, r),
              CRYPTO_OK);
    EXPECT_NE(std::memcmp(s, r, 32), 0);
}

TEST(DeriveSecret, DifferentCountersProduceDifferentSecrets) {
    const std::string seed_str = "a b c";
    const char* keyset_id = "0100000000000000000000000000000000000000000000000000000000000000";
    uint8_t s0[32], s1[32];
    ASSERT_EQ(derive_secret(reinterpret_cast<const uint8_t*>(seed_str.data()),
                             seed_str.size(), keyset_id, 0, s0), CRYPTO_OK);
    ASSERT_EQ(derive_secret(reinterpret_cast<const uint8_t*>(seed_str.data()),
                             seed_str.size(), keyset_id, 1, s1), CRYPTO_OK);
    EXPECT_NE(std::memcmp(s0, s1, 32), 0);
}

TEST(DeriveBlindingFactor, RejectsCounterAboveInt32Max) {
    // v1 BIP32 hardened index must fit in 31 bits (cashu-ts NUT13.ts guard).
    const std::string seed_str = "seed";
    const char* keyset_id = "abcdef0123456789"; // 8-byte v1 keyset id
    uint8_t r[32];
    EXPECT_EQ(derive_blinding_factor(reinterpret_cast<const uint8_t*>(seed_str.data()),
                                      seed_str.size(), keyset_id, 0x80000000ULL, r),
              CRYPTO_ERR_INVALID_SCALAR);
}

// -----------------------------------------------------------------------------
// seckey_generate — never produces zero or scalar ≥ N.
// -----------------------------------------------------------------------------
TEST(SeckeyGenerate, NonZero) {
    uint8_t key[32];
    ASSERT_EQ(seckey_generate(key), CRYPTO_OK);
    bool all_zero = true;
    for (uint8_t b : key) all_zero &= (b == 0);
    EXPECT_FALSE(all_zero);
}

// -----------------------------------------------------------------------------
// Schnorr sign / verify
// -----------------------------------------------------------------------------
TEST(Schnorr, SignVerifyRoundtrip) {
    uint8_t seckey[32] = {0};
    seckey[31] = 0x01;

    uint8_t msg32[32] = {0};
    msg32[31] = 0x42;

    uint8_t sig[64];
    ASSERT_EQ(schnorr_sign(seckey, msg32, sig), CRYPTO_OK);

    // xonly pubkey for scalar 1 = generator x-coord
    const auto xonly = hex_to_bytes(
        "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
    ASSERT_EQ(xonly.size(), 32u);

    EXPECT_EQ(schnorr_verify(sig, msg32, xonly.data()), CRYPTO_OK);
}

TEST(Schnorr, WrongMessageFails) {
    uint8_t seckey[32] = {0};
    seckey[31] = 0x01;

    uint8_t msg32[32] = {0};
    uint8_t sig[64];
    ASSERT_EQ(schnorr_sign(seckey, msg32, sig), CRYPTO_OK);

    uint8_t bad_msg[32] = {0};
    bad_msg[0] = 0xff;

    const auto xonly = hex_to_bytes(
        "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
    EXPECT_NE(schnorr_verify(sig, bad_msg, xonly.data()), CRYPTO_OK);
}

// -----------------------------------------------------------------------------
// NUT-28 / P2BK — derive_p2bk_blinded_pubkeys
// Test vectors from https://github.com/cashubtc/nuts/blob/main/tests/28-tests.md
// -----------------------------------------------------------------------------

// Sender ephemeral private key e
static constexpr const char* kE_priv =
    "1cedb9df0c6872188b560ace9e35fd55c2532d53e19ae65b46159073886482ca";
// Corresponding E = e·G
static constexpr const char* kE_pub =
    "02a8cda4cf448bfce9a9e46e588c06ea1780fcb94e3bbdf3277f42995d403a8b0c";
// Receiver long-lived public key P
static constexpr const char* kP =
    "02771fed6cb88aaac38b8b32104a942bf4b8f4696bc361171b3c7d06fa2ebddf06";

static constexpr const char* kBlindedPubkeys[11] = {
    "03b7c03eb05a0a539cfc438e81bcf38b65b7bb8685e8790f9b853bfe3d77ad5315",
    "0352fb6d93360b7c2538eedf3c861f32ea5883fceec9f3e573d9d84377420da838",
    "03667361ca925065dcafea0a705ba49e75bdd7975751fcc933e05953463c79fff1",
    "02aca3ed09382151250b38c85087ae0a1436a057b40f824a5569ba353d40347d08",
    "02cd397bd6e326677128f1b0e5f1d745ad89b933b1b8671e947592778c9fc2301d",
    "0394140369aae01dbaf74977ccbb09b3a9cf2252c274c791ac734a331716f1f7d4",
    "03480f28e8f8775d56a4254c7e0dfdd5a6ecd6318c757fcec9e84c1b48ada0666d",
    "02f8a7be813f7ba2253d09705cc68c703a9fd785a055bf8766057fc6695ec80efc",
    "03aa5446aaf07ca9730b233f5c404fd024ef92e3787cd1c34c81c0778fe23c59e9",
    "037f82d4e0a79b0624a58ef7181344b95afad8acf4275dad49bcd39c189b73ece2",
    "032371fc0eef6885062581a3852494e2eab8f384b7dd196281b85b77f94770fac5",
};

TEST(P2BK, Slot0BlindedPubkeyMatchesVector) {
    const auto e   = hex_to_bytes(kE_priv);
    const auto P   = hex_to_bytes(kP);

    uint8_t blinded[33];
    uint8_t E_out[33];
    ASSERT_EQ(derive_p2bk_blinded_pubkeys(P.data(), 1, e.data(), blinded, E_out), CRYPTO_OK);

    EXPECT_EQ(bytes_to_hex(blinded, 33), kBlindedPubkeys[0]);
}

TEST(P2BK, EOutputMatchesKnownEphemeralPubkey) {
    const auto e = hex_to_bytes(kE_priv);
    const auto P = hex_to_bytes(kP);

    uint8_t blinded[33];
    uint8_t E_out[33];
    ASSERT_EQ(derive_p2bk_blinded_pubkeys(P.data(), 1, e.data(), blinded, E_out), CRYPTO_OK);

    EXPECT_EQ(bytes_to_hex(E_out, 33), kE_pub);
}

TEST(P2BK, AllElevenSlotsMatchVectors) {
    const auto e = hex_to_bytes(kE_priv);
    const auto P = hex_to_bytes(kP);

    // Build input: 11 copies of the same receiver pubkey P
    std::vector<uint8_t> pubkeys_buf(11 * 33);
    for (size_t i = 0; i < 11; i++)
        std::memcpy(pubkeys_buf.data() + i * 33, P.data(), 33);

    std::vector<uint8_t> blinded(11 * 33);
    uint8_t E_out[33];
    ASSERT_EQ(derive_p2bk_blinded_pubkeys(
                  pubkeys_buf.data(), 11, e.data(), blinded.data(), E_out),
              CRYPTO_OK);

    for (size_t i = 0; i < 11; i++) {
        EXPECT_EQ(bytes_to_hex(blinded.data() + i * 33, 33), kBlindedPubkeys[i])
            << "slot " << i;
    }
}

TEST(P2BK, DifferentSlotsProduceDifferentBlindedKeys) {
    const auto e = hex_to_bytes(kE_priv);
    const auto P = hex_to_bytes(kP);

    std::vector<uint8_t> pubkeys_buf(2 * 33);
    std::memcpy(pubkeys_buf.data() + 0 * 33, P.data(), 33);
    std::memcpy(pubkeys_buf.data() + 1 * 33, P.data(), 33);

    std::vector<uint8_t> blinded(2 * 33);
    uint8_t E_out[33];
    ASSERT_EQ(derive_p2bk_blinded_pubkeys(
                  pubkeys_buf.data(), 2, e.data(), blinded.data(), E_out),
              CRYPTO_OK);

    EXPECT_NE(std::memcmp(blinded.data(), blinded.data() + 33, 33), 0);
}

TEST(P2BK, RandomEphemeralKeyProducesValidPoint) {
    const auto P = hex_to_bytes(kP);

    uint8_t blinded[33];
    uint8_t E_out[33];
    // e_in32 == nullptr → generate random ephemeral key
    ASSERT_EQ(derive_p2bk_blinded_pubkeys(P.data(), 1, nullptr, blinded, E_out), CRYPTO_OK);

    EXPECT_TRUE(blinded[0] == 0x02 || blinded[0] == 0x03);
    EXPECT_TRUE(E_out[0]   == 0x02 || E_out[0]   == 0x03);
}

TEST(P2BK, ZeroPubkeysReturnsOk) {
    const auto e = hex_to_bytes(kE_priv);
    // The null check runs before the num_pubkeys==0 guard, so pass valid (unused) pointers.
    const auto P = hex_to_bytes(kP);
    uint8_t blinded[33];
    uint8_t E_out[33] = {0};
    EXPECT_EQ(derive_p2bk_blinded_pubkeys(P.data(), 0, e.data(), blinded, E_out), CRYPTO_OK);
}

TEST(P2BK, NullPtrReturnsError) {
    const auto e = hex_to_bytes(kE_priv);
    const auto P = hex_to_bytes(kP);
    uint8_t blinded[33];
    uint8_t E_out[33];

    EXPECT_EQ(derive_p2bk_blinded_pubkeys(nullptr, 1, e.data(), blinded, E_out),
              CRYPTO_ERR_NULL_PTR);
    EXPECT_EQ(derive_p2bk_blinded_pubkeys(P.data(), 1, e.data(), nullptr, E_out),
              CRYPTO_ERR_NULL_PTR);
    EXPECT_EQ(derive_p2bk_blinded_pubkeys(P.data(), 1, e.data(), blinded, nullptr),
              CRYPTO_ERR_NULL_PTR);
}

TEST(P2BK, ExampleProofDataTagMatchesSlot0) {
    // Sanity: the example P2BK proof in the spec uses slot 0's blinded pubkey
    // as the "data" field in the secret. Verify it matches our computation.
    const auto e = hex_to_bytes(kE_priv);
    const auto P = hex_to_bytes(kP);

    uint8_t blinded[33];
    uint8_t E_out[33];
    ASSERT_EQ(derive_p2bk_blinded_pubkeys(P.data(), 1, e.data(), blinded, E_out), CRYPTO_OK);

    // From example proof: secret "data" field
    EXPECT_EQ(bytes_to_hex(blinded, 33),
              "03b7c03eb05a0a539cfc438e81bcf38b65b7bb8685e8790f9b853bfe3d77ad5315");
}
