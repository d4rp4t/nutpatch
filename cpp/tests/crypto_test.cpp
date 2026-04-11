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
