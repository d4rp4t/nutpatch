//
// Created by d4rp4t on 1/04/2026.
//
#include "crypto.h"
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>

#include "../vendor/trezor/sha2.h"
#include "../vendor/trezor/hmac.h"
#include "../vendor/trezor/memzero.h"

#include <fcntl.h>
#include <string.h>
#include <unistd.h>

static const unsigned char DOMAIN_SEPARATOR[] = "Secp256k1_HashToCurve_Cashu_";
#define DOMAIN_SEPARATOR_LEN (sizeof(DOMAIN_SEPARATOR) - 1)

static const char HEX_CHARS[] = "0123456789abcdef";

static secp256k1_context *ctx = NULL;

void crypto_init(void) {
    if (ctx == NULL) {
        ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    }
}

void crypto_free(void) {
    if (ctx != NULL) {
        secp256k1_context_destroy(ctx);
        ctx = NULL;
    }
}

static void ctcpy(uint8_t *dst, const uint8_t *src, size_t len) {
    volatile uint8_t *d = dst;
    const volatile uint8_t *s = src;
    for (size_t i = 0; i < len; i++) d[i] = s[i];
}

static int ct_eq(const uint8_t *a, const uint8_t *b, size_t len) {
    volatile uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) diff |= a[i] ^ b[i];
    return (1 & ((diff - 1) >> 8));
}

static int secure_random(uint8_t *buf, size_t len) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return 0;
    ssize_t n = read(fd, buf, len);
    close(fd);
    return (n >= 0 && (size_t)n == len);
}

static void bytes_to_hex(const uint8_t *bytes, size_t len, char *out) {
    for (size_t i = 0; i < len; i++) {
        out[i * 2]     = HEX_CHARS[bytes[i] >> 4];
        out[i * 2 + 1] = HEX_CHARS[bytes[i] & 0xf];
    }
}

static crypto_err_t pubkey_serialize(const secp256k1_pubkey *key, uint8_t *out33) {
    size_t len = 33;
    if (!secp256k1_ec_pubkey_serialize(ctx, out33, &len, key, SECP256K1_EC_COMPRESSED))
        return CRYPTO_ERR_INVALID_POINT;
    return CRYPTO_OK;
}

static crypto_err_t pubkey_parse(const uint8_t *in33, secp256k1_pubkey *out) {
    if (!secp256k1_ec_pubkey_parse(ctx, out, in33, 33))
        return CRYPTO_ERR_INVALID_POINT;
    return CRYPTO_OK;
}

crypto_err_t hash_to_curve(const uint8_t *msg, size_t msg_len, uint8_t *out33) {
    // msg_hash = SHA256(DOMAIN_SEPARATOR || msg)
    uint8_t msg_hash[32];
    {
        SHA256_CTX h;
        sha256_Init(&h);
        sha256_Update(&h, DOMAIN_SEPARATOR, DOMAIN_SEPARATOR_LEN);
        sha256_Update(&h, msg, msg_len);
        sha256_Final(&h, msg_hash);
    }

    for (uint32_t i = 0; i < (1u << 16); i++) {
        uint8_t point_bytes[33];
        point_bytes[0] = 0x02;

        uint8_t counter_le[4] = {
            i & 0xFF, (i >> 8) & 0xFF, (i >> 16) & 0xFF, (i >> 24) & 0xFF,
        };

        SHA256_CTX h;
        sha256_Init(&h);
        sha256_Update(&h, msg_hash, 32);
        sha256_Update(&h, counter_le, 4);
        sha256_Final(&h, point_bytes + 1);

        secp256k1_pubkey point;
        if (secp256k1_ec_pubkey_parse(ctx, &point, point_bytes, 33) == 1)
            return pubkey_serialize(&point, out33);
    }
    return CRYPTO_ERR_HASH_TO_CURVE;
}

crypto_err_t blind(const uint8_t *msg, size_t msg_len, const uint8_t *r32, uint8_t *out33) {
    secp256k1_pubkey Y;
    {
        uint8_t Y_bytes[33];
        crypto_err_t err = hash_to_curve(msg, msg_len, Y_bytes);
        if (err != CRYPTO_OK) return err;
        if (pubkey_parse(Y_bytes, &Y) != CRYPTO_OK) return CRYPTO_ERR_INVALID_POINT;
    }

    secp256k1_pubkey rG;
    if (!secp256k1_ec_pubkey_create(ctx, &rG, r32))
        return CRYPTO_ERR_INVALID_SCALAR;

    const secp256k1_pubkey *points[2] = { &Y, &rG };
    secp256k1_pubkey B_;
    if (!secp256k1_ec_pubkey_combine(ctx, &B_, points, 2))
        return CRYPTO_ERR_INVALID_POINT;

    return pubkey_serialize(&B_, out33);
}

crypto_err_t unblind(const uint8_t *C_33, const uint8_t *r32,
                     const uint8_t *A_33, uint8_t *out33) {
    secp256k1_pubkey C_;
    if (pubkey_parse(C_33, &C_) != CRYPTO_OK) return CRYPTO_ERR_INVALID_POINT;

    secp256k1_pubkey A;
    if (pubkey_parse(A_33, &A) != CRYPTO_OK) return CRYPTO_ERR_INVALID_POINT;

    uint8_t neg_r[32];
    ctcpy(neg_r, r32, 32);
    int ok = secp256k1_ec_seckey_negate(ctx, neg_r);
    if (ok) ok = secp256k1_ec_pubkey_tweak_mul(ctx, &A, neg_r);
    memzero(neg_r, sizeof(neg_r));
    if (!ok) return CRYPTO_ERR_INVALID_POINT;

    const secp256k1_pubkey *points[2] = { &C_, &A };
    secp256k1_pubkey C;
    if (!secp256k1_ec_pubkey_combine(ctx, &C, points, 2))
        return CRYPTO_ERR_INVALID_POINT;

    return pubkey_serialize(&C, out33);
}

crypto_err_t hash_e(const uint8_t *pubkeys_33, size_t num_pubkeys, uint8_t *out32) {
    SHA256_CTX h;
    sha256_Init(&h);

    for (size_t i = 0; i < num_pubkeys; i++) {
        secp256k1_pubkey pubkey;
        if (!secp256k1_ec_pubkey_parse(ctx, &pubkey, pubkeys_33 + i * 33, 33))
            return CRYPTO_ERR_INVALID_POINT;

        uint8_t uncompressed[65];
        size_t len = 65;
        secp256k1_ec_pubkey_serialize(ctx, uncompressed, &len, &pubkey,
                                      SECP256K1_EC_UNCOMPRESSED);

        char hex[130];
        bytes_to_hex(uncompressed, 65, hex);
        sha256_Update(&h, (const uint8_t *)hex, 130);
    }

    sha256_Final(&h, out32);
    return CRYPTO_OK;
}

void compute_sha256(const uint8_t *msg, size_t msg_len, uint8_t *out32) {
    sha256_Raw(msg, msg_len, out32);
}

crypto_err_t schnorr_sign(const uint8_t *seckey, const uint8_t *msg32, uint8_t *sig_out) {
    secp256k1_keypair keypair;
    if (!secp256k1_keypair_create(ctx, &keypair, seckey)) {
        memzero(&keypair, sizeof(keypair));
        return CRYPTO_ERR_INVALID_SCALAR;
    }

    uint8_t aux_rand[32];
    if (!secure_random(aux_rand, 32)) {
        memzero(&keypair, sizeof(keypair));
        return CRYPTO_ERR_RANDOM;
    }

    int ok = secp256k1_schnorrsig_sign32(ctx, sig_out, msg32, &keypair, aux_rand);
    memzero(aux_rand, sizeof(aux_rand));
    memzero(&keypair, sizeof(keypair));
    return ok ? CRYPTO_OK : CRYPTO_ERR_SCHNORR_SIGN;
}

crypto_err_t schnorr_verify(const uint8_t *sig, const uint8_t *msg32,
                             const uint8_t *xonly_pubkey32) {
    secp256k1_xonly_pubkey pubkey;
    if (!secp256k1_xonly_pubkey_parse(ctx, &pubkey, xonly_pubkey32))
        return CRYPTO_ERR_INVALID_POINT;

    if (!secp256k1_schnorrsig_verify(ctx, sig, msg32, 32, &pubkey))
        return CRYPTO_ERR_SCHNORR_VERIFY;

    return CRYPTO_OK;
}

crypto_err_t seckey_generate(uint8_t *out32) {
    for (int i = 0; i < 100; i++) {
        if (!secure_random(out32, 32)) return CRYPTO_ERR_RANDOM;
        if (secp256k1_ec_seckey_verify(ctx, out32)) return CRYPTO_OK;
    }
    return CRYPTO_ERR_INVALID_SCALAR;
}

crypto_err_t create_blind_signature(const uint8_t *B_33, const uint8_t *seckey,
                                     uint8_t *out33) {
    secp256k1_pubkey B_;
    if (pubkey_parse(B_33, &B_) != CRYPTO_OK) return CRYPTO_ERR_INVALID_POINT;

    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &B_, seckey))
        return CRYPTO_ERR_INVALID_SCALAR;

    return pubkey_serialize(&B_, out33);
}

int verify_dleq_proof(const uint8_t *B_33, const uint8_t *C_33, const uint8_t *A_33,
                      const uint8_t *s32, const uint8_t *e32) {
    secp256k1_pubkey B_, C_, A;
    if (pubkey_parse(B_33, &B_) != CRYPTO_OK) return 0;
    if (pubkey_parse(C_33, &C_) != CRYPTO_OK) return 0;
    if (pubkey_parse(A_33, &A)  != CRYPTO_OK) return 0;

    uint8_t neg_e[32];
    ctcpy(neg_e, e32, 32);
    if (!secp256k1_ec_seckey_negate(ctx, neg_e)) {
        memzero(neg_e, sizeof(neg_e));
        return 0;
    }

    // R1 = s*G + (-e)*A
    secp256k1_pubkey sG, neg_eA, R1;
    if (!secp256k1_ec_pubkey_create(ctx, &sG, s32)) {
        memzero(neg_e, sizeof(neg_e));
        return 0;
    }
    ctcpy((uint8_t*)&neg_eA, (const uint8_t*)&A, sizeof(secp256k1_pubkey));
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &neg_eA, neg_e)) {
        memzero(neg_e, sizeof(neg_e));
        return 0;
    }
    { const secp256k1_pubkey *pts[2] = { &sG, &neg_eA };
      if (!secp256k1_ec_pubkey_combine(ctx, &R1, pts, 2)) {
          memzero(neg_e, sizeof(neg_e));
          return 0;
      }
    }

    // R2 = s*B_ + (-e)*C_
    secp256k1_pubkey sB_, neg_eC_, R2;
    ctcpy((uint8_t*)&sB_, (const uint8_t*)&B_, sizeof(secp256k1_pubkey));
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &sB_, s32)) {
        memzero(neg_e, sizeof(neg_e));
        return 0;
    }
    ctcpy((uint8_t*)&neg_eC_, (const uint8_t*)&C_, sizeof(secp256k1_pubkey));
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &neg_eC_, neg_e)) {
        memzero(neg_e, sizeof(neg_e));
        return 0;
    }
    memzero(neg_e, sizeof(neg_e));
    { const secp256k1_pubkey *pts[2] = { &sB_, &neg_eC_ };
      if (!secp256k1_ec_pubkey_combine(ctx, &R2, pts, 2)) return 0; }

    // e' = hash_e([R1, R2, A, C_])
    uint8_t flat[33 * 4];
    pubkey_serialize(&R1, flat +  0);
    pubkey_serialize(&R2, flat + 33);
    pubkey_serialize(&A,  flat + 66);
    pubkey_serialize(&C_, flat + 99);

    uint8_t e_prime[32];
    if (hash_e(flat, 4, e_prime) != CRYPTO_OK) return 0;

    return ct_eq(e_prime, e32, 32);
}

crypto_err_t create_dleq_proof(const uint8_t *B_33, const uint8_t *a32,
                                uint8_t *s_out32, uint8_t *e_out32) {
    secp256k1_pubkey B_;
    if (pubkey_parse(B_33, &B_) != CRYPTO_OK) return CRYPTO_ERR_INVALID_POINT;

    uint8_t r[32];
    crypto_err_t err = seckey_generate(r);
    if (err != CRYPTO_OK) return err;

    crypto_err_t ret = CRYPTO_ERR_INVALID_SCALAR;

    // R1 = r*G
    secp256k1_pubkey R1;
    if (!secp256k1_ec_pubkey_create(ctx, &R1, r)) goto cleanup;

    // R2 = r*B_
    secp256k1_pubkey R2;
    ctcpy((uint8_t*)&R2, (const uint8_t*)&B_, sizeof(secp256k1_pubkey));
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &R2, r)) { ret = CRYPTO_ERR_INVALID_POINT; goto cleanup; }

    // C_ = a*B_
    secp256k1_pubkey C_;
    ctcpy((uint8_t*)&C_, (const uint8_t*)&B_, sizeof(secp256k1_pubkey));
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &C_, a32)) { ret = CRYPTO_ERR_INVALID_POINT; goto cleanup; }

    // A = a*G
    secp256k1_pubkey A;
    if (!secp256k1_ec_pubkey_create(ctx, &A, a32)) goto cleanup;

    // e = hash_e([R1, R2, A, C_])
    {
        uint8_t flat[33 * 4];
        pubkey_serialize(&R1, flat +  0);
        pubkey_serialize(&R2, flat + 33);
        pubkey_serialize(&A,  flat + 66);
        pubkey_serialize(&C_, flat + 99);
        if (hash_e(flat, 4, e_out32) != CRYPTO_OK) { ret = CRYPTO_ERR_INVALID_POINT; goto cleanup; }
    }

    // s = r + e*a mod n
    {
        uint8_t ea[32];
        ctcpy(ea, a32, 32);
        if (!secp256k1_ec_seckey_tweak_mul(ctx, ea, e_out32)) { memzero(ea, sizeof(ea)); goto cleanup; }
        ctcpy(s_out32, r, 32);
        if (!secp256k1_ec_seckey_tweak_add(ctx, s_out32, ea)) { memzero(ea, sizeof(ea)); goto cleanup; }
        memzero(ea, sizeof(ea));
    }

    ret = CRYPTO_OK;

cleanup:
    memzero(r, sizeof(r));
    return ret;
}


// Returns 0-15 for valid hex nibble, -1 otherwise.
static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int hex_decode_str(const char *hex, uint8_t *out, size_t *out_len) {
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0) return -1;
    size_t n = hex_len / 2;
    for (size_t i = 0; i < n; i++) {
        int hi = hex_nibble(hex[i * 2]);
        int lo = hex_nibble(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    *out_len = n;
    return 0;
}

static int keyset_id_is_hex(const char *id) {
    size_t len = strlen(id);
    if (len == 0 || len % 2 != 0) return 0;
    for (const char *p = id; *p; p++)
        if (hex_nibble(*p) < 0) return 0;
    return 1;
}

// bigint_from_bytes(bytes) mod 2^31-1
static uint32_t bytes_mod_2_31_minus_1(const uint8_t *bytes, size_t len) {
    const uint32_t MOD = 2147483647u;
    uint64_t acc = 0;
    for (size_t i = 0; i < len; i++)
        acc = (acc * 256 + bytes[i]) % MOD;
    return (uint32_t)acc;
}

static uint32_t keyset_id_to_bip32_int(const char *keyset_id) {
    size_t len = strlen(keyset_id);
    uint8_t buf[64];
    size_t buf_len;
    if (keyset_id_is_hex(keyset_id) && hex_decode_str(keyset_id, buf, &buf_len) == 0)
        return bytes_mod_2_31_minus_1(buf, buf_len);
    return bytes_mod_2_31_minus_1((const uint8_t *)keyset_id, len);
}

static void write_be32(uint8_t *out, uint32_t v) {
    out[0] = (v >> 24) & 0xFF;
    out[1] = (v >> 16) & 0xFF;
    out[2] = (v >>  8) & 0xFF;
    out[3] = (v) & 0xFF;
}

static void write_be64(uint8_t *out, uint64_t v) {
    out[0] = (uint8_t)(v >> 56);
    out[1] = (uint8_t)(v >> 48);
    out[2] = (uint8_t)(v >> 40);
    out[3] = (uint8_t)(v >> 32);
    out[4] = (uint8_t)(v >> 24);
    out[5] = (uint8_t)(v >> 16);
    out[6] = (uint8_t)(v >>  8);
    out[7] = (uint8_t)(v      );
}

// v2: HMAC-SHA256 KDF  (keyset ID prefix "01")

static const uint8_t SECP256K1_N[32] = {
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
    0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,
    0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x41
};

static void bytes32_sub(uint8_t *out, const uint8_t *a, const uint8_t *b) {
    int borrow = 0;
    for (int i = 31; i >= 0; i--) {
        int d = (int)a[i] - (int)b[i] - borrow;
        out[i] = (uint8_t)(d & 0xFF);
        borrow = (d < 0) ? 1 : 0;
    }
}

static crypto_err_t derive_v2(
    const uint8_t *seed, size_t seed_len,
    const char *keyset_id, uint64_t counter,
    uint8_t suffix, uint8_t *out32)
{
    static const char LABEL[] = "Cashu_KDF_HMAC_SHA256";
    static const size_t LABEL_LEN = sizeof(LABEL) - 1;  // 21, excludes null terminator
    uint8_t kid_bytes[64];
    size_t kid_len;
    if (hex_decode_str(keyset_id, kid_bytes, &kid_len) != 0)
        return CRYPTO_ERR_INVALID_SCALAR;

    // data = LABEL || keyset_id_bytes || counter_be64 || suffix_byte
    uint8_t data[sizeof(LABEL) - 1 + 64 + 8 + 1];
    size_t pos = 0;
    memcpy(data, LABEL, LABEL_LEN);  pos += LABEL_LEN;
    memcpy(data + pos, kid_bytes, kid_len); pos += kid_len;
    write_be64(data + pos, counter); pos += 8;
    data[pos++] = suffix;

    hmac_sha256(seed, (uint32_t)seed_len, data, (uint32_t)pos, out32);
    memzero(data, sizeof(data));

    // raw HMAC digest for secret (suffix 0x00), mod-N reduced.
    // non-zero scalar check for blinding factor (suffix 0x01).
    if (suffix == 0x01) {
        if (memcmp(out32, SECP256K1_N, 32) >= 0)
            bytes32_sub(out32, out32, SECP256K1_N);
        uint8_t zero[32] = {0};
        if (memcmp(out32, zero, 32) == 0) return CRYPTO_ERR_INVALID_SCALAR;
    }

    return CRYPTO_OK;
}

// v1: BIP32 path  m/129372'/0'/{kid}'/{counter}'/{suffix_idx}

typedef struct { uint8_t key[32]; uint8_t chain[32]; } bip32_node;

static int bip32_from_seed(const uint8_t *seed, size_t seed_len, bip32_node *out) {
    static const uint8_t BSEED[] = "Bitcoin seed";
    uint8_t I[64];
    hmac_sha512(BSEED, (uint32_t)(sizeof(BSEED) - 1), seed, (uint32_t)seed_len, I);
    memcpy(out->key, I, 32);
    memcpy(out->chain, I + 32, 32);
    memzero(I, sizeof(I));
    return secp256k1_ec_seckey_verify(ctx, out->key) ? 0 : -1;
}

static int bip32_child_hard(const bip32_node *p, uint32_t idx, bip32_node *out) {
    // idx must already have 0x80000000 set
    uint8_t data[37];
    data[0] = 0x00;
    memcpy(data + 1, p->key, 32);
    write_be32(data + 33, idx);

    uint8_t I[64];
    hmac_sha512(p->chain, 32, data, 37, I);
    memzero(data, sizeof(data));

    memcpy(out->key, I, 32);
    memcpy(out->chain, I + 32, 32);
    memzero(I, sizeof(I));

    if (!secp256k1_ec_seckey_tweak_add(ctx, out->key, p->key)) return -1;
    return secp256k1_ec_seckey_verify(ctx, out->key) ? 0 : -1;
}

static int bip32_child_normal(const bip32_node *p, uint32_t idx, bip32_node *out) {
    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_create(ctx, &pubkey, p->key)) return -1;
    uint8_t pub33[33];
    size_t plen = 33;
    secp256k1_ec_pubkey_serialize(ctx, pub33, &plen, &pubkey, SECP256K1_EC_COMPRESSED);

    uint8_t data[37];
    memcpy(data, pub33, 33);
    write_be32(data + 33, idx);

    uint8_t I[64];
    hmac_sha512(p->chain, 32, data, 37, I);

    memcpy(out->key, I, 32);
    memcpy(out->chain, I + 32, 32);
    memzero(I, sizeof(I));

    if (!secp256k1_ec_seckey_tweak_add(ctx, out->key, p->key)) return -1;
    return secp256k1_ec_seckey_verify(ctx, out->key) ? 0 : -1;
}

static crypto_err_t derive_v1(
    const uint8_t *seed, size_t seed_len,
    const char *keyset_id, uint64_t counter,
    uint8_t suffix_idx, uint8_t *out32)
{
    // BIP32 hardened indices are limited to [0, 2^31-1]. throw on overflow
    if (counter > 0x7FFFFFFFu) return CRYPTO_ERR_INVALID_SCALAR;

    uint32_t kid_int = keyset_id_to_bip32_int(keyset_id);
    uint32_t ctr_idx = (uint32_t)counter;

    bip32_node node, tmp;
    crypto_err_t ret = CRYPTO_ERR_INVALID_SCALAR;

    if (bip32_from_seed(seed, seed_len, &node) != 0)          goto cleanup;
    if (bip32_child_hard(&node, 129372u | 0x80000000u, &tmp)) goto cleanup;
    node = tmp;
    if (bip32_child_hard(&node, 0x80000000u, &tmp))            goto cleanup;
    node = tmp;
    if (bip32_child_hard(&node, kid_int | 0x80000000u, &tmp)) goto cleanup;
    node = tmp;
    if (bip32_child_hard(&node, ctr_idx | 0x80000000u, &tmp)) goto cleanup;
    node = tmp;
    if (bip32_child_normal(&node, (uint32_t)suffix_idx, &tmp)) goto cleanup;

    memcpy(out32, tmp.key, 32);
    ret = CRYPTO_OK;

cleanup:
    memzero(&node, sizeof(node));
    memzero(&tmp, sizeof(tmp));
    return ret;
}


crypto_err_t derive_secret(
    const uint8_t *seed, size_t seed_len,
    const char *keyset_id, uint64_t counter,
    uint8_t *out32)
{
    if (keyset_id_is_hex(keyset_id) &&
        keyset_id[0] == '0' && keyset_id[1] == '1')
        return derive_v2(seed, seed_len, keyset_id, counter, 0x00, out32);
    return derive_v1(seed, seed_len, keyset_id, counter, 0, out32);
}

crypto_err_t derive_blinding_factor(
    const uint8_t *seed, size_t seed_len,
    const char *keyset_id, uint64_t counter,
    uint8_t *out32)
{
    if (keyset_id_is_hex(keyset_id) &&
        keyset_id[0] == '0' && keyset_id[1] == '1')
        return derive_v2(seed, seed_len, keyset_id, counter, 0x01, out32);
    return derive_v1(seed, seed_len, keyset_id, counter, 1, out32);
}
