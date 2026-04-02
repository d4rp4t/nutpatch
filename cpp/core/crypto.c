//
// Created by d4rp4t on 1/04/2026.
//
#include "crypto.h"
#define VERIFY_CHECK(x) ((void)(x))
#include "../vendor/secp256k1/src/util.h"
#include "../vendor/secp256k1/src/hash.h"
#include "../vendor/secp256k1/src/hash_impl.h"
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>

#include <fcntl.h>
#include <string.h>
#include <unistd.h>

static const unsigned char DOMAIN_SEPARATOR[] = "Secp256k1_HashToCurve_Cashu_";
#define DOMAIN_SEPARATOR_LEN (sizeof(DOMAIN_SEPARATOR) - 1)

static const char HEX_CHARS[] = "0123456789abcdef";

static secp256k1_context *ctx = NULL;

void crypto_init(void) {
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
}

void crypto_free(void) {
    secp256k1_context_destroy(ctx);
    ctx = NULL;
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
    secp256k1_ec_pubkey_serialize(ctx, out33, &len, key, SECP256K1_EC_COMPRESSED);
    return CRYPTO_OK;
}

static crypto_err_t pubkey_parse(const uint8_t *in33, secp256k1_pubkey *out) {
    if (!secp256k1_ec_pubkey_parse(ctx, out, in33, 33))
        return CRYPTO_ERR_INVALID_POINT;
    return CRYPTO_OK;
}

crypto_err_t hash_to_curve(const uint8_t *msg, size_t msg_len, uint8_t *out33) {
    secp256k1_hash_ctx hash_ctx;
    secp256k1_hash_ctx_init(&hash_ctx);

    // msg_hash = SHA256(DOMAIN_SEPARATOR || msg)
    uint8_t msg_hash[32];
    {
        secp256k1_sha256 hash;
        secp256k1_sha256_initialize(&hash);
        secp256k1_sha256_write(&hash_ctx, &hash, DOMAIN_SEPARATOR, DOMAIN_SEPARATOR_LEN);
        secp256k1_sha256_write(&hash_ctx, &hash, msg, msg_len);
        secp256k1_sha256_finalize(&hash_ctx, &hash, msg_hash);
    }

    for (uint32_t i = 0; i < UINT32_MAX; i++) {
        uint8_t point_bytes[33];
        point_bytes[0] = 0x02;

        uint8_t counter_le[4] = {
            i & 0xFF, (i >> 8) & 0xFF, (i >> 16) & 0xFF, (i >> 24) & 0xFF,
        };

        secp256k1_sha256 hash;
        secp256k1_sha256_initialize(&hash);
        secp256k1_sha256_write(&hash_ctx, &hash, msg_hash, 32);
        secp256k1_sha256_write(&hash_ctx, &hash, counter_le, 4);
        secp256k1_sha256_finalize(&hash_ctx, &hash, point_bytes + 1);

        secp256k1_pubkey point;
        if (secp256k1_ec_pubkey_parse(ctx, &point, point_bytes, 33) == 1) {
            pubkey_serialize(&point, out33);
            return CRYPTO_OK;
        }
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
    if (!secp256k1_ec_seckey_negate(ctx, neg_r))
        return CRYPTO_ERR_INVALID_SCALAR;

    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &A, neg_r))
        return CRYPTO_ERR_INVALID_POINT;

    const secp256k1_pubkey *points[2] = { &C_, &A };
    secp256k1_pubkey C;
    if (!secp256k1_ec_pubkey_combine(ctx, &C, points, 2))
        return CRYPTO_ERR_INVALID_POINT;

    return pubkey_serialize(&C, out33);
}

crypto_err_t hash_e(const uint8_t *pubkeys_33, size_t num_pubkeys, uint8_t *out32) {
    secp256k1_hash_ctx hash_ctx;
    secp256k1_hash_ctx_init(&hash_ctx);

    secp256k1_sha256 hash;
    secp256k1_sha256_initialize(&hash);

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
        secp256k1_sha256_write(&hash_ctx, &hash, (const uint8_t *)hex, 130);
    }

    secp256k1_sha256_finalize(&hash_ctx, &hash, out32);
    return CRYPTO_OK;
}

void compute_sha256(const uint8_t *msg, size_t msg_len, uint8_t *out32) {
    secp256k1_hash_ctx hash_ctx;
    secp256k1_hash_ctx_init(&hash_ctx);

    secp256k1_sha256 hash;
    secp256k1_sha256_initialize(&hash);
    secp256k1_sha256_write(&hash_ctx, &hash, msg, msg_len);
    secp256k1_sha256_finalize(&hash_ctx, &hash, out32);
}

crypto_err_t schnorr_sign(const uint8_t *seckey, const uint8_t *msg32, uint8_t *sig_out) {
    secp256k1_keypair keypair;
    if (!secp256k1_keypair_create(ctx, &keypair, seckey))
        return CRYPTO_ERR_INVALID_SCALAR;

    uint8_t aux_rand[32];
    if (!secure_random(aux_rand, 32))
        return CRYPTO_ERR_RANDOM;

    if (!secp256k1_schnorrsig_sign32(ctx, sig_out, msg32, &keypair, aux_rand))
        return CRYPTO_ERR_SCHNORR_SIGN;

    return CRYPTO_OK;
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
    if (!secp256k1_ec_seckey_negate(ctx, neg_e)) return 0;

    // R1 = s*G + (-e)*A
    secp256k1_pubkey sG, neg_eA, R1;
    if (!secp256k1_ec_pubkey_create(ctx, &sG, s32)) return 0;
    ctcpy((uint8_t*)&neg_eA, (const uint8_t*)&A, sizeof(secp256k1_pubkey));
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &neg_eA, neg_e)) return 0;
    { const secp256k1_pubkey *pts[2] = { &sG, &neg_eA };
      if (!secp256k1_ec_pubkey_combine(ctx, &R1, pts, 2)) return 0; }

    // R2 = s*B_ + (-e)*C_
    secp256k1_pubkey sB_, neg_eC_, R2;
    ctcpy((uint8_t*)&sB_, (const uint8_t*)&B_, sizeof(secp256k1_pubkey));
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &sB_, s32)) return 0;
    ctcpy((uint8_t*)&neg_eC_, (const uint8_t*)&C_, sizeof(secp256k1_pubkey));
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &neg_eC_, neg_e)) return 0;
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

    // R1 = r*G
    secp256k1_pubkey R1;
    if (!secp256k1_ec_pubkey_create(ctx, &R1, r)) return CRYPTO_ERR_INVALID_SCALAR;

    // R2 = r*B_
    secp256k1_pubkey R2;
    ctcpy((uint8_t*)&R2, (const uint8_t*)&B_, sizeof(secp256k1_pubkey));
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &R2, r)) return CRYPTO_ERR_INVALID_POINT;

    // C_ = a*B_
    secp256k1_pubkey C_;
    ctcpy((uint8_t*)&C_, (const uint8_t*)&B_, sizeof(secp256k1_pubkey));
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &C_, a32)) return CRYPTO_ERR_INVALID_POINT;

    // A = a*G
    secp256k1_pubkey A;
    if (!secp256k1_ec_pubkey_create(ctx, &A, a32)) return CRYPTO_ERR_INVALID_SCALAR;

    // e = hash_e([R1, R2, A, C_])
    uint8_t flat[33 * 4];
    pubkey_serialize(&R1, flat +  0);
    pubkey_serialize(&R2, flat + 33);
    pubkey_serialize(&A,  flat + 66);
    pubkey_serialize(&C_, flat + 99);
    if (hash_e(flat, 4, e_out32) != CRYPTO_OK) return CRYPTO_ERR_INVALID_POINT;

    // s = r + e*a mod n
    uint8_t ea[32];
    ctcpy(ea, a32, 32);
    if (!secp256k1_ec_seckey_tweak_mul(ctx, ea, e_out32)) return CRYPTO_ERR_INVALID_SCALAR;
    ctcpy(s_out32, r, 32);
    if (!secp256k1_ec_seckey_tweak_add(ctx, s_out32, ea)) return CRYPTO_ERR_INVALID_SCALAR;

    return CRYPTO_OK;
}
