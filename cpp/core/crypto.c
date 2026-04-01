//
// Created by d4rp4t on 18/02/2026.
//
#include "crypto.h"
#define VERIFY_CHECK(x) ((void)(x))
#include "../vendor/secp256k1/src/util.h"
#include "../vendor/secp256k1/src/hash.h"
#include "../vendor/secp256k1/src/hash_impl.h"
#include <secp256k1.h>

static const unsigned char DOMAIN_SEPARATOR[] = "Secp256k1_HashToCurve_Cashu_";
#define DOMAIN_SEPARATOR_LEN (sizeof(DOMAIN_SEPARATOR) - 1)

static secp256k1_context *ctx = NULL;

void crypto_init(void) {
	ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
}

void crypto_free(void) {
	secp256k1_context_destroy(ctx);
	ctx = NULL;
}

secp256k1_context *crypto_ctx(void) { return ctx; }

static void get_msg_hash(const uint8_t *msg, size_t msg_len, uint8_t *out) {
	secp256k1_sha256 hash;
    secp256k1_hash_ctx hash_ctx;

    secp256k1_hash_ctx_init(&hash_ctx);
    secp256k1_sha256_initialize(&hash);

    secp256k1_sha256_write(&hash_ctx, &hash, DOMAIN_SEPARATOR, DOMAIN_SEPARATOR_LEN);
    secp256k1_sha256_write(&hash_ctx, &hash, msg, msg_len);

    secp256k1_sha256_finalize(&hash_ctx, &hash, out);
}

crypto_err_t hash_to_curve(const uint8_t *x, size_t x_len, secp256k1_pubkey *out) {
	uint8_t msg_hash[32];
	get_msg_hash(x, x_len, msg_hash);

	for (uint32_t i = 0; i < UINT32_MAX; i++) {
        uint8_t point_bytes[33];
        point_bytes[0] = 0x02;

	    // make sure the counter is little endian
        uint8_t counter_le[4] = {
        i & 0xFF, (i >> 8) & 0xFF, (i >> 16) & 0xFF, (i >> 24) & 0xFF,
    };

    secp256k1_sha256 hash;
    secp256k1_hash_ctx hash_ctx;

    secp256k1_hash_ctx_init(&hash_ctx);
    secp256k1_sha256_initialize(&hash);
    secp256k1_sha256_write(&hash_ctx, &hash, msg_hash, 32);
    secp256k1_sha256_write(&hash_ctx, &hash, counter_le, 4);
    secp256k1_sha256_finalize(&hash_ctx, &hash, point_bytes + 1);

    if (secp256k1_ec_pubkey_parse(ctx, out, point_bytes, 33) == 1)
      return CRYPTO_OK;
    }
    // couldn't find a curve point
	return CRYPTO_ERR_HASH_TO_CURVE;
}


// B_ = Y + rG
crypto_err_t blind(const secp256k1_pubkey *Y, const uint8_t *r, secp256k1_pubkey *out) {
    secp256k1_pubkey rG;
    if (!secp256k1_ec_pubkey_create(ctx, &rG, r)){
        return CRYPTO_ERR_INVALID_SCALAR;
    }
    const secp256k1_pubkey *points[2] = { Y, &rG };
    if (!secp256k1_ec_pubkey_combine(ctx, out, points, 2)){
        return CRYPTO_ERR_INVALID_POINT;
    }
    return CRYPTO_OK;
}

// C = C_ - rA
crypto_err_t unblind(const secp256k1_pubkey *C_, const uint8_t *r,
                    const secp256k1_pubkey *A, secp256k1_pubkey *out) {
    uint8_t neg_r[32];
    memcpy(neg_r, r, 32);
    if (!secp256k1_ec_seckey_negate(ctx, neg_r)){
        return CRYPTO_ERR_INVALID_SCALAR;
    }

    secp256k1_pubkey rA;
    memcpy(&rA, A, sizeof(secp256k1_pubkey));
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &rA, neg_r)){
        return CRYPTO_ERR_INVALID_POINT;
    }
    const secp256k1_pubkey *points[2] = { C_, &rA };
    if (!secp256k1_ec_pubkey_combine(ctx, out, points, 2)){
        return CRYPTO_ERR_INVALID_POINT;
    }
    return CRYPTO_OK;
}