//
// Created by d4rp4t on 01/04/2026.
//

#ifndef CRYPTO_H
#define CRYPTO_H

#include <stddef.h>
#include <stdint.h>
#include <secp256k1.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    CRYPTO_OK = 0,
    CRYPTO_ERR_INVALID_POINT,
    CRYPTO_ERR_INVALID_SCALAR,
    CRYPTO_ERR_HASH_TO_CURVE,
} crypto_err_t;

void crypto_init(void);
void crypto_free(void);
secp256k1_context *crypto_ctx(void);

crypto_err_t hash_to_curve(const uint8_t *msg, size_t msg_len, secp256k1_pubkey *out);
crypto_err_t blind(const secp256k1_pubkey *Y, const uint8_t *r, secp256k1_pubkey *out);
crypto_err_t unblind(const secp256k1_pubkey *C_, const uint8_t *r,
                     const secp256k1_pubkey *A, secp256k1_pubkey *out);

#ifdef __cplusplus
}
#endif

#endif // CRYPTO_H
