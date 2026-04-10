//
// Created by d4rp4t on 01/04/2026.
//

#ifndef CRYPTO_H
#define CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    CRYPTO_OK = 0,
    CRYPTO_ERR_INVALID_POINT,
    CRYPTO_ERR_INVALID_SCALAR,
    CRYPTO_ERR_HASH_TO_CURVE,
    CRYPTO_ERR_SCHNORR_SIGN,
    CRYPTO_ERR_SCHNORR_VERIFY,
    CRYPTO_ERR_RANDOM,
} crypto_err_t;

// Context
void crypto_init(void);
void crypto_free(void);

int secure_random(uint8_t *buf, size_t len);
crypto_err_t hash_to_curve(const uint8_t *msg, size_t msg_len, uint8_t *out33);

crypto_err_t blind(const uint8_t *msg, size_t msg_len, const uint8_t *r32, uint8_t *out33);

crypto_err_t unblind(const uint8_t *C_33, const uint8_t *r32,
                     const uint8_t *A_33, uint8_t *out33);

crypto_err_t hash_e(const uint8_t *pubkeys_33, size_t num_pubkeys, uint8_t *out32);

void compute_sha256(const uint8_t *msg, size_t msg_len, uint8_t *out32);

crypto_err_t schnorr_sign(const uint8_t *seckey, const uint8_t *msg32, uint8_t *sig_out);

crypto_err_t schnorr_verify(const uint8_t *sig, const uint8_t *msg32,
                             const uint8_t *xonly_pubkey32);

crypto_err_t seckey_generate(uint8_t *out32);

crypto_err_t create_blind_signature(const uint8_t *B_33, const uint8_t *seckey,
                                     uint8_t *out33);

int verify_dleq_proof(const uint8_t *B_33, const uint8_t *C_33, const uint8_t *A_33,
                      const uint8_t *s32, const uint8_t *e32);

crypto_err_t create_dleq_proof(const uint8_t *B_33, const uint8_t *a32,
                                uint8_t *s_out32, uint8_t *e_out32);


#ifdef __cplusplus
}
#endif

#endif // CRYPTO_H
