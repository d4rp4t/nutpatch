//
// Created by d4rp4t on 01/04/2026.
//

#include "HybridCashuCrypto.hpp"
#include "crypto.h"

#include <NitroModules/ArrayBuffer.hpp>
#include <secp256k1.h>

#include <fcntl.h>
#include <stdexcept>
#include <unistd.h>

namespace margelo::nitro::nutpatch {

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static void secure_random(uint8_t* buf, size_t len) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        throw std::runtime_error("secure_random: failed to open /dev/urandom");
    }
    ssize_t n = read(fd, buf, len);
    close(fd);
    if (n < 0 || static_cast<size_t>(n) != len) {
        throw std::runtime_error("secure_random: short read");
    }
}

static std::shared_ptr<ArrayBuffer> pubkeyToBuffer(const secp256k1_pubkey& pubkey) {
    auto buf = ArrayBuffer::allocate(33);
    size_t len = 33;
    secp256k1_ec_pubkey_serialize(crypto_ctx(), buf->data(), &len, &pubkey,
                                  SECP256K1_EC_COMPRESSED);
    return buf;
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

HybridCashuCrypto::HybridCashuCrypto() : HybridObject(TAG) {
    crypto_init();
}

HybridCashuCrypto::~HybridCashuCrypto() {
    crypto_free();
}

// ---------------------------------------------------------------------------
// Methods
// ---------------------------------------------------------------------------

std::shared_ptr<ArrayBuffer> HybridCashuCrypto::hashToCurve(
    const std::shared_ptr<ArrayBuffer>& message) {

    secp256k1_pubkey point;
    crypto_err_t err = ::hash_to_curve(message->data(), message->size(), &point);
    if (err != CRYPTO_OK) {
        throw std::runtime_error("hashToCurve failed");
    }
    return pubkeyToBuffer(point);
}

std::shared_ptr<ArrayBuffer> HybridCashuCrypto::blind(
    const std::shared_ptr<ArrayBuffer>& message,
    const std::shared_ptr<ArrayBuffer>& blindingFactor) {

    if (blindingFactor->size() != 32) {
        throw std::invalid_argument("blind: blindingFactor must be 32 bytes");
    }

    secp256k1_pubkey Y;
    crypto_err_t err = ::hash_to_curve(message->data(), message->size(), &Y);
    if (err != CRYPTO_OK) {
        throw std::runtime_error("blind: hash_to_curve failed");
    }

    secp256k1_pubkey B_;
    err = ::blind(&Y, blindingFactor->data(), &B_);
    if (err != CRYPTO_OK) {
        throw std::runtime_error("blind failed");
    }
    return pubkeyToBuffer(B_);
}

std::shared_ptr<ArrayBuffer> HybridCashuCrypto::unblind(
    const std::shared_ptr<ArrayBuffer>& blindedSignature,
    const std::shared_ptr<ArrayBuffer>& blindingFactor,
    const std::shared_ptr<ArrayBuffer>& mintPubkey) {

    if (blindingFactor->size() != 32) {
        throw std::invalid_argument("unblind: blindingFactor must be 32 bytes");
    }

    secp256k1_pubkey C_;
    if (!secp256k1_ec_pubkey_parse(crypto_ctx(), &C_,
                                    blindedSignature->data(), blindedSignature->size())) {
        throw std::invalid_argument("unblind: invalid blindedSignature");
    }

    secp256k1_pubkey A;
    if (!secp256k1_ec_pubkey_parse(crypto_ctx(), &A,
                                    mintPubkey->data(), mintPubkey->size())) {
        throw std::invalid_argument("unblind: invalid mintPubkey");
    }

    secp256k1_pubkey C;
    crypto_err_t err = ::unblind(&C_, blindingFactor->data(), &A, &C);
    if (err != CRYPTO_OK) {
        throw std::runtime_error("unblind failed");
    }
    return pubkeyToBuffer(C);
}

} // namespace margelo::nitro::nutpatch
