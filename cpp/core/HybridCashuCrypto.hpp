//
// Created by d4rp4t on 01/04/2026.
//

#pragma once

#include "../../nitrogen/generated/shared/c++/HybridCryptoSpec.hpp"
#include <NitroModules/ArrayBuffer.hpp>

namespace margelo::nitro::nutpatch {

using namespace margelo::nitro;

class HybridCashuCrypto : public HybridCryptoSpec {
public:

    HybridCashuCrypto();
    ~HybridCashuCrypto() override;

    std::shared_ptr<ArrayBuffer> hashToCurve(const std::shared_ptr<ArrayBuffer>& message) override;
    std::shared_ptr<ArrayBuffer> blind(const std::shared_ptr<ArrayBuffer>& message,
                                       const std::shared_ptr<ArrayBuffer>& blindingFactor) override;
    std::shared_ptr<ArrayBuffer> unblind(const std::shared_ptr<ArrayBuffer>& blindedSignature,
                                          const std::shared_ptr<ArrayBuffer>& blindingFactor,
                                          const std::shared_ptr<ArrayBuffer>& mintPubkey) override;

};

} // namespace margelo::nitro::nutpatch
