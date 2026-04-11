//
// Created by d4rp4t on 10/04/2026.
//

#pragma once

#include "../../nitrogen/generated/shared/c++/HybridOutputCreatorSpec.hpp"
#include <optional>
#include <string>
#include <vector>

namespace margelo::nitro::nutpatch {

using namespace margelo::nitro;

class HybridOutputCreator : public HybridOutputCreatorSpec {
public:
    HybridOutputCreator();
    ~HybridOutputCreator() = default;

public:
    std::vector<NativeOutputData> createP2PKData(
        const NitroP2PKOptions& p2pk,
        uint64_t amount,
        const Keyset& keyset,
        const std::optional<std::vector<uint64_t>>& customSplit
    ) override;

    NativeOutputData createSingleP2PKData(
        const NitroP2PKOptions& p2pk,
        uint64_t amount,
        const std::string& keysetId
    ) override;

    std::vector<NativeOutputData> createRandomData(
        uint64_t amount,
        const Keyset& keyset,
        const std::optional<std::vector<uint64_t>>& customSplit
    ) override;

    NativeOutputData createSingleRandomData(
        uint64_t amount,
        const std::string& keysetId
    ) override;

    std::vector<NativeOutputData> createDeterministicData(
        uint64_t amount,
        const std::shared_ptr<ArrayBuffer>& seed,
        uint64_t counter,
        const Keyset& keyset,
        const std::optional<std::vector<uint64_t>>& customSplit
    ) override;

    NativeOutputData createSingleDeterministicData(
        uint64_t amount,
        const std::shared_ptr<ArrayBuffer>& seed,
        uint64_t counter,
        const std::string& keysetId
    ) override;
};

} // namespace margelo::nitro::nutpatch
