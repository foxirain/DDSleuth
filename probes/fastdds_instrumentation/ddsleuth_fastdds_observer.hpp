#pragma once

// Opt-in, observation-only hooks for an instrumented Fast DDS SecurityManager.
// The corresponding source overlay calls this header immediately before an
// endpoint CryptoToken is sent and immediately after an addressed token is
// accepted by the local ParticipantGenericMessage dispatcher.

#include "ddsleuth_event.hpp"
#include "ddsleuth_fingerprint.hpp"

#include <cstdlib>
#include <sstream>
#include <string>
#include <vector>

namespace ddsleuth {
namespace fastdds_observer {

inline bool enabled()
{
    const char* value = std::getenv("DDSLEUTH_FASTDDS_OBSERVER");
    return value != nullptr && std::string(value) == "1";
}

inline std::string actor()
{
    const char* value = std::getenv("DDSLEUTH_ACTOR");
    return value == nullptr || *value == '\0' ? "unknown" : value;
}

template<typename Guid>
std::string guid_string(
        const Guid& guid)
{
    std::ostringstream output;
    output << guid;
    return output.str();
}

inline EventSink& sink()
{
    static EventSink event_sink("fastdds", stderr);
    return event_sink;
}

struct KeyMaterialPart
{
    std::string key_class;
    std::string semantics;
    size_t offset;
    size_t size;
};

inline std::vector<KeyMaterialPart> split_key_material(
        const std::vector<uint8_t>& material)
{
    // Fast DDS serializes KeyMaterial_AES_GCM_GMAC as a fixed transform kind,
    // length-prefixed salt, sender id/key, and an optional receiver-specific
    // id/key. Keep this parser local to the revision-pinned observer so the
    // vendor-neutral event model never depends on the C++ object layout.
    if (material.size() < 8)
    {
        return {{"opaque", "opaque_serialized_key_material", 0, material.size()}};
    }
    const uint8_t kind = material[3];
    if (kind == 0)
    {
        return {{"opaque", "empty_key_material", 0, material.size()}};
    }
    const size_t expected_key_size = kind <= 2 ? 16 : 32;
    auto sequence_size = [&material](size_t offset, size_t& size) -> bool
            {
                if (offset + 4 > material.size() || material[offset] != 0 ||
                        material[offset + 1] != 0 || material[offset + 2] != 0)
                {
                    return false;
                }
                size = material[offset + 3];
                return offset + 4 + size <= material.size();
            };

    size_t salt_size = 0;
    if (!sequence_size(4, salt_size) || salt_size != expected_key_size)
    {
        return {{"opaque", "opaque_serialized_key_material", 0, material.size()}};
    }
    size_t position = 8 + salt_size;
    if (position + 4 > material.size())
    {
        return {{"opaque", "opaque_serialized_key_material", 0, material.size()}};
    }
    position += 4; // sender key id
    size_t sender_size = 0;
    if (!sequence_size(position, sender_size) || sender_size != expected_key_size)
    {
        return {{"opaque", "opaque_serialized_key_material", 0, material.size()}};
    }
    position += 4 + sender_size;
    if (position + 4 > material.size())
    {
        return {{"opaque", "opaque_serialized_key_material", 0, material.size()}};
    }

    const size_t receiver_offset = position;
    bool has_receiver_specific_key = false;
    for (size_t index = 0; index < 4; ++index)
    {
        has_receiver_specific_key = has_receiver_specific_key || material[position + index] != 0;
    }
    position += 4;
    std::vector<KeyMaterialPart> parts{{
        "sender",
        "common_sender",
        0,
        receiver_offset,
    }};
    if (!has_receiver_specific_key)
    {
        if (position + 4 != material.size())
        {
            return {{"opaque", "opaque_serialized_key_material", 0, material.size()}};
        }
        return parts;
    }

    size_t receiver_size = 0;
    if (!sequence_size(position, receiver_size) || receiver_size != expected_key_size)
    {
        return {{"opaque", "opaque_serialized_key_material", 0, material.size()}};
    }
    position += 4 + receiver_size;
    if (position != material.size())
    {
        return {{"opaque", "opaque_serialized_key_material", 0, material.size()}};
    }
    parts.push_back({
        "receiver_specific",
        "recipient_specific",
        receiver_offset,
        position - receiver_offset,
    });
    return parts;
}

inline void emit_error(
        const std::string& phase,
        const std::string& reason)
{
    sink().emit(
        "probe.observer_error",
        actor(),
        "failed",
        JsonObject().string("phase", phase).string("reason", reason));
}

inline void observe_session_rotation(
        const std::string& context,
        uint32_t previous_session_id,
        uint32_t session_id,
        uint64_t max_blocks_per_session)
{
    if (!enabled())
    {
        return;
    }

    try
    {
        sink().emit(
            "key.rotated",
            actor(),
            "rotated",
            JsonObject()
                    .string("rotation_kind", "session_key")
                    .string("context", context)
                    .integer("previous_session_id", previous_session_id)
                    .integer("session_id", session_id)
                    .integer("max_blocks_per_session", static_cast<int64_t>(max_blocks_per_session)));
    }
    catch (const std::exception& error)
    {
        emit_error("session_rotation", error.what());
    }
    catch (...)
    {
        emit_error("session_rotation", "unknown observer failure");
    }
}

template<typename Guid, typename TokenSequence>
void observe_endpoint_tokens(
        const std::string& phase,
        const std::string& token_class,
        const Guid& local_participant,
        const Guid& destination_participant,
        const Guid& destination_endpoint,
        const Guid& source_endpoint,
        const TokenSequence& tokens)
{
    if (!enabled())
    {
        return;
    }

    try
    {
        const std::string local_participant_text = guid_string(local_participant);
        const std::string destination_participant_text = guid_string(destination_participant);
        const std::string destination_endpoint_text = guid_string(destination_endpoint);
        const std::string source_endpoint_text = guid_string(source_endpoint);
        const bool destination_is_builtin = destination_endpoint.is_builtin();
        const bool source_is_builtin = source_endpoint.is_builtin();
        const std::string endpoint_class =
                destination_is_builtin || source_is_builtin ? "builtin" : "user";
        const bool received = phase == "received";

        sink().emit(
            received ? "crypto_token.observed" : "crypto_token.generated",
            actor(),
            received ? "observed" : "generated",
            JsonObject()
                    .string("observation_phase", phase)
                    .string("token_class", token_class)
                    .string("local_participant_guid", local_participant_text)
                    .string("destination_participant_guid", destination_participant_text)
                    .string("destination_endpoint_guid", destination_endpoint_text)
                    .string("source_endpoint_guid", source_endpoint_text)
                    .string("endpoint_class", endpoint_class)
                    .boolean("destination_is_builtin", destination_is_builtin)
                    .boolean("source_is_builtin", source_is_builtin)
                    .boolean("addressed_to_local", local_participant_text == destination_participant_text)
                    .integer("token_count", static_cast<int64_t>(tokens.size())));

        RunLocalFingerprinter fingerprinter = RunLocalFingerprinter::from_environment();
        size_t token_index = 0;
        for (const auto& token : tokens)
        {
            size_t property_index = 0;
            for (const auto& property : token.binary_properties())
            {
                if (property.name() != "dds.cryp.keymat" || property.value().empty())
                {
                    ++property_index;
                    continue;
                }
                const auto& material = property.value();
                const auto parts = split_key_material(material);
                for (const auto& part : parts)
                {
                    sink().emit(
                        "key_material.observed",
                        actor(),
                        "observed",
                        JsonObject()
                                .string("observation_phase", phase)
                                .string("token_class", token_class)
                                .string("key_class", part.key_class)
                                .string("material_semantics", part.semantics)
                                .string("local_participant_guid", local_participant_text)
                                .string("destination_participant_guid", destination_participant_text)
                                .string("destination_endpoint_guid", destination_endpoint_text)
                                .string("source_endpoint_guid", source_endpoint_text)
                                .string("endpoint_class", endpoint_class)
                                .boolean("destination_is_builtin", destination_is_builtin)
                                .boolean("source_is_builtin", source_is_builtin)
                                .boolean("receiver_specific_key_present", parts.size() > 1)
                                .string(
                                    "key_fingerprint",
                                    fingerprinter.fingerprint(
                                        material.data() + part.offset,
                                        part.size))
                                .integer("material_bytes", static_cast<int64_t>(part.size))
                                .integer(
                                    "serialized_material_bytes",
                                    static_cast<int64_t>(material.size()))
                                .integer("token_index", static_cast<int64_t>(token_index))
                                .integer("property_index", static_cast<int64_t>(property_index)));
                }
                ++property_index;
            }
            ++token_index;
        }
    }
    catch (const std::exception& error)
    {
        // Instrumentation must never change the implementation's protocol result.
        emit_error(phase, error.what());
    }
    catch (...)
    {
        emit_error(phase, "unknown observer failure");
    }
}

} // namespace fastdds_observer
} // namespace ddsleuth
