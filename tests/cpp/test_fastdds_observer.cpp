#include "ddsleuth_fastdds_observer.hpp"

#include <cstdlib>
#include <ostream>
#include <string>
#include <vector>

namespace {

struct FakeGuid
{
    std::string value;
    bool builtin{false};

    bool is_builtin() const
    {
        return builtin;
    }
};

std::ostream& operator <<(
        std::ostream& output,
        const FakeGuid& guid)
{
    return output << guid.value;
}

class FakeProperty
{
public:

    FakeProperty(
            std::string name,
            std::vector<uint8_t> value)
        : name_(std::move(name))
        , value_(std::move(value))
    {
    }

    const std::string& name() const
    {
        return name_;
    }

    const std::vector<uint8_t>& value() const
    {
        return value_;
    }

private:

    std::string name_;
    std::vector<uint8_t> value_;
};

struct FakeToken
{
    const std::vector<FakeProperty>& binary_properties() const
    {
        return properties;
    }

    std::vector<FakeProperty> properties;
};

} // namespace

int main()
{
    setenv("DDSLEUTH_FASTDDS_OBSERVER", "1", 1);
    setenv("DDSLEUTH_ACTOR", "alice", 1);
    setenv("DDSLEUTH_FINGERPRINT_SECRET", "4242424242424242424242424242424242424242424242424242424242424242", 1);

    const std::vector<FakeToken> tokens{{{
        FakeProperty("dds.cryp.keymat", {0x10, 0x20, 0x30, 0x40}),
    }}};
    const FakeGuid local{"local|participant", true};
    const FakeGuid destination_participant{"local|participant", true};
    const FakeGuid destination_endpoint{"remote|reader", false};
    const FakeGuid source_endpoint{"local|writer", false};
    ddsleuth::fastdds_observer::observe_endpoint_tokens(
        "generated", "datawriter", local, destination_participant,
        destination_endpoint, source_endpoint, tokens);
    ddsleuth::fastdds_observer::observe_endpoint_tokens(
        "received", "datawriter", local, destination_participant,
        destination_endpoint, source_endpoint, tokens);
    ddsleuth::fastdds_observer::observe_session_rotation(
        "serialized_payload", 41, 42, 2);
}
