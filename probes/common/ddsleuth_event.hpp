#pragma once

#include <chrono>
#include <cstdio>
#include <cstdint>
#include <mutex>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace ddsleuth {

inline std::string json_quote(
        const std::string& value)
{
    std::ostringstream output;
    output << '"';
    static constexpr char HEX[] = "0123456789abcdef";
    for (unsigned char byte : value)
    {
        switch (byte)
        {
            case '"':
                output << "\\\"";
                break;
            case '\\':
                output << "\\\\";
                break;
            case '\b':
                output << "\\b";
                break;
            case '\f':
                output << "\\f";
                break;
            case '\n':
                output << "\\n";
                break;
            case '\r':
                output << "\\r";
                break;
            case '\t':
                output << "\\t";
                break;
            default:
                if (byte < 0x20)
                {
                    output << "\\u00" << HEX[(byte >> 4) & 0xf] << HEX[byte & 0xf];
                }
                else
                {
                    output << static_cast<char>(byte);
                }
        }
    }
    output << '"';
    return output.str();
}

class JsonObject
{
public:

    JsonObject& string(
            const std::string& name,
            const std::string& value)
    {
        members_.emplace_back(json_quote(name), json_quote(value));
        return *this;
    }

    JsonObject& boolean(
            const std::string& name,
            bool value)
    {
        members_.emplace_back(json_quote(name), value ? "true" : "false");
        return *this;
    }

    JsonObject& integer(
            const std::string& name,
            int64_t value)
    {
        members_.emplace_back(json_quote(name), std::to_string(value));
        return *this;
    }

    std::string render() const
    {
        std::ostringstream output;
        output << '{';
        for (size_t index = 0; index < members_.size(); ++index)
        {
            if (index != 0)
            {
                output << ',';
            }
            output << members_[index].first << ':' << members_[index].second;
        }
        output << '}';
        return output.str();
    }

private:

    std::vector<std::pair<std::string, std::string>> members_;
};

class EventSink
{
public:

    explicit EventSink(
            std::string implementation,
            FILE* stream = stderr)
        : implementation_(std::move(implementation))
        , stream_(stream)
    {
    }

    void emit(
            const std::string& kind,
            const std::string& actor,
            const std::string& outcome,
            const JsonObject& attributes = JsonObject())
    {
        const auto monotonic_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
        const std::string line =
                "DDSLEUTH_EVENT {\"kind\":" + json_quote(kind) +
                ",\"actor\":" + json_quote(actor) +
                ",\"implementation\":" + json_quote(implementation_) +
                ",\"outcome\":" + json_quote(outcome) +
                ",\"monotonic_ns\":" + std::to_string(monotonic_ns) +
                ",\"attributes\":" + attributes.render() + "}\n";
        std::lock_guard<std::mutex> lock(mutex_);
        std::fwrite(line.data(), 1, line.size(), stream_);
        std::fflush(stream_);
    }

private:

    std::string implementation_;
    FILE* stream_;
    std::mutex mutex_;
};

} // namespace ddsleuth
