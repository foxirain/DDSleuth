#include <arpa/inet.h>
#include <dlfcn.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

namespace {

using SendTo = ssize_t (*)(int, const void*, size_t, int, const sockaddr*, socklen_t);
using SendMsg = ssize_t (*)(int, const msghdr*, int);

struct Action
{
    double at_ms;
    std::string id;
    std::string operation;
    std::vector<std::string> arguments;
};

struct Datagram
{
    int fd{-1};
    std::vector<uint8_t> bytes;
    sockaddr_storage destination{};
    socklen_t destination_size{0};
};

std::vector<std::string> split_tabs(const std::string& line)
{
    std::vector<std::string> result;
    size_t start = 0;
    while (true)
    {
        const size_t end = line.find('\t', start);
        result.push_back(line.substr(start, end - start));
        if (end == std::string::npos)
        {
            return result;
        }
        start = end + 1;
    }
}

std::string json_escape(const std::string& value)
{
    std::string result;
    for (char character : value)
    {
        if (character == '"' || character == '\\')
        {
            result.push_back('\\');
            result.push_back(character);
        }
        else if (static_cast<unsigned char>(character) >= 0x20)
        {
            result.push_back(character);
        }
    }
    return result;
}

void emit(const std::string& kind, const std::string& actor, const std::string& outcome,
        const std::string& fault, size_t bytes, const std::string& action_id,
        const std::string& source_action_id = "")
{
    const auto monotonic_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    std::ostringstream output;
    output << "DDSLEUTH_EVENT {\"kind\":\"" << kind
           << "\",\"actor\":\"" << json_escape(actor)
           << "\",\"implementation\":\"fastdds\",\"outcome\":\"" << outcome
           << "\",\"monotonic_ns\":" << monotonic_ns
           << ",\"attributes\":{\"fault\":\"" << fault
           << "\",\"transport\":\"udp\",\"loopback\":true,\"packet_bytes\":" << bytes
           << ",\"action_id\":\"" << json_escape(action_id) << "\"";
    if (!source_action_id.empty())
    {
        output << ",\"source_action_id\":\"" << json_escape(source_action_id) << "\"";
    }
    output << "}}\n";
    const std::string text = output.str();
    static std::mutex output_mutex;
    std::lock_guard<std::mutex> lock(output_mutex);
    size_t written = 0;
    while (written < text.size())
    {
        const ssize_t result = ::write(
            STDERR_FILENO, text.data() + written, text.size() - written);
        if (result <= 0)
        {
            break;
        }
        written += static_cast<size_t>(result);
    }
}

bool is_loopback(const sockaddr* address)
{
    if (address == nullptr)
    {
        return false;
    }
    if (address->sa_family == AF_INET)
    {
        const auto* ipv4 = reinterpret_cast<const sockaddr_in*>(address);
        return (ntohl(ipv4->sin_addr.s_addr) >> 24U) == 127U;
    }
    if (address->sa_family == AF_INET6)
    {
        const auto* ipv6 = reinterpret_cast<const sockaddr_in6*>(address);
        return IN6_IS_ADDR_LOOPBACK(&ipv6->sin6_addr);
    }
    return false;
}

uint32_t positive(const Action& action, size_t index, uint32_t fallback)
{
    if (action.arguments.size() <= index)
    {
        return fallback;
    }
    try
    {
        const unsigned long value = std::stoul(action.arguments[index]);
        return value == 0 || value > UINT32_MAX ? fallback : static_cast<uint32_t>(value);
    }
    catch (...)
    {
        return fallback;
    }
}

class Controller
{
public:
    Controller()
        : actor_(std::getenv("DDSLEUTH_ACTOR") == nullptr ? "unknown" : std::getenv("DDSLEUTH_ACTOR"))
        , started_(std::chrono::steady_clock::now())
        , real_sendto_(reinterpret_cast<SendTo>(dlsym(RTLD_NEXT, "sendto")))
    {
        const char* enabled = std::getenv("DDSLEUTH_TRANSPORT_FAULTS");
        const char* plan = std::getenv("DDSLEUTH_ACTION_PLAN");
        if (enabled == nullptr || std::string(enabled) != "1" || plan == nullptr || real_sendto_ == nullptr)
        {
            return;
        }
        std::ifstream input(plan);
        std::string line;
        if (!input || !std::getline(input, line) || line != "# ddsleuth-action-plan-v1")
        {
            return;
        }
        while (std::getline(input, line))
        {
            const auto fields = split_tabs(line);
            if (fields.size() < 3 || fields[2].rfind("transport.", 0) != 0)
            {
                continue;
            }
            try
            {
                actions_.push_back({
                    std::stod(fields[0]), fields[1], fields[2],
                    std::vector<std::string>(fields.begin() + 3, fields.end())});
            }
            catch (...)
            {
                actions_.clear();
                return;
            }
        }
        if (!actions_.empty())
        {
            enabled_ = true;
            const char* control = std::getenv("DDSLEUTH_TRANSPORT_CONTROL");
            if (control == nullptr || std::string(control) != "explicit")
            {
                size_t next_action = 0;
                while (next_action < actions_.size() &&
                        actions_[next_action].at_ms <= 0.0 &&
                        actions_[next_action].operation != "transport.replay_last")
                {
                    static_cast<void>(apply(actions_[next_action]));
                    ++next_action;
                }
                if (next_action < actions_.size())
                {
                    std::thread([this, next_action]() { run_actions(next_action); }).detach();
                }
            }
        }
    }

    ssize_t send(int fd, const void* data, size_t size, int flags,
            const sockaddr* destination, socklen_t destination_size)
    {
        if (!enabled_ || !is_loopback(destination) || size > 1024U * 1024U)
        {
            return real_sendto_(fd, data, size, flags, destination, destination_size);
        }

        uint32_t delay_ms = 0;
        uint32_t duplicates = 0;
        std::string capture_id;
        std::string drop_id;
        std::string delay_id;
        std::string duplicate_id;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            remember(last_, fd, data, size, destination, destination_size);
            if (capture_remaining_ > 0)
            {
                --capture_remaining_;
                capture_id = capture_action_;
                remember(captured_, fd, data, size, destination, destination_size);
                captured_action_ = capture_action_;
            }
            if (drop_remaining_ > 0)
            {
                --drop_remaining_;
                drop_id = drop_action_;
            }
            else
            {
                delay_ms = delay_ms_;
                delay_ms_ = 0;
                delay_id = delay_action_;
                duplicates = duplicate_remaining_;
                duplicate_remaining_ = 0;
                duplicate_id = duplicate_action_;
            }
        }
        available_.notify_all();
        if (!capture_id.empty())
        {
            emit("transport.datagram_captured", actor_, "captured", "capture_next", size,
                    capture_id);
        }
        if (!drop_id.empty())
        {
            emit("transport.datagram_dropped", actor_, "dropped", "drop_next", size, drop_id);
            return static_cast<ssize_t>(size);
        }
        if (delay_ms > 0)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms));
            emit("transport.datagram_delayed", actor_, "delayed", "delay_next", size, delay_id);
        }
        const ssize_t result = real_sendto_(fd, data, size, flags, destination, destination_size);
        for (uint32_t index = 0; index < duplicates && result >= 0; ++index)
        {
            static_cast<void>(real_sendto_(fd, data, size, flags, destination, destination_size));
        }
        if (duplicates > 0 && result >= 0)
        {
            emit("transport.datagram_duplicated", actor_, "duplicated", "duplicate_next", size,
                    duplicate_id);
        }
        return result;
    }

    SendTo real_sendto() const
    {
        return real_sendto_;
    }

    bool apply(const Action& action)
    {
        if (!enabled_)
        {
            return false;
        }
        if (action.operation == "transport.drop_next")
        {
            std::lock_guard<std::mutex> lock(mutex_);
            drop_remaining_ += positive(action, 0, 1);
            drop_action_ = action.id;
            emit("transport.fault_armed", actor_, "armed", "drop_next", 0, action.id);
            return true;
        }
        if (action.operation == "transport.delay_next")
        {
            std::lock_guard<std::mutex> lock(mutex_);
            delay_ms_ = positive(action, 0, 1);
            delay_action_ = action.id;
            emit("transport.fault_armed", actor_, "armed", "delay_next", 0, action.id);
            return true;
        }
        if (action.operation == "transport.duplicate_next")
        {
            std::lock_guard<std::mutex> lock(mutex_);
            duplicate_remaining_ += positive(action, 0, 1);
            duplicate_action_ = action.id;
            emit("transport.fault_armed", actor_, "armed", "duplicate_next", 0, action.id);
            return true;
        }
        if (action.operation == "transport.capture_next")
        {
            std::lock_guard<std::mutex> lock(mutex_);
            capture_remaining_ += positive(action, 0, 1);
            capture_action_ = action.id;
            emit("transport.fault_armed", actor_, "armed", "capture_next", 0, action.id);
            return true;
        }
        if (action.operation == "transport.replay_last")
        {
            emit("transport.fault_armed", actor_, "armed", "replay_last", 0, action.id);
            replay(action);
            return true;
        }
        return false;
    }

private:
    void remember(Datagram& target, int fd, const void* data, size_t size,
            const sockaddr* destination, socklen_t destination_size)
    {
        if (target.fd >= 0)
        {
            ::close(target.fd);
        }
        target.fd = ::dup(fd);
        target.bytes.assign(
            static_cast<const uint8_t*>(data), static_cast<const uint8_t*>(data) + size);
        target.destination_size = destination_size;
        std::memcpy(&target.destination, destination, destination_size);
    }

    void run_actions(size_t first_action)
    {
        for (size_t index = first_action; index < actions_.size(); ++index)
        {
            const Action& action = actions_[index];
            const auto offset = std::chrono::duration_cast<std::chrono::steady_clock::duration>(
                std::chrono::duration<double, std::milli>(action.at_ms));
            std::this_thread::sleep_until(started_ + offset);
            static_cast<void>(apply(action));
        }
    }

    void replay(const Action& action)
    {
        Datagram datagram;
        std::string source_action_id;
        {
            std::unique_lock<std::mutex> lock(mutex_);
            available_.wait_for(lock, std::chrono::seconds(5), [this]()
                    {
                        return captured_.fd >= 0 || last_.fd >= 0;
                    });
            const Datagram& source = captured_.fd >= 0 ? captured_ : last_;
            source_action_id = captured_.fd >= 0 ? captured_action_ : "latest_datagram";
            if (source.fd < 0)
            {
                emit("transport.datagram_replayed", actor_, "failed", "replay_last", 0,
                        action.id);
                return;
            }
            datagram.fd = ::dup(source.fd);
            datagram.bytes = source.bytes;
            datagram.destination = source.destination;
            datagram.destination_size = source.destination_size;
        }
        const uint32_t count = positive(action, 0, 1);
        bool succeeded = true;
        for (uint32_t index = 0; index < count; ++index)
        {
            succeeded = succeeded && real_sendto_(
                datagram.fd, datagram.bytes.data(), datagram.bytes.size(), 0,
                reinterpret_cast<const sockaddr*>(&datagram.destination),
                datagram.destination_size) >= 0;
        }
        ::close(datagram.fd);
        emit("transport.datagram_replayed", actor_, succeeded ? "replayed" : "failed",
                "replay_last", datagram.bytes.size(), action.id, source_action_id);
    }

    std::string actor_;
    std::chrono::steady_clock::time_point started_;
    SendTo real_sendto_{nullptr};
    bool enabled_{false};
    std::vector<Action> actions_;
    std::mutex mutex_;
    std::condition_variable available_;
    Datagram last_;
    Datagram captured_;
    uint32_t capture_remaining_{0};
    uint32_t drop_remaining_{0};
    uint32_t delay_ms_{0};
    uint32_t duplicate_remaining_{0};
    std::string drop_action_;
    std::string delay_action_;
    std::string duplicate_action_;
    std::string capture_action_;
    std::string captured_action_;
};

Controller& controller()
{
    static Controller* instance = new Controller();
    return *instance;
}

} // namespace

extern "C" ssize_t sendto(int fd, const void* data, size_t size, int flags,
        const sockaddr* destination, socklen_t destination_size)
{
    return controller().send(fd, data, size, flags, destination, destination_size);
}

extern "C" ssize_t sendmsg(int fd, const msghdr* message, int flags)
{
    static auto real_sendmsg = reinterpret_cast<SendMsg>(dlsym(RTLD_NEXT, "sendmsg"));
    if (message == nullptr || message->msg_name == nullptr || message->msg_iov == nullptr)
    {
        return real_sendmsg(fd, message, flags);
    }
    size_t size = 0;
    for (size_t index = 0; index < message->msg_iovlen; ++index)
    {
        size += message->msg_iov[index].iov_len;
    }
    if (size > 1024U * 1024U)
    {
        return real_sendmsg(fd, message, flags);
    }
    std::vector<uint8_t> bytes;
    bytes.reserve(size);
    for (size_t index = 0; index < message->msg_iovlen; ++index)
    {
        const auto* begin = static_cast<const uint8_t*>(message->msg_iov[index].iov_base);
        bytes.insert(bytes.end(), begin, begin + message->msg_iov[index].iov_len);
    }
    return controller().send(
        fd, bytes.data(), bytes.size(), flags,
        static_cast<const sockaddr*>(message->msg_name), message->msg_namelen);
}

extern "C" int ddsleuth_transport_apply(
        const char* action_id,
        const char* operation,
        const char* const* arguments,
        size_t argument_count)
{
    if (action_id == nullptr || operation == nullptr)
    {
        return -1;
    }
    Action action;
    action.id = action_id;
    action.operation = operation;
    for (size_t index = 0; index < argument_count; ++index)
    {
        if (arguments == nullptr || arguments[index] == nullptr)
        {
            return -1;
        }
        action.arguments.emplace_back(arguments[index]);
    }
    return controller().apply(action) ? 0 : -1;
}
