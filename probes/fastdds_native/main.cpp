#include "ddsleuth_event.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdlib>
#include <cmath>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>

#include <fastdds/dds/core/ReturnCode.hpp>
#include <fastdds/dds/core/policy/QosPolicies.hpp>
#include <fastdds/dds/core/status/PublicationMatchedStatus.hpp>
#include <fastdds/dds/core/status/StatusMask.hpp>
#include <fastdds/dds/core/status/SubscriptionMatchedStatus.hpp>
#include <fastdds/dds/domain/DomainParticipant.hpp>
#include <fastdds/dds/domain/DomainParticipantFactory.hpp>
#include <fastdds/dds/domain/qos/DomainParticipantQos.hpp>
#include <fastdds/dds/publisher/DataWriter.hpp>
#include <fastdds/dds/publisher/DataWriterListener.hpp>
#include <fastdds/dds/publisher/Publisher.hpp>
#include <fastdds/dds/publisher/qos/DataWriterQos.hpp>
#include <fastdds/dds/subscriber/DataReader.hpp>
#include <fastdds/dds/subscriber/DataReaderListener.hpp>
#include <fastdds/dds/subscriber/SampleInfo.hpp>
#include <fastdds/dds/subscriber/Subscriber.hpp>
#include <fastdds/dds/subscriber/qos/DataReaderQos.hpp>
#include <fastdds/dds/topic/Topic.hpp>
#include <fastdds/dds/topic/TypeSupport.hpp>
#include <fastdds/dds/xtypes/dynamic_types/DynamicData.hpp>
#include <fastdds/dds/xtypes/dynamic_types/DynamicDataFactory.hpp>
#include <fastdds/dds/xtypes/dynamic_types/DynamicPubSubType.hpp>
#include <fastdds/dds/xtypes/dynamic_types/DynamicType.hpp>
#include <fastdds/dds/xtypes/dynamic_types/DynamicTypeBuilder.hpp>
#include <fastdds/dds/xtypes/dynamic_types/DynamicTypeBuilderFactory.hpp>
#include <fastdds/dds/xtypes/dynamic_types/MemberDescriptor.hpp>
#include <fastdds/dds/xtypes/dynamic_types/TypeDescriptor.hpp>
#include <fastdds/dds/xtypes/type_representation/TypeObject.hpp>

using namespace eprosima::fastdds::dds;

namespace {

struct Arguments
{
    std::string actor;
    std::string mode;
    DomainId_t domain;
    std::string topic;
    std::chrono::milliseconds timeout;
    std::chrono::milliseconds hold_after_write;
    uint32_t expected_matches;
    uint32_t expected_samples;
    uint32_t sample_count;
    uint32_t max_blocks_per_session;
    std::string expected;
    std::string message;
};

struct PlannedAction
{
    double at_ms;
    std::string id;
    std::string operation;
    std::vector<std::string> arguments;
};

std::string required_environment(
        const char* name)
{
    const char* value = std::getenv(name);
    if (value == nullptr || *value == '\0')
    {
        throw std::runtime_error(std::string("missing environment variable ") + name);
    }
    return value;
}

std::string optional_environment(
        const char* name,
        const std::string& fallback)
{
    const char* value = std::getenv(name);
    return value == nullptr || *value == '\0' ? fallback : value;
}

uint32_t positive_environment(
        const char* name,
        uint32_t fallback)
{
    const std::string text = optional_environment(name, std::to_string(fallback));
    size_t consumed = 0;
    const unsigned long value = std::stoul(text, &consumed);
    if (consumed != text.size() || value == 0 ||
            value > static_cast<unsigned long>(UINT32_MAX))
    {
        throw std::runtime_error(std::string(name) + " must be a positive 32-bit integer");
    }
    return static_cast<uint32_t>(value);
}

std::chrono::milliseconds nonnegative_milliseconds_environment(
        const char* name)
{
    const std::string text = optional_environment(name, "0");
    size_t consumed = 0;
    const unsigned long value = std::stoul(text, &consumed);
    if (consumed != text.size() || value > static_cast<unsigned long>(UINT32_MAX))
    {
        throw std::runtime_error(std::string(name) + " must be a non-negative 32-bit integer");
    }
    return std::chrono::milliseconds(value);
}

uint32_t nonnegative_environment(
        const char* name)
{
    const std::string text = optional_environment(name, "0");
    size_t consumed = 0;
    const unsigned long value = std::stoul(text, &consumed);
    if (consumed != text.size() || value > static_cast<unsigned long>(UINT32_MAX))
    {
        throw std::runtime_error(std::string(name) + " must be a non-negative 32-bit integer");
    }
    return static_cast<uint32_t>(value);
}

uint32_t positive_text(
        const std::string& text,
        const std::string& context)
{
    size_t consumed = 0;
    const unsigned long value = std::stoul(text, &consumed);
    if (consumed != text.size() || value == 0 ||
            value > static_cast<unsigned long>(UINT32_MAX))
    {
        throw std::runtime_error(context + " must be a positive 32-bit integer");
    }
    return static_cast<uint32_t>(value);
}

std::vector<std::string> split_tabs(
        const std::string& line)
{
    std::vector<std::string> fields;
    size_t start = 0;
    while (true)
    {
        const size_t delimiter = line.find('\t', start);
        fields.push_back(line.substr(start, delimiter - start));
        if (delimiter == std::string::npos)
        {
            break;
        }
        start = delimiter + 1;
    }
    return fields;
}

std::vector<PlannedAction> load_action_plan()
{
    const std::filesystem::path path(required_environment("DDSLEUTH_ACTION_PLAN"));
    std::ifstream input(path);
    if (!input)
    {
        throw std::runtime_error("cannot open DDSLEUTH_ACTION_PLAN");
    }
    std::string line;
    if (!std::getline(input, line) || line != "# ddsleuth-action-plan-v1")
    {
        throw std::runtime_error("unsupported DDSLEUTH_ACTION_PLAN header");
    }
    std::vector<PlannedAction> actions;
    double previous_at_ms = -1.0;
    size_t line_number = 1;
    while (std::getline(input, line))
    {
        ++line_number;
        if (line.empty())
        {
            continue;
        }
        std::vector<std::string> fields = split_tabs(line);
        if (fields.size() < 3 || fields[1].empty() || fields[2].empty())
        {
            throw std::runtime_error(
                      "invalid action plan line " + std::to_string(line_number));
        }
        size_t consumed = 0;
        const double at_ms = std::stod(fields[0], &consumed);
        if (consumed != fields[0].size() || !std::isfinite(at_ms) ||
                at_ms < 0 || at_ms < previous_at_ms)
        {
            throw std::runtime_error(
                      "action plan timestamps must be finite, non-negative, and ordered");
        }
        previous_at_ms = at_ms;
        actions.push_back({
            at_ms,
            fields[1],
            fields[2],
            std::vector<std::string>(fields.begin() + 3, fields.end()),
        });
    }
    if (actions.empty())
    {
        throw std::runtime_error("DDSLEUTH_ACTION_PLAN contains no actions");
    }
    return actions;
}

std::string file_uri(
        const std::filesystem::path& path)
{
    return "file://" + std::filesystem::absolute(path).string();
}

Arguments parse_arguments(
        int argc,
        char** argv)
{
    if (argc < 7 || argc > 8)
    {
        throw std::runtime_error(
                  "usage: ddsleuth_fastdds_probe ACTOR MODE DOMAIN TOPIC TIMEOUT_MS EXPECTED [MESSAGE]");
    }
    size_t consumed = 0;
    const unsigned long domain = std::stoul(argv[3], &consumed);
    if (consumed != std::string(argv[3]).size() || domain > 232)
    {
        throw std::runtime_error("DOMAIN must be between 0 and 232");
    }
    const unsigned long timeout = std::stoul(argv[5], &consumed);
    if (consumed != std::string(argv[5]).size() || timeout == 0)
    {
        throw std::runtime_error("TIMEOUT_MS must be positive");
    }
    const std::string mode = argv[2];
    if (mode != "writer" && mode != "recreate-writer" && mode != "scripted-writer" &&
            mode != "reader" && mode != "scripted-reader" && mode != "check-reader" &&
            mode != "check-writer" && mode != "observe-denied-reader" &&
            mode != "observe-denied-writer")
    {
        throw std::runtime_error(
                  "MODE must be writer, recreate-writer, scripted-writer, reader, "
                  "scripted-reader, check-reader, check-writer, observe-denied-reader, "
                  "or observe-denied-writer");
    }
    const std::string expected = argv[6];
    if (expected != "allow" && expected != "deny")
    {
        throw std::runtime_error("EXPECTED must be allow or deny");
    }
    const uint32_t expected_matches = positive_environment("DDSLEUTH_EXPECTED_MATCHES", 1);
    const uint32_t expected_samples = positive_environment("DDSLEUTH_EXPECTED_SAMPLES", 1);
    const uint32_t sample_count = positive_environment("DDSLEUTH_SAMPLE_COUNT", 1);
    const uint32_t max_blocks_per_session =
            nonnegative_environment("DDSLEUTH_MAX_BLOCKS_PER_SESSION");
    if (max_blocks_per_session > static_cast<uint32_t>((std::numeric_limits<int>::max)()))
    {
        throw std::runtime_error("DDSLEUTH_MAX_BLOCKS_PER_SESSION exceeds the Fast DDS integer range");
    }
    const std::chrono::milliseconds hold_after_write =
            nonnegative_milliseconds_environment("DDSLEUTH_HOLD_AFTER_WRITE_MS");
    return Arguments{
        argv[1],
        mode,
        static_cast<DomainId_t>(domain),
        argv[4],
        std::chrono::milliseconds(timeout),
        hold_after_write,
        expected_matches,
        expected_samples,
        sample_count,
        max_blocks_per_session,
        expected,
        argc == 8 ? argv[7] : "ddsleuth-sample",
    };
}

DomainParticipantQos security_qos(
        const Arguments& arguments)
{
    const std::string identity_ca = required_environment("DDSLEUTH_IDENTITY_CA");
    const std::string identity_certificate = required_environment("DDSLEUTH_IDENTITY_CERTIFICATE");
    const std::string private_key = required_environment("DDSLEUTH_IDENTITY_PRIVATE_KEY");
    const std::string policies = required_environment("DDSLEUTH_FASTDDS_POLICIES");
    const std::string permissions_ca = optional_environment("DDSLEUTH_PERMISSIONS_CA", identity_ca);

    DomainParticipantQos qos = PARTICIPANT_QOS_DEFAULT;
    qos.name("ddsleuth-" + arguments.actor);
    auto& properties = qos.properties().properties();
    properties.emplace_back("dds.sec.auth.plugin", "builtin.PKI-DH");
    properties.emplace_back("dds.sec.auth.builtin.PKI-DH.identity_ca", file_uri(identity_ca));
    properties.emplace_back(
        "dds.sec.auth.builtin.PKI-DH.identity_certificate",
        file_uri(identity_certificate));
    properties.emplace_back("dds.sec.auth.builtin.PKI-DH.private_key", file_uri(private_key));
    properties.emplace_back("dds.sec.access.plugin", "builtin.Access-Permissions");
    properties.emplace_back(
        "dds.sec.access.builtin.Access-Permissions.permissions_ca",
        file_uri(permissions_ca));
    properties.emplace_back(
        "dds.sec.access.builtin.Access-Permissions.governance",
        file_uri(std::filesystem::path(policies) / "governance.smime"));
    properties.emplace_back(
        "dds.sec.access.builtin.Access-Permissions.permissions",
        file_uri(std::filesystem::path(policies) / "permissions.smime"));
    properties.emplace_back("dds.sec.crypto.plugin", "builtin.AES-GCM-GMAC");
    return qos;
}

DynamicType::_ref_type create_type()
{
    TypeDescriptor::_ref_type descriptor{traits<TypeDescriptor>::make_shared()};
    descriptor->kind(TK_STRUCTURE);
    descriptor->name("DdsSecLabSample");
    DynamicTypeBuilder::_ref_type builder =
            DynamicTypeBuilderFactory::get_instance()->create_type(descriptor);
    if (!builder)
    {
        throw std::runtime_error("cannot create dynamic type builder");
    }

    MemberDescriptor::_ref_type index{traits<MemberDescriptor>::make_shared()};
    index->name("index");
    index->type(DynamicTypeBuilderFactory::get_instance()->get_primitive_type(TK_UINT32));
    if (builder->add_member(index) != RETCODE_OK)
    {
        throw std::runtime_error("cannot add index member");
    }

    MemberDescriptor::_ref_type message{traits<MemberDescriptor>::make_shared()};
    message->name("message");
    message->type(
        DynamicTypeBuilderFactory::get_instance()->create_string_type(4096)->build());
    if (builder->add_member(message) != RETCODE_OK)
    {
        throw std::runtime_error("cannot add message member");
    }
    return builder->build();
}

class ParticipantOwner
{
public:

    explicit ParticipantOwner(
            DomainParticipant* participant)
        : participant_(participant)
    {
    }

    ParticipantOwner(const ParticipantOwner&) = delete;
    ParticipantOwner& operator=(const ParticipantOwner&) = delete;

    ~ParticipantOwner()
    {
        if (participant_ != nullptr)
        {
            participant_->delete_contained_entities();
            DomainParticipantFactory::get_instance()->delete_participant(participant_);
        }
    }

private:

    DomainParticipant* participant_;
};

class PublisherOwner
{
public:

    PublisherOwner(
            DomainParticipant* participant,
            Publisher* publisher)
        : participant_(participant)
        , publisher_(publisher)
    {
    }

    PublisherOwner(const PublisherOwner&) = delete;
    PublisherOwner& operator=(const PublisherOwner&) = delete;

    ~PublisherOwner()
    {
        if (publisher_ != nullptr)
        {
            publisher_->delete_contained_entities();
            participant_->delete_publisher(publisher_);
        }
    }

private:

    DomainParticipant* participant_;
    Publisher* publisher_;
};

class DataWriterOwner
{
public:

    DataWriterOwner(
            Publisher* publisher,
            DataWriter* writer)
        : publisher_(publisher)
        , writer_(writer)
    {
    }

    DataWriterOwner(const DataWriterOwner&) = delete;
    DataWriterOwner& operator=(const DataWriterOwner&) = delete;

    ~DataWriterOwner()
    {
        close();
    }

    void close()
    {
        if (writer_ != nullptr)
        {
            publisher_->delete_datawriter(writer_);
            writer_ = nullptr;
        }
    }

private:

    Publisher* publisher_;
    DataWriter* writer_;
};

class SubscriberOwner
{
public:

    SubscriberOwner(
            DomainParticipant* participant,
            Subscriber* subscriber)
        : participant_(participant)
        , subscriber_(subscriber)
    {
    }

    SubscriberOwner(const SubscriberOwner&) = delete;
    SubscriberOwner& operator=(const SubscriberOwner&) = delete;

    ~SubscriberOwner()
    {
        if (subscriber_ != nullptr)
        {
            subscriber_->delete_contained_entities();
            participant_->delete_subscriber(subscriber_);
        }
    }

private:

    DomainParticipant* participant_;
    Subscriber* subscriber_;
};

class WriterListener final : public DataWriterListener
{
public:

    void on_publication_matched(
            DataWriter*,
            const PublicationMatchedStatus& status) override
    {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            matched_count_ = status.current_count;
        }
        condition_.notify_all();
    }

    bool wait(
            std::chrono::milliseconds timeout,
            uint32_t expected_matches)
    {
        std::unique_lock<std::mutex> lock(mutex_);
        return condition_.wait_for(lock, timeout, [this, expected_matches]()
                {
                    return matched_count_ >= static_cast<int32_t>(expected_matches);
                });
    }

    int32_t matched_count()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return matched_count_;
    }

    void reset()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        matched_count_ = 0;
    }

private:

    std::mutex mutex_;
    std::condition_variable condition_;
    int32_t matched_count_{0};
};

class ReaderListener final : public DataReaderListener
{
public:

    ReaderListener(
            DynamicType::_ref_type type,
            ddsleuth::EventSink& sink,
            std::string actor,
            std::string topic)
        : data_(DynamicDataFactory::get_instance()->create_data(type))
        , sink_(sink)
        , actor_(std::move(actor))
        , topic_(std::move(topic))
    {
        if (!data_)
        {
            throw std::runtime_error("cannot create dynamic reader data");
        }
    }

    void on_data_available(
            DataReader* reader) override
    {
        SampleInfo info;
        while (reader->take_next_sample(&data_, &info) == RETCODE_OK)
        {
            if (!info.valid_data)
            {
                continue;
            }
            uint32_t index = 0;
            std::string message;
            if (data_->get_uint32_value(index, data_->get_member_id_by_name("index")) != RETCODE_OK ||
                    data_->get_string_value(message, data_->get_member_id_by_name("message")) != RETCODE_OK)
            {
                continue;
            }
            ddsleuth::JsonObject attributes;
            attributes.integer("sample_index", index)
                    .string("message", message)
                    .string("topic", topic_)
                    .boolean("attacker_controlled", false);
            sink_.emit("application.sample_received", actor_, "received", attributes);
            received_.fetch_add(1);
            condition_.notify_all();
        }
    }

    bool wait(
            std::chrono::milliseconds timeout,
            uint32_t expected_samples)
    {
        std::unique_lock<std::mutex> lock(mutex_);
        return condition_.wait_for(lock, timeout, [this, expected_samples]()
                {
                    return received_.load() >= expected_samples;
                });
    }

    uint32_t received_count() const
    {
        return received_.load();
    }

private:

    DynamicData::_ref_type data_;
    ddsleuth::EventSink& sink_;
    std::string actor_;
    std::string topic_;
    std::atomic<uint32_t> received_{0};
    std::mutex mutex_;
    std::condition_variable condition_;
};

void emit_access_decision(
        ddsleuth::EventSink& sink,
        const Arguments& arguments,
        const std::string& operation,
        bool allowed)
{
    ddsleuth::JsonObject attributes;
    attributes.string("operation", operation)
            .string("resource", arguments.topic);
    sink.emit(
        "access_control.decision",
        arguments.actor,
        allowed ? "allowed" : "denied",
        attributes);
}

void write_sample(
        DataWriter* writer,
        DynamicType::_ref_type dynamic_type,
        ddsleuth::EventSink& sink,
        const Arguments& arguments,
        uint32_t sample_index,
        const std::string& message,
        uint32_t lifecycle_epoch)
{
    DynamicData::_ref_type data = DynamicDataFactory::get_instance()->create_data(dynamic_type);
    if (!data)
    {
        throw std::runtime_error("cannot create dynamic writer data");
    }
    if (data->set_uint32_value(data->get_member_id_by_name("index"), sample_index) != RETCODE_OK ||
            data->set_string_value(data->get_member_id_by_name("message"), message) != RETCODE_OK)
    {
        throw std::runtime_error("cannot populate sample");
    }
    const ddsleuth::JsonObject sample_attributes = ddsleuth::JsonObject()
            .integer("sample_index", sample_index)
            .string("message", message)
            .integer("lifecycle_epoch", lifecycle_epoch);
    sink.emit("application.write_attempt", arguments.actor, "attempted", sample_attributes);
    if (writer->write(&data) != RETCODE_OK)
    {
        throw std::runtime_error("cannot write sample");
    }
    sink.emit("application.sample_written", arguments.actor, "succeeded", sample_attributes);
    writer->wait_for_acknowledgments({
        static_cast<int32_t>(arguments.timeout.count() / 1000),
        static_cast<uint32_t>((arguments.timeout.count() % 1000) * 1000000),
    });
}

void hold_after_write(
        ddsleuth::EventSink& sink,
        const Arguments& arguments,
        uint32_t lifecycle_epoch)
{
    if (arguments.hold_after_write.count() == 0)
    {
        return;
    }
    sink.emit("probe.ready", arguments.actor, "ready",
            ddsleuth::JsonObject()
                    .string("endpoint", "writer-hold")
                    .string("topic", arguments.topic)
                    .integer("hold_ms", arguments.hold_after_write.count())
                    .integer("lifecycle_epoch", lifecycle_epoch));
    std::this_thread::sleep_for(arguments.hold_after_write);
}

void wait_for_action_time(
        const std::chrono::steady_clock::time_point& started,
        const PlannedAction& action)
{
    const auto offset = std::chrono::duration_cast<std::chrono::steady_clock::duration>(
        std::chrono::duration<double, std::milli>(action.at_ms));
    std::this_thread::sleep_until(started + offset);
}

void emit_action_event(
        ddsleuth::EventSink& sink,
        const Arguments& arguments,
        const PlannedAction& action,
        const std::string& kind,
        const std::string& outcome)
{
    sink.emit(
        kind,
        arguments.actor,
        outcome,
        ddsleuth::JsonObject()
                .string("action_id", action.id)
                .string("operation", action.operation)
                .string("scheduled_at_ms", std::to_string(action.at_ms)));
}

uint32_t action_count(
        const PlannedAction& action,
        uint32_t fallback)
{
    return action.arguments.empty() ?
           fallback :
           positive_text(action.arguments[0], "action " + action.id + " count");
}

int run_scripted_writer(
        const Arguments& arguments,
        DomainParticipant* participant,
        Topic* topic,
        DynamicType::_ref_type dynamic_type,
        ddsleuth::EventSink& sink)
{
    const std::vector<PlannedAction> actions = load_action_plan();
    Publisher* publisher = participant->create_publisher(PUBLISHER_QOS_DEFAULT);
    if (publisher == nullptr)
    {
        throw std::runtime_error("cannot create publisher");
    }
    WriterListener listener;
    PublisherOwner publisher_owner(participant, publisher);
    DataWriterQos writer_qos = DATAWRITER_QOS_DEFAULT;
    publisher->get_default_datawriter_qos(writer_qos);
    writer_qos.reliability().kind = RELIABLE_RELIABILITY_QOS;
    if (arguments.max_blocks_per_session > 0)
    {
        writer_qos.properties().properties().emplace_back(
            "dds.sec.crypto.maxblockspersession",
            std::to_string(arguments.max_blocks_per_session));
    }

    DataWriter* writer = nullptr;
    uint32_t lifecycle_epoch = 0;
    uint32_t sample_index = 0;
    const auto started = std::chrono::steady_clock::now();
    for (const PlannedAction& action : actions)
    {
        wait_for_action_time(started, action);
        emit_action_event(sink, arguments, action, "action.started", "started");
        if (action.operation == "endpoint.create")
        {
            if (writer != nullptr)
            {
                throw std::runtime_error("cannot create a writer while one is active");
            }
            listener.reset();
            writer = publisher->create_datawriter(
                topic,
                writer_qos,
                &listener,
                StatusMask::all());
            const bool allowed = writer != nullptr;
            emit_access_decision(sink, arguments, "create_datawriter", allowed);
            if ((allowed ? "allow" : "deny") != arguments.expected)
            {
                return 4;
            }
            if (allowed)
            {
                ++lifecycle_epoch;
                sink.emit(
                    lifecycle_epoch == 1 ? "endpoint.created" : "endpoint.recreated",
                    arguments.actor,
                    "created",
                    ddsleuth::JsonObject()
                            .string("endpoint", "writer")
                            .string("topic", arguments.topic)
                            .integer("lifecycle_epoch", lifecycle_epoch));
            }
        }
        else if (action.operation == "endpoint.wait_match")
        {
            if (writer == nullptr)
            {
                throw std::runtime_error("cannot wait for a match without an active writer");
            }
            const uint32_t target = action_count(action, arguments.expected_matches);
            if (!listener.wait(arguments.timeout, target))
            {
                throw std::runtime_error("scripted writer did not reach the requested match count");
            }
            sink.emit("endpoint.matched", arguments.actor, "matched",
                    ddsleuth::JsonObject()
                            .string("endpoint", "writer")
                            .string("topic", arguments.topic)
                            .integer("matched_count", listener.matched_count())
                            .integer("expected_matches", target)
                            .integer("lifecycle_epoch", lifecycle_epoch));
        }
        else if (action.operation == "sample.write")
        {
            if (writer == nullptr)
            {
                throw std::runtime_error("cannot write without an active writer");
            }
            ++sample_index;
            const std::string message = action.arguments.empty() ?
                    arguments.message : action.arguments[0];
            write_sample(
                writer,
                dynamic_type,
                sink,
                arguments,
                sample_index,
                message,
                lifecycle_epoch);
        }
        else if (action.operation == "endpoint.destroy")
        {
            if (writer == nullptr)
            {
                throw std::runtime_error("cannot destroy a writer when none is active");
            }
            if (publisher->delete_datawriter(writer) != RETCODE_OK)
            {
                throw std::runtime_error("cannot destroy scripted writer");
            }
            writer = nullptr;
            sink.emit("endpoint.destroyed", arguments.actor, "destroyed",
                    ddsleuth::JsonObject()
                            .string("endpoint", "writer")
                            .string("topic", arguments.topic)
                            .integer("lifecycle_epoch", lifecycle_epoch));
        }
        else
        {
            throw std::runtime_error("unsupported scripted writer action: " + action.operation);
        }
        emit_action_event(sink, arguments, action, "action.completed", "completed");
    }
    return 0;
}

int run_scripted_reader(
        const Arguments& arguments,
        DomainParticipant* participant,
        Topic* topic,
        DynamicType::_ref_type dynamic_type,
        ddsleuth::EventSink& sink)
{
    const std::vector<PlannedAction> actions = load_action_plan();
    Subscriber* subscriber = participant->create_subscriber(SUBSCRIBER_QOS_DEFAULT);
    if (subscriber == nullptr)
    {
        throw std::runtime_error("cannot create subscriber");
    }
    ReaderListener listener(dynamic_type, sink, arguments.actor, arguments.topic);
    SubscriberOwner subscriber_owner(participant, subscriber);
    DataReaderQos reader_qos = DATAREADER_QOS_DEFAULT;
    subscriber->get_default_datareader_qos(reader_qos);
    reader_qos.reliability().kind = RELIABLE_RELIABILITY_QOS;

    DataReader* reader = nullptr;
    uint32_t lifecycle_epoch = 0;
    const auto started = std::chrono::steady_clock::now();
    for (const PlannedAction& action : actions)
    {
        wait_for_action_time(started, action);
        emit_action_event(sink, arguments, action, "action.started", "started");
        if (action.operation == "endpoint.create")
        {
            if (reader != nullptr)
            {
                throw std::runtime_error("cannot create a reader while one is active");
            }
            reader = subscriber->create_datareader(
                topic,
                reader_qos,
                &listener,
                StatusMask::all());
            const bool allowed = reader != nullptr;
            emit_access_decision(sink, arguments, "create_datareader", allowed);
            if ((allowed ? "allow" : "deny") != arguments.expected)
            {
                return 4;
            }
            if (allowed)
            {
                ++lifecycle_epoch;
                sink.emit(
                    lifecycle_epoch == 1 ? "endpoint.created" : "endpoint.recreated",
                    arguments.actor,
                    "created",
                    ddsleuth::JsonObject()
                            .string("endpoint", "reader")
                            .string("topic", arguments.topic)
                            .integer("lifecycle_epoch", lifecycle_epoch));
            }
        }
        else if (action.operation == "sample.wait")
        {
            if (reader == nullptr)
            {
                throw std::runtime_error("cannot wait for a sample without an active reader");
            }
            const uint32_t target = action_count(action, arguments.expected_samples);
            if (!listener.wait(arguments.timeout, target))
            {
                throw std::runtime_error("scripted reader did not receive the requested samples");
            }
        }
        else if (action.operation == "endpoint.destroy")
        {
            if (reader == nullptr)
            {
                throw std::runtime_error("cannot destroy a reader when none is active");
            }
            if (subscriber->delete_datareader(reader) != RETCODE_OK)
            {
                throw std::runtime_error("cannot destroy scripted reader");
            }
            reader = nullptr;
            sink.emit("endpoint.destroyed", arguments.actor, "destroyed",
                    ddsleuth::JsonObject()
                            .string("endpoint", "reader")
                            .string("topic", arguments.topic)
                            .integer("lifecycle_epoch", lifecycle_epoch));
        }
        else
        {
            throw std::runtime_error("unsupported scripted reader action: " + action.operation);
        }
        emit_action_event(sink, arguments, action, "action.completed", "completed");
    }
    return 0;
}

int run_writer(
        const Arguments& arguments,
        DomainParticipant* participant,
        Topic* topic,
        DynamicType::_ref_type dynamic_type,
        ddsleuth::EventSink& sink)
{
    Publisher* publisher = participant->create_publisher(PUBLISHER_QOS_DEFAULT);
    if (publisher == nullptr)
    {
        throw std::runtime_error("cannot create publisher");
    }
    WriterListener listener;
    // Declared after the listener so endpoint deletion and callback shutdown
    // happen before the listener's storage is released.
    PublisherOwner publisher_owner(participant, publisher);
    DataWriterQos writer_qos = DATAWRITER_QOS_DEFAULT;
    publisher->get_default_datawriter_qos(writer_qos);
    writer_qos.reliability().kind = RELIABLE_RELIABILITY_QOS;
    if (arguments.max_blocks_per_session > 0)
    {
        writer_qos.properties().properties().emplace_back(
            "dds.sec.crypto.maxblockspersession",
            std::to_string(arguments.max_blocks_per_session));
    }
    DataWriter* writer = publisher->create_datawriter(
        topic,
        writer_qos,
        &listener,
        StatusMask::all());
    DataWriterOwner writer_owner(publisher, writer);
    const bool allowed = writer != nullptr;
    emit_access_decision(sink, arguments, "create_datawriter", allowed);
    if ((allowed ? "allow" : "deny") != arguments.expected)
    {
        return 4;
    }
    if (!allowed && arguments.mode == "observe-denied-writer")
    {
        sink.emit("probe.ready", arguments.actor, "ready",
                ddsleuth::JsonObject().string("endpoint", "denied-writer").string("topic", arguments.topic));
        std::this_thread::sleep_for(arguments.timeout);
        return 0;
    }
    if (!allowed || arguments.mode == "check-writer")
    {
        return 0;
    }

    sink.emit("endpoint.created", arguments.actor, "created",
            ddsleuth::JsonObject()
                    .string("endpoint", "writer")
                    .string("topic", arguments.topic)
                    .integer("lifecycle_epoch", 1));

    sink.emit("probe.ready", arguments.actor, "ready",
            ddsleuth::JsonObject().string("endpoint", "writer").string("topic", arguments.topic));
    if (!listener.wait(arguments.timeout, arguments.expected_matches))
    {
        throw std::runtime_error("writer did not reach the expected reader match count before timeout");
    }
    sink.emit("endpoint.matched", arguments.actor, "matched",
            ddsleuth::JsonObject()
                    .string("endpoint", "writer")
                    .string("topic", arguments.topic)
                    .integer("matched_count", listener.matched_count())
                    .integer("expected_matches", arguments.expected_matches)
                    .integer("lifecycle_epoch", 1));

    if (arguments.mode != "recreate-writer")
    {
        for (uint32_t sample_index = 1; sample_index <= arguments.sample_count; ++sample_index)
        {
            const std::string message = arguments.sample_count == 1 ?
                    arguments.message :
                    arguments.message + " [sample " + std::to_string(sample_index) + "]";
            write_sample(
                writer,
                dynamic_type,
                sink,
                arguments,
                sample_index,
                message,
                1);
        }
        hold_after_write(sink, arguments, 1);
        return 0;
    }

    write_sample(writer, dynamic_type, sink, arguments, 1, arguments.message, 1);

    writer_owner.close();
    sink.emit("endpoint.destroyed", arguments.actor, "destroyed",
            ddsleuth::JsonObject()
                    .string("endpoint", "writer")
                    .string("topic", arguments.topic)
                    .integer("lifecycle_epoch", 1));

    WriterListener recreated_listener;
    DataWriter* recreated_writer = publisher->create_datawriter(
        topic,
        writer_qos,
        &recreated_listener,
        StatusMask::all());
    DataWriterOwner recreated_writer_owner(publisher, recreated_writer);
    const bool recreated_allowed = recreated_writer != nullptr;
    emit_access_decision(sink, arguments, "create_datawriter", recreated_allowed);
    if (!recreated_allowed)
    {
        throw std::runtime_error("cannot recreate authorized writer");
    }
    sink.emit("endpoint.recreated", arguments.actor, "created",
            ddsleuth::JsonObject()
                    .string("endpoint", "writer")
                    .string("topic", arguments.topic)
                    .integer("lifecycle_epoch", 2));
    if (!recreated_listener.wait(arguments.timeout, arguments.expected_matches))
    {
        throw std::runtime_error("recreated writer did not reach the expected reader match count");
    }
    sink.emit("endpoint.matched", arguments.actor, "matched",
            ddsleuth::JsonObject()
                    .string("endpoint", "writer")
                    .string("topic", arguments.topic)
                    .integer("matched_count", recreated_listener.matched_count())
                    .integer("expected_matches", arguments.expected_matches)
                    .integer("lifecycle_epoch", 2));
    write_sample(
        recreated_writer,
        dynamic_type,
        sink,
        arguments,
        2,
        arguments.message + " [epoch 2]",
        2);
    hold_after_write(sink, arguments, 2);
    return 0;
}

int run_reader(
        const Arguments& arguments,
        DomainParticipant* participant,
        Topic* topic,
        DynamicType::_ref_type dynamic_type,
        ddsleuth::EventSink& sink)
{
    Subscriber* subscriber = participant->create_subscriber(SUBSCRIBER_QOS_DEFAULT);
    if (subscriber == nullptr)
    {
        throw std::runtime_error("cannot create subscriber");
    }
    ReaderListener listener(dynamic_type, sink, arguments.actor, arguments.topic);
    // See PublisherOwner above: callbacks must not outlive their listener.
    SubscriberOwner subscriber_owner(participant, subscriber);
    DataReaderQos reader_qos = DATAREADER_QOS_DEFAULT;
    subscriber->get_default_datareader_qos(reader_qos);
    reader_qos.reliability().kind = RELIABLE_RELIABILITY_QOS;
    DataReader* reader = subscriber->create_datareader(
        topic,
        reader_qos,
        &listener,
        StatusMask::all());
    const bool allowed = reader != nullptr;
    emit_access_decision(sink, arguments, "create_datareader", allowed);
    if ((allowed ? "allow" : "deny") != arguments.expected)
    {
        return 4;
    }
    if (!allowed && arguments.mode == "observe-denied-reader")
    {
        sink.emit("probe.ready", arguments.actor, "ready",
                ddsleuth::JsonObject().string("endpoint", "denied-reader").string("topic", arguments.topic));
        std::this_thread::sleep_for(arguments.timeout);
        return 0;
    }
    if (!allowed || arguments.mode == "check-reader")
    {
        return 0;
    }

    sink.emit("probe.ready", arguments.actor, "ready",
            ddsleuth::JsonObject().string("endpoint", "reader").string("topic", arguments.topic));
    if (!listener.wait(arguments.timeout, arguments.expected_samples))
    {
        throw std::runtime_error("reader did not receive a sample before timeout");
    }
    return 0;
}

int run(
        const Arguments& arguments)
{
    ddsleuth::EventSink sink("fastdds", stdout);
    DomainParticipant* participant = DomainParticipantFactory::get_instance()->create_participant(
        arguments.domain,
        security_qos(arguments));
    if (participant == nullptr)
    {
        throw std::runtime_error("cannot create secure DomainParticipant");
    }
    ParticipantOwner owner(participant);
    DynamicType::_ref_type dynamic_type = create_type();
    if (!dynamic_type)
    {
        throw std::runtime_error("cannot build dynamic type");
    }
    TypeSupport type(new DynamicPubSubType(dynamic_type));
    if (type.register_type(participant) != RETCODE_OK)
    {
        throw std::runtime_error("cannot register dynamic type");
    }
    Topic* topic = participant->create_topic(
        arguments.topic,
        type.get_type_name(),
        TOPIC_QOS_DEFAULT);
    if (topic == nullptr)
    {
        throw std::runtime_error("cannot create topic");
    }
    sink.emit("probe.ready", arguments.actor, "ready",
            ddsleuth::JsonObject().string("endpoint", "participant"));

    if (arguments.mode == "scripted-writer")
    {
        return run_scripted_writer(arguments, participant, topic, dynamic_type, sink);
    }
    if (arguments.mode == "scripted-reader")
    {
        return run_scripted_reader(arguments, participant, topic, dynamic_type, sink);
    }
    if (arguments.mode == "writer" || arguments.mode == "recreate-writer" ||
            arguments.mode == "check-writer" ||
            arguments.mode == "observe-denied-writer")
    {
        return run_writer(arguments, participant, topic, dynamic_type, sink);
    }
    return run_reader(arguments, participant, topic, dynamic_type, sink);
}

} // namespace

int main(
        int argc,
        char** argv)
{
    try
    {
        return run(parse_arguments(argc, argv));
    }
    catch (const std::exception& error)
    {
        std::cerr << "ddsleuth_fastdds_probe: " << error.what() << '\n';
        return 3;
    }
}
