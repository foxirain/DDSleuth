#include "ddsleuth_event.hpp"

int main()
{
    ddsleuth::EventSink sink("fastdds", stdout);
    ddsleuth::JsonObject attributes;
    attributes.string("resource", "SecretTopic\nquoted\"")
            .boolean("reader_created", false)
            .integer("domain_id", 222);
    sink.emit("access_control.decision", "mallory", "denied", attributes);
    return 0;
}
