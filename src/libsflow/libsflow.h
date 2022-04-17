#pragma once

#include <array>
#include <climits>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <sstream>
#include <string>
#include <tuple>
#include <vector>

#include <arpa/inet.h>

// We need it for sanity checks 
const uint32_t max_udp_packet_size = 65535; 

enum class sflow_sample_type_t : unsigned int {
    FLOW_SAMPLE             = 1,
    COUNTER_SAMPLE          = 2,
    EXPANDED_FLOW_SAMPLE    = 3,
    EXPANDED_COUNTER_SAMPLE = 4,
    BROKEN_TYPE             = UINT_MAX,
};

// Old fashioned not typed enums for fast comparisions and assignments to
// integers
enum sflow_sample_type_not_typed_t {
    SFLOW_SAMPLE_TYPE_FLOW_SAMPLE             = 1,
    SFLOW_SAMPLE_TYPE_COUNTER_SAMPLE          = 2,
    SFLOW_SAMPLE_TYPE_EXPANDED_FLOW_SAMPLE    = 3,
    SFLOW_SAMPLE_TYPE_EXPANDED_COUNTER_SAMPLE = 4,
};

enum sflow_record_types_not_typed_t {
    SFLOW_RECORD_TYPE_RAW_PACKET_HEADER     = 1,
    SFLOW_RECORD_TYPE_EXTENDED_SWITCH_DATA  = 1001,
    SFLOW_RECORD_TYPE_EXTENDED_ROUTER_DATA  = 1002,
    SFLOW_RECORD_TYPE_EXTENDED_GATEWAY_DATA = 1003
};

enum class sample_counter_types_t : unsigned int {
    GENERIC_INTERFACE_COUNTERS  = 1,
    ETHERNET_INTERFACE_COUNTERS = 2,
    BROKEN_COUNTER              = UINT_MAX
};

// enterprise, format, length, pointer
typedef std::tuple<uint32_t, uint32_t, ssize_t, uint8_t*> counter_record_sample_t;
typedef std::vector<counter_record_sample_t> counter_record_sample_vector_t;

std::string print_counter_record_sample_vector(counter_record_sample_vector_t counter_record_sample_vector);

// Element type, pointer, length
typedef std::tuple<int32_t, uint8_t*, int32_t> record_tuple_t;
typedef std::vector<record_tuple_t> vector_tuple_t;

std::string print_vector_tuple(vector_tuple_t vector_tuple);

// Enterprise, integer_format, data_block_start, sample_length
typedef std::tuple<int32_t, int32_t, uint8_t*, size_t> sample_tuple_t;
typedef std::vector<sample_tuple_t> vector_sample_tuple_t;

std::string print_vector_sample_tuple(vector_sample_tuple_t vector_sample_tuple);

// Create scoped enum from integer with sanity check
sflow_sample_type_t sflow_sample_type_from_integer(int32_t format_as_integer);

std::tuple<uint32_t, uint32_t> split_32bit_integer_by_8_and_24_bits(uint32_t original_data);
std::tuple<int32_t, int32_t> split_mixed_enterprise_and_format(int32_t enterprise_and_format);
std::string build_ipv4_address_from_array(std::array<uint8_t, 4> ipv4_array_address);
std::string build_ipv6_address_from_array(std::array<uint8_t, 16> ipv6_array_address);
unsigned int get_flow_enum_type_as_number(const sflow_sample_type_t& value);

// Type safe versions of ntohl, ntohs with type control
// network (big endian) byte order to host byte order
uint16_t strict_ntoh(uint16_t value);
uint32_t strict_ntoh(uint32_t value);
int32_t strict_ntoh(int32_t value);
uint64_t strict_ntoh(uint64_t value);

// Type safe version of functions fot converting from host byte order to network
// byte order
uint16_t strict_hton(uint16_t value);
uint32_t strict_hton(uint32_t value);
int32_t strict_hton(int32_t value);

bool get_all_samples(vector_sample_tuple_t& vector_sample,
                     uint8_t* samples_block_start,
                     uint8_t* total_packet_end,
                     int32_t samples_count,
                     bool& discovered_padding);
bool get_records(vector_tuple_t& vector_tuple,
                 uint8_t* flow_record_zone_start,
                 uint32_t number_of_flow_records,
                 uint8_t* current_packet_end,
                 bool& padding_found);
bool get_all_counter_records(counter_record_sample_vector_t& counter_record_sample_vector,
                             uint8_t* data_block_start,
                             uint8_t* data_block_end,
                             uint32_t number_of_records);

int32_t get_int_value_by_32bit_shift(uint8_t* payload_ptr, unsigned int shift);

// pretty popular encoding way in sflow
std::tuple<uint32_t, uint32_t> split_32bit_integer_by_2_and_30_bits(uint32_t original_data);

class __attribute__((__packed__)) sflow_sample_header_as_struct_t {
    public:
    union {
        uint32_t enterprise : 20, sample_type : 12;
        uint32_t enterprise_and_sample_type_as_integer;
    };
    uint32_t sample_length = 0;

    void host_byte_order_to_network_byte_order() {
        enterprise_and_sample_type_as_integer = htonl(enterprise_and_sample_type_as_integer);
        sample_length                         = htonl(sample_length);
    }
};

class __attribute__((__packed__)) sflow_record_header_t {
    public:
    uint32_t record_type   = 0;
    uint32_t record_length = 0;

    void host_byte_order_to_network_byte_order() {
        record_type   = htonl(record_type);
        record_length = htonl(record_length);
    }
};

static_assert(sizeof(sflow_sample_header_as_struct_t) == 8, "Bad size for sflow_sample_header_as_struct_t");
static_assert(sizeof(sflow_record_header_t) == 8, "Bad size for sflow_record_header_t");

// Structure which describes sampled raw ethernet packet from switch
class __attribute__((__packed__)) sflow_raw_protocol_header_t {
    public:
    uint32_t header_protocol{ 0 };
    uint32_t frame_length_before_sampling{ 0 };
    uint32_t number_of_bytes_removed_from_packet{ 0 };
    uint32_t header_size{ 0 };

    // Convert byte order from network to host byte order
    void network_to_host_byte_order() {
        header_protocol                     = strict_ntoh(header_protocol);
        frame_length_before_sampling        = strict_ntoh(frame_length_before_sampling);
        number_of_bytes_removed_from_packet = strict_ntoh(number_of_bytes_removed_from_packet);
        header_size                         = strict_ntoh(header_size);
    }

    // Convert byte order from host to network
    void host_byte_order_to_network_byte_order() {
        header_protocol                     = strict_hton(header_protocol);
        frame_length_before_sampling        = strict_hton(frame_length_before_sampling);
        number_of_bytes_removed_from_packet = strict_hton(number_of_bytes_removed_from_packet);
        header_size                         = strict_hton(header_size);
    }

    std::string print() {
        std::stringstream buffer;

        buffer << "header_protocol: " << header_protocol << " "
               << "frame_length_before_sampling: " << frame_length_before_sampling << " "
               << "number_of_bytes_removed_from_packet: " << number_of_bytes_removed_from_packet << " "
               << "header_size: " << header_size << std::endl;

        return buffer.str();
    }
};

class __attribute__((__packed__)) sflow_sample_header_t {
    public:
    uint32_t sample_sequence_number; // sample sequence number
    union __attribute__((__packed__)) {
        uint32_t source_id_with_id_type{ 0 }; // source id type + source id
        uint32_t source_id : 24, source_id_type : 8;
    };
    uint32_t sampling_rate{ 0 }; // sampling ratio
    uint32_t sample_pool{ 0 }; // number of sampled packets
    uint32_t drops_count{ 0 }; // number of drops due to hardware overload
    uint32_t input_port{ 0 }; // input  port + 2 bits port type
    uint32_t output_port{ 0 }; // output port + 2 bits port type
    uint32_t number_of_flow_records{ 0 };

    // Convert all fields to host byte order (little endian)
    void network_to_host_byte_order() {
        sample_sequence_number = strict_ntoh(sample_sequence_number);
        sampling_rate          = strict_ntoh(sampling_rate);
        sample_pool            = strict_ntoh(sample_pool);
        drops_count            = strict_ntoh(drops_count);
        number_of_flow_records = strict_ntoh(number_of_flow_records);

        input_port             = strict_ntoh(input_port);
        output_port            = strict_ntoh(output_port);
        source_id_with_id_type = strict_ntoh(source_id_with_id_type);
    }

    // Convert all fields ti network byte order (big endian)
    void host_byte_order_to_network_byte_order() {
        sample_sequence_number = strict_hton(sample_sequence_number);
        sampling_rate          = strict_hton(sampling_rate);
        sample_pool            = strict_hton(sample_pool);
        drops_count            = strict_hton(drops_count);
        number_of_flow_records = strict_hton(number_of_flow_records);

        input_port             = strict_hton(input_port);
        output_port            = strict_hton(output_port);
        source_id_with_id_type = strict_hton(source_id_with_id_type);
    }

    std::string print() {
        std::stringstream buffer;

        buffer << "sample_sequence_number: " << sample_sequence_number << " "
               << "sampling_rate: " << sampling_rate << " "
               << "sample_pool: " << sample_pool << " "
               << "drops_count: " << drops_count << " "
               << "number_of_flow_records: " << number_of_flow_records;

        return buffer.str();
    }
};

// This header format is really close to "sflow_sample_header_t" but we do not
// encode formats in
// value
class __attribute__((__packed__)) sflow_sample_expanded_header_t {
    public:
    uint32_t sample_sequence_number; // sample sequence number
    uint32_t source_id_type; // source id type
    uint32_t source_id_index; // source id index
    uint32_t sampling_rate; // sampling ratio
    uint32_t sample_pool; // number of sampled packets
    uint32_t drops_count; // number of drops due to hardware overload
    uint32_t input_port_type; // input port type
    uint32_t input_port_index; // input port index
    uint32_t output_port_type; // output port type
    uint32_t output_port_index; // outpurt port index
    uint32_t number_of_flow_records;

    void network_to_host_byte_order() {
        sample_sequence_number = strict_ntoh(sample_sequence_number);
        source_id_type         = strict_ntoh(source_id_type);
        source_id_index        = strict_ntoh(source_id_index);
        sampling_rate          = strict_ntoh(sampling_rate);
        sample_pool            = strict_ntoh(sample_pool);
        drops_count            = strict_ntoh(drops_count);
        input_port_type        = strict_ntoh(input_port_type);
        input_port_index       = strict_ntoh(input_port_index);
        output_port_type       = strict_ntoh(output_port_type);
        output_port_index      = strict_ntoh(output_port_index);
        number_of_flow_records = strict_ntoh(number_of_flow_records);
    }

    std::string print() {
        std::stringstream buffer;

        std::string delimiter = ",";

        buffer << "sample_sequence_number: " << sample_sequence_number << delimiter << "source_id_type: " << source_id_type
               << delimiter << "source_id_index: " << source_id_index << delimiter << "sampling_rate: " << sampling_rate
               << delimiter << "sample_pool: " << sample_pool << delimiter << "drops_count: " << drops_count << delimiter
               << "input_port_type: " << input_port_type << delimiter << "input_port_index: " << input_port_index << delimiter
               << "output_port_type: " << output_port_type << delimiter << "output_port_index: " << output_port_index
               << delimiter << "number_of_flow_records: " << number_of_flow_records;

        return buffer.str();
    }
};

// Unified accessor for sflow_sample_header_t sflow_sample_expanded_header_t
// classes.
class sflow_sample_header_unified_accessor_t {
    public:
    uint32_t sample_sequence_number; // sample sequence number
    uint32_t source_id_type; // source id type
    uint32_t source_id_index; // source id index
    uint32_t sampling_rate; // sampling ratio
    uint32_t sample_pool; // number of sampled packets
    uint32_t drops_count; // number of drops due to hardware overload
    uint32_t input_port_type; // input port type
    uint32_t input_port_index; // input port index
    uint32_t output_port_type; // output port type
    uint32_t output_port_index; // outpurt port index
    uint32_t number_of_flow_records;
    ssize_t original_payload_length;

    uint32_t get_sample_sequence_number() {
        return sample_sequence_number;
    }
    uint32_t get_source_id_type() {
        return source_id_type;
    }
    uint32_t get_source_id_index() {
        return source_id_index;
    }
    uint32_t get_sampling_rate() {
        return sampling_rate;
    }
    uint32_t get_sample_pool() {
        return sample_pool;
    }
    uint32_t get_drops_count() {
        return drops_count;
    }
    uint32_t get_input_port_type() {
        return input_port_type;
    }
    uint32_t get_input_port_index() {
        return input_port_index;
    }
    uint32_t get_output_port_type() {
        return output_port_type;
    }
    uint32_t get_output_port_index() {
        return output_port_index;
    }
    uint32_t get_number_of_flow_records() {
        return number_of_flow_records;
    }
    ssize_t get_original_payload_length() {
        return original_payload_length;
    }

    sflow_sample_header_unified_accessor_t() {
    }

    sflow_sample_header_unified_accessor_t(sflow_sample_header_t sflow_sample_header) {
        sample_sequence_number = sflow_sample_header.sample_sequence_number;
        sampling_rate          = sflow_sample_header.sampling_rate;
        sample_pool            = sflow_sample_header.sample_pool;
        drops_count            = sflow_sample_header.drops_count;

        number_of_flow_records = sflow_sample_header.number_of_flow_records;

        std::tie(input_port_type, input_port_index) = split_32bit_integer_by_2_and_30_bits(sflow_sample_header.input_port);
        std::tie(output_port_type, output_port_index) = split_32bit_integer_by_2_and_30_bits(sflow_sample_header.output_port);

        std::tie(source_id_type, source_id_index) = split_32bit_integer_by_8_and_24_bits(sflow_sample_header.source_id_with_id_type);

        original_payload_length = sizeof(sflow_sample_header_t);
    }

    sflow_sample_header_unified_accessor_t(sflow_sample_expanded_header_t sflow_sample_expanded_header) {
        sample_sequence_number = sflow_sample_expanded_header.sample_sequence_number;
        source_id_type         = sflow_sample_expanded_header.source_id_type;
        source_id_index        = sflow_sample_expanded_header.source_id_index;
        sampling_rate          = sflow_sample_expanded_header.sampling_rate;
        sample_pool            = sflow_sample_expanded_header.sample_pool;
        drops_count            = sflow_sample_expanded_header.drops_count;
        input_port_type        = sflow_sample_expanded_header.input_port_type;
        input_port_index       = sflow_sample_expanded_header.input_port_index;
        output_port_type       = sflow_sample_expanded_header.output_port_type;
        output_port_index      = sflow_sample_expanded_header.output_port_index;
        number_of_flow_records = sflow_sample_expanded_header.number_of_flow_records;

        original_payload_length = sizeof(sflow_sample_expanded_header_t);
    }

    std::string print() {
        std::stringstream buffer;

        buffer << "sample_sequence_number: " << sample_sequence_number << " "
               << "source_id_type: " << source_id_type << " "
               << "source_id_index: " << source_id_index << " "
               << "sampling_rate: " << sampling_rate << " "
               << "sample_pool: " << sample_pool << " "
               << "drops_count: " << drops_count << " "
               << "input_port_type: " << input_port_type << " "
               << "input_port_index: " << input_port_index << " "
               << "output_port_type: " << output_port_type << " "
               << "output_port_index: " << output_port_index << " "
               << "number_of_flow_records: " << number_of_flow_records;

        return buffer.str();
    }
};

// IP protocol version use by sflow agent
enum sflow_agent_ip_protocol_version_not_typed : int32_t {
    SFLOW_AGENT_PROTOCOL_VERSION_IPv4 = 1,
    SFLOW_AGENT_PROTOCOL_VERSION_IPV6 = 2,
};

enum sflow_address_type { SFLOW_ADDRESS_TYPE_UNDEFINED = 0, SFLOW_ADDRESS_TYPE_IPv4 = 1, SFLOW_ADDRESS_TYPE_IPV6 = 2 };

// with __attribute__((__packed__)) we have disabled any paddings inside this
// struct
template <std::size_t address_length> class __attribute__((__packed__)) sflow_packet_header {
    public:
    sflow_packet_header() {
        static_assert(address_length == 4 or address_length == 16, "You have specified wrong value for template");
    }
    // 2, 4, 5
    int32_t sflow_version{ 5 };
    // IPv4: 1 (SFLOW_AGENT_PROTOCOL_VERSION_IPv4), IPv6: 2
    // (SFLOW_AGENT_PROTOCOL_VERSION_IPV6)
    int32_t agent_ip_version{ 1 };
    std::array<uint8_t, address_length> address_v4_or_v6{};
    uint32_t sub_agent_id{ 1 };
    uint32_t datagram_sequence_number{ 0 };
    // Device uptime in milliseconds
    uint32_t device_uptime{ 0 };
    uint32_t datagram_samples_count{ 0 };

    // Convert all structure fields to host byte order
    void network_to_host_byte_order() {
        sflow_version            = strict_ntoh(sflow_version);
        agent_ip_version         = strict_ntoh(agent_ip_version);
        sub_agent_id             = strict_ntoh(sub_agent_id);
        datagram_sequence_number = strict_ntoh(datagram_sequence_number);
        device_uptime            = strict_ntoh(device_uptime);
        datagram_samples_count   = strict_ntoh(datagram_samples_count);
    }

    // Convert all structure fields to network byte order
    void host_byte_order_to_network_byte_order() {
        sflow_version            = strict_hton(sflow_version);
        agent_ip_version         = strict_hton(agent_ip_version);
        sub_agent_id             = strict_hton(sub_agent_id);
        datagram_sequence_number = strict_hton(datagram_sequence_number);
        device_uptime            = strict_hton(device_uptime);
        datagram_samples_count   = strict_hton(datagram_samples_count);
    }

    std::string print() {
        std::stringstream buffer;

        buffer << "sflow_version: " << sflow_version << std::endl
               << "agent_ip_version: " << agent_ip_version << std::endl
               << "sub_agent_id: " << sub_agent_id << std::endl;

        if (address_length == 4) {
            buffer << "agent_ip_address: " << build_ipv4_address_from_array(address_v4_or_v6) << std::endl;
        } else {
            buffer << "agent_ip_address: " << build_ipv6_address_from_array(address_v4_or_v6) << std::endl;
        }

        buffer << "datagram_sequence_number: " << datagram_sequence_number << std::endl
               << "device_uptime: " << device_uptime << std::endl
               << "datagram_samples_count: " << datagram_samples_count << std::endl;

        return buffer.str();
    }
};

using sflow_packet_header_v4_t = sflow_packet_header<4>;
using sflow_packet_header_v6_t = sflow_packet_header<16>;

class sflow_packet_header_unified_accessor {
    private:
    int32_t sflow_version            = 0;
    int32_t agent_ip_version         = 0;
    std::string agent_ip_address     = "";
    int32_t sub_agent_id             = 0;
    int32_t datagram_sequence_number = 0;
    int32_t device_uptime            = 0;
    int32_t datagram_samples_count   = 0;
    ssize_t original_payload_length  = 0;

    public:
    int32_t get_sflow_version() const {
        return sflow_version;
    }
    int32_t get_agent_ip_version() const {
        return agent_ip_version;
    }
    std::string get_agent_ip_address() const {
        return agent_ip_address;
    }
    int32_t get_sub_agent_id() const {
        return sub_agent_id;
    }
    int32_t get_datagram_sequence_number() const {
        return datagram_sequence_number;
    };
    int32_t get_device_uptime() const {
        return device_uptime;
    }
    int32_t get_datagram_samples_count() const {
        return datagram_samples_count;
    };

    ssize_t get_original_payload_length() const {
        return original_payload_length;
    }

    std::string print() {
        std::stringstream buffer;

        buffer << "sflow_version: " << sflow_version << " "
               << "agent_ip_version: " << agent_ip_version << " "
               << "agent_ip_address: " << agent_ip_address << " "
               << "sub_agent_id: " << sub_agent_id << " "
               << "datagram_sequence_number: " << datagram_sequence_number << " "
               << "device_uptime: " << device_uptime << " "
               << "datagram_samples_count: " << datagram_samples_count << " "
               << "original_payload_length: " << original_payload_length;

        return buffer.str();
    }

    sflow_packet_header_unified_accessor() {
    }
    sflow_packet_header_unified_accessor(sflow_packet_header_v4_t sflow_packet_header_v4) {
        sflow_version            = sflow_packet_header_v4.sflow_version;
        agent_ip_version         = sflow_packet_header_v4.agent_ip_version;
        sub_agent_id             = sflow_packet_header_v4.sub_agent_id;
        datagram_sequence_number = sflow_packet_header_v4.datagram_sequence_number;
        device_uptime            = sflow_packet_header_v4.device_uptime;
        datagram_samples_count   = sflow_packet_header_v4.datagram_samples_count;
        agent_ip_address         = build_ipv4_address_from_array(sflow_packet_header_v4.address_v4_or_v6);

        original_payload_length = sizeof(sflow_packet_header_v4);
    }

    sflow_packet_header_unified_accessor(sflow_packet_header_v6_t sflow_packet_header_v6) {
        sflow_version            = sflow_packet_header_v6.sflow_version;
        agent_ip_version         = sflow_packet_header_v6.agent_ip_version;
        sub_agent_id             = sflow_packet_header_v6.sub_agent_id;
        datagram_sequence_number = sflow_packet_header_v6.datagram_sequence_number;
        device_uptime            = sflow_packet_header_v6.device_uptime;
        datagram_samples_count   = sflow_packet_header_v6.datagram_samples_count;
        agent_ip_address         = build_ipv6_address_from_array(sflow_packet_header_v6.address_v4_or_v6);

        original_payload_length = sizeof(sflow_packet_header_v6);
    }
};

// This structure keeps information about gateway details, we use it to parse only few first fields
class __attribute__((__packed__)) sflow_extended_gateway_information_t {
    public:
    // Must be IPv4 only, for IPv6 we need another structure
    uint32_t next_hop_address_type = 0;
    uint32_t next_hop              = 0;
    uint32_t router_asn            = 0;
    uint32_t source_asn            = 0;
    uint32_t peer_asn              = 0;
};

class __attribute__((__packed__)) sflow_counter_header_t {
    public:
    uint32_t sample_sequence_number;
    uint32_t source_type_with_id;
    uint32_t number_of_counter_records;

    void network_to_host_byte_order() {
        sample_sequence_number    = strict_ntoh(sample_sequence_number);
        source_type_with_id       = strict_ntoh(source_type_with_id);
        number_of_counter_records = strict_ntoh(number_of_counter_records);
    }

    std::string print() {
        std::stringstream buffer;

        buffer << "sample_sequence_number: " << sample_sequence_number << " "
               << "source_type_with_id: " << source_type_with_id << " "
               << "number_of_counter_records: " << number_of_counter_records << std::endl;

        return buffer.str();
    }
};

// Expanded form of sflow_counter_header_t
class __attribute__((__packed__)) sflow_counter_expanded_header_t {
    public:
    uint32_t sample_sequence_number;
    uint32_t source_id_type;
    uint32_t source_id_index;
    uint32_t number_of_counter_records;

    void network_to_host_byte_order() {
        sample_sequence_number    = strict_ntoh(sample_sequence_number);
        source_id_type            = strict_ntoh(source_id_type);
        source_id_index           = strict_ntoh(source_id_index);
        number_of_counter_records = strict_ntoh(number_of_counter_records);
    }

    std::string print() {
        std::stringstream buffer;

        buffer << "sample_sequence_number: " << sample_sequence_number << " "
               << "source_id_type: " << source_id_type << " "
               << "source_id_index: " << source_id_index << " "
               << "number_of_counter_records: " << number_of_counter_records << std::endl;

        return buffer.str();
    }
};

// Unified accessor for sflow_counter_header_t and
// sflow_counter_expanded_header_t
class sflow_counter_header_unified_accessor_t {
    private:
    uint32_t sample_sequence_number    = 0;
    uint32_t source_id_type            = 0;
    uint32_t source_id_index           = 0;
    uint32_t number_of_counter_records = 0;
    ssize_t original_payload_length    = 0;
    bool expanded                      = false;

    public:
    uint32_t get_sample_sequence_number() {
        return sample_sequence_number;
    }
    uint32_t get_source_id_type() {
        return source_id_type;
    }
    uint32_t get_source_id_index() {
        return source_id_index;
    }
    uint32_t get_number_of_counter_records() {
        return number_of_counter_records;
    }
    ssize_t get_original_payload_length() {
        return original_payload_length;
    }
    bool get_expaned() {
        return expanded;
    }

    sflow_counter_header_unified_accessor_t() {
        // default constructor
    }

    sflow_counter_header_unified_accessor_t(sflow_counter_header_t sflow_counter_header) {
        sample_sequence_number = sflow_counter_header.sample_sequence_number;

        // Get first two bytes
        std::tie(source_id_type, source_id_index) = split_32bit_integer_by_2_and_30_bits(sflow_counter_header.source_type_with_id);

        number_of_counter_records = sflow_counter_header.number_of_counter_records;
        original_payload_length   = sizeof(sflow_counter_header_t);
        expanded                  = false;
    }

    sflow_counter_header_unified_accessor_t(sflow_counter_expanded_header_t sflow_counter_expanded_header) {
        sample_sequence_number    = sflow_counter_expanded_header.sample_sequence_number;
        source_id_type            = sflow_counter_expanded_header.source_id_type;
        source_id_index           = sflow_counter_expanded_header.source_id_index;
        number_of_counter_records = sflow_counter_expanded_header.number_of_counter_records;

        original_payload_length = sizeof(sflow_counter_expanded_header_t);
        expanded                = true;
    }

    std::string print() {
        std::stringstream buffer;

        buffer << "sample_sequence_number: " << sample_sequence_number << " "
               << "source_id_type: " << source_id_type << " "
               << "source_id_index: " << source_id_index << " "
               << "number_of_counter_records: " << number_of_counter_records << " "
               << "original_payload_length: " << original_payload_length << " "
               << "expanded: " << expanded;

        return buffer.str();
    }
};

class __attribute__((__packed__)) ethernet_sflow_interface_counters_t {
    public:
    uint32_t alignment_errors;
    uint32_t fcs_errors;
    uint32_t single_collision_frames;
    uint32_t multiple_collision_frames;
    uint32_t sqe_test_errors;
    uint32_t deferred_transmissions;
    uint32_t late_collisions;
    uint32_t excessive_collisions;
    uint32_t internal_mac_transmit_errors;
    uint32_t carrier_sense_errors;
    uint32_t frame_too_longs;
    uint32_t internal_mac_receive_errors;
    uint32_t symbol_errors;

    ethernet_sflow_interface_counters_t(uint8_t* data_pointer) {
        memcpy(this, data_pointer, sizeof(ethernet_sflow_interface_counters_t));
        this->network_to_host_byte_order();
    }

    void network_to_host_byte_order() {
        alignment_errors             = strict_ntoh(alignment_errors);
        fcs_errors                   = strict_ntoh(alignment_errors);
        single_collision_frames      = strict_ntoh(single_collision_frames);
        multiple_collision_frames    = strict_ntoh(multiple_collision_frames);
        sqe_test_errors              = strict_ntoh(sqe_test_errors);
        deferred_transmissions       = strict_ntoh(deferred_transmissions);
        late_collisions              = strict_ntoh(late_collisions);
        excessive_collisions         = strict_ntoh(excessive_collisions);
        internal_mac_transmit_errors = strict_ntoh(internal_mac_transmit_errors);
        carrier_sense_errors         = strict_ntoh(carrier_sense_errors);
        frame_too_longs              = strict_ntoh(frame_too_longs);
        internal_mac_receive_errors  = strict_ntoh(internal_mac_receive_errors);
        symbol_errors                = strict_ntoh(symbol_errors);
    }

    std::string print() {
        std::stringstream buffer;

        std::string delimiter = ",";

        buffer << "alignment_errors: " << alignment_errors << delimiter << "fcs_errors: " << fcs_errors << delimiter
               << "single_collision_frames: " << single_collision_frames << delimiter
               << "multiple_collision_frames: " << multiple_collision_frames << delimiter << "sqe_test_errors: " << sqe_test_errors
               << delimiter << "deferred_transmissions: " << deferred_transmissions << delimiter
               << "late_collisions: " << late_collisions << delimiter << "excessive_collisions: " << excessive_collisions
               << delimiter << "internal_mac_transmit_errors: " << internal_mac_transmit_errors << delimiter
               << "carrier_sense_errors: " << carrier_sense_errors << delimiter << "frame_too_longs: " << frame_too_longs
               << delimiter << "internal_mac_receive_errors: " << internal_mac_receive_errors << delimiter
               << "symbol_errors: " << symbol_errors;

        return buffer.str();
    }
};

// http://www.sflow.org/SFLOW-STRUCTS5.txt
class __attribute__((__packed__)) generic_sflow_interface_counters_t {
    public:
    uint32_t if_index;
    uint32_t if_type;
    uint64_t if_speed;
    uint32_t if_direction; /* derived from MAU MIB (RFC 2668)
                            0 = unkown, 1=full-duplex, 2=half-duplex,
                            3 = in, 4=out */
    uint32_t if_status; /* bit field with the following bits assigned
                         bit 0 = ifAdminStatus (0 = down, 1 = up)
                         bit 1 = ifOperStatus (0 = down, 1 = up) */
    uint64_t if_in_octets;
    uint32_t if_in_ucast_pkts;
    uint32_t if_in_multicast_pkts;
    uint32_t if_in_broadcast_pkts;
    uint32_t if_in_discards;
    uint32_t if_in_errors;
    uint32_t if_in_unknown_protos;
    uint64_t if_out_octets;
    uint32_t if_out_ucast_pkts;
    uint32_t if_out_multicast_pkts;
    uint32_t if_out_broadcast_pkts;
    uint32_t if_out_discards;
    uint32_t if_out_errors;
    uint32_t if_promiscuous_mode;

    generic_sflow_interface_counters_t(uint8_t* data_pointer) {
        memcpy(this, data_pointer, sizeof(generic_sflow_interface_counters_t));
        this->network_to_host_byte_order();
    }

    void network_to_host_byte_order() {
        if_index              = strict_ntoh(if_index);
        if_type               = strict_ntoh(if_type);
        if_speed              = strict_ntoh(if_speed);
        if_direction          = strict_ntoh(if_direction);
        if_status             = strict_ntoh(if_status);
        if_in_octets          = strict_ntoh(if_in_octets);
        if_in_ucast_pkts      = strict_ntoh(if_in_ucast_pkts);
        if_in_multicast_pkts  = strict_ntoh(if_in_multicast_pkts);
        if_in_broadcast_pkts  = strict_ntoh(if_in_broadcast_pkts);
        if_in_discards        = strict_ntoh(if_in_discards);
        if_in_errors          = strict_ntoh(if_in_errors);
        if_in_unknown_protos  = strict_ntoh(if_in_unknown_protos);
        if_out_octets         = strict_ntoh(if_out_octets);
        if_out_ucast_pkts     = strict_ntoh(if_out_ucast_pkts);
        if_out_multicast_pkts = strict_ntoh(if_out_multicast_pkts);
        if_out_broadcast_pkts = strict_ntoh(if_out_broadcast_pkts);
        if_out_discards       = strict_ntoh(if_out_discards);
        if_out_errors         = strict_ntoh(if_out_errors);
        if_promiscuous_mode   = strict_ntoh(if_promiscuous_mode);
    }

    std::string print() {
        std::stringstream buffer;

        std::string delimiter = ",";

        buffer << "if_index: " << if_index << delimiter << "if_type: " << if_type << delimiter << "if_speed: " << if_speed
               << delimiter << "if_direction: " << if_direction << delimiter << "if_status: " << if_status << delimiter
               << "if_in_octets: " << if_in_octets << delimiter << "if_in_ucast_pkts: " << if_in_ucast_pkts << delimiter
               << "if_in_multicast_pkts: " << if_in_multicast_pkts << delimiter << "if_in_broadcast_pkts: " << if_in_broadcast_pkts
               << delimiter << "if_in_discards: " << if_in_discards << delimiter << "if_in_errors: " << if_in_errors
               << delimiter << "if_in_unknown_protos: " << if_in_unknown_protos << delimiter
               << "if_out_octets: " << if_out_octets << delimiter << "if_out_ucast_pkts: " << if_out_ucast_pkts << delimiter
               << "if_out_multicast_pkts: " << if_out_multicast_pkts << delimiter << "if_out_broadcast_pkts: " << if_out_broadcast_pkts
               << delimiter << "if_out_discards: " << if_out_discards << delimiter << "if_out_errors: " << if_out_errors
               << delimiter << "if_promiscuous_mode: " << if_promiscuous_mode;

        return buffer.str();
    }
};

// High level processing functions. They uses classes defined upper
bool read_sflow_header(uint8_t* payload_ptr, unsigned int payload_length, sflow_packet_header_unified_accessor& sflow_header_accessor);
bool read_sflow_counter_header(uint8_t* data_pointer,
                               size_t data_length,
                               bool expanded,
                               sflow_counter_header_unified_accessor_t& sflow_counter_header_unified_accessor);
bool read_sflow_sample_header_unified(sflow_sample_header_unified_accessor_t& sflow_sample_header_unified_accessor,
                                      uint8_t* data_pointer,
                                      size_t data_length,
                                      bool expanded);

static_assert(sizeof(sflow_raw_protocol_header_t) == 16, "Broken size for sflow_raw_protocol_header_t");
static_assert(sizeof(sflow_sample_expanded_header_t) == 44, "Broken size for sflow_sample_expanded_header_t");
static_assert(sizeof(sflow_counter_header_t) == 12, "Broken size for sflow_counter_header_t");
static_assert(sizeof(sflow_counter_expanded_header_t) == 16, "Broken size for sflow_counter_expanded_header_t");
static_assert(sizeof(ethernet_sflow_interface_counters_t) == 52, "Broken size for ethernet_sflow_interface_counters_t");
static_assert(sizeof(generic_sflow_interface_counters_t) == 88, "Broken size for generic_sflow_interface_counters_t");

static_assert(sizeof(sflow_sample_header_t) == 32, "Broken size for sflow_sample_header_t");
static_assert(sizeof(sflow_packet_header_v4_t) == 28, "Broken size for packed IPv4 structure");
static_assert(sizeof(sflow_packet_header_v6_t) == 40, "Broken size for packed IPv6 structure");
