#include "clickhousedb.hpp"

#include "../fastnetmon_types.h"
#include "../fast_library.h"
#include "../abstract_subnet_counters.hpp"

#include "../all_logcpp_libraries.h"

#include <vector>
#include <set>

extern bool print_average_traffic_counts;
extern struct timeval graphite_thread_execution_time;
extern total_counter_element_t total_speed_average_counters[4];
extern map_of_vector_counters_t SubnetVectorMapSpeed;
extern map_of_vector_counters_t SubnetVectorMapSpeedAverage;
extern map_of_vector_counters_for_flow_t SubnetVectorMapFlow;
extern uint64_t incoming_total_flows_speed;
extern uint64_t outgoing_total_flows_speed;
extern map_for_subnet_counters_t PerSubnetAverageSpeedMap;
extern uint64_t influxdb_writes_total;
extern uint64_t influxdb_writes_failed;
extern total_counter_element_t total_speed_average_counters_ipv6[4];
extern abstract_subnet_counters_t<subnet_ipv6_cidr_mask_t> ipv6_host_counters;
extern abstract_subnet_counters_t<subnet_cidr_mask_t> ipv4_host_counters;
extern abstract_subnet_counters_t<subnet_cidr_mask_t> ipv4_remote_host_counters;
extern std::vector<ban_settings_t> hostgroup_list_total_calculation;
extern std::mutex hostgroup_list_total_calculation_mutex;
extern abstract_subnet_counters_t<int64_t> per_hostgroup_total_counters;
extern log4cpp::Category& logger;
extern map_of_packets PacketMap;
extern std::string clickhousedb_database;
extern std::string clickhousedb_user;
extern std::string clickhousedb_password;
extern unsigned int clickhousedb_push_period;

extern boost::mutex packet_map_mutex;


// This thread pushes data to ClickHouse
void clickhouse_push_traffic_thread() {
    // Sleep for a half second for shift against calculation thread
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));

    bool do_dns_resolution = false;

    logger << log4cpp::Priority::INFO << "START CLICKHOUSE THREAD";

    while (true) {
        boost::this_thread::sleep(boost::posix_time::seconds(10));

        push_traffic_counters_to_clickhousedb(clickhousedb_database);

    }
}
// This thread pushes data to ClickHouse
void clickhouse_push_thread() {
    // Sleep for a half second for shift against calculation thread
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));

    bool do_dns_resolution = false;

    logger << log4cpp::Priority::INFO << "START CLICKHOUSE THREAD";

    while (true) {
        boost::this_thread::sleep(boost::posix_time::seconds(1));

	//logger << log4cpp::Priority::INFO << "Clickhouse push to DB: " << clickhousedb_database << "with period: " << clickhousedb_push_period ;


        push_total_metrics_counters_to_clickhousedb(clickhousedb_database, total_speed_average_counters, false);

	push_hosts_traffic_counters_to_clickhousedb(clickhousedb_database);

	push_network_traffic_counters_to_clickhousedb(clickhousedb_database);
	//logger << log4cpp::Priority::INFO << "Push OK";
    }
}

// Push total traffic counters to Clickhouse
bool push_total_metrics_counters_to_clickhousedb(std::string clickhousedb_database,
                                             total_counter_element_t total_speed_average_counters_param[4],
                                             bool ipv6) {

    auto metricDateTime = std::make_shared<clickhouse::ColumnDateTime>();
    auto direction = std::make_shared<clickhouse::ColumnString>();
    auto flows = std::make_shared<clickhouse::ColumnUInt64>();
    auto packets = std::make_shared<clickhouse::ColumnUInt64>();
    auto bits = std::make_shared<clickhouse::ColumnUInt64>();

    std::vector<direction_t> directions = { INCOMING, OUTGOING, INTERNAL, OTHER };

    uint64_t unix_timestamp_nanoseconds = get_current_unix_time_in_nanoseconds();

    for (auto packet_direction : directions) {
        std::map<std::string, uint64_t> plain_total_counters_map;

	std::string direction_as_string = get_direction_name(packet_direction);

        uint64_t speed_in_pps             = total_speed_average_counters_param[packet_direction].packets;
        uint64_t speed_in_bits_per_second = total_speed_average_counters_param[packet_direction].bytes * 8;

        // We do not have this counter for IPv6
        if (!ipv6) {
            // We have flow information only for incoming and outgoing directions
            if (packet_direction == INCOMING or packet_direction == OUTGOING) {
                uint64_t flow_counter_for_this_direction = 0;

                if (packet_direction == INCOMING) {
                    flow_counter_for_this_direction = incoming_total_flows_speed;
                } else {
                    flow_counter_for_this_direction = outgoing_total_flows_speed;
                }

                metricDateTime->Append(unix_timestamp_nanoseconds/1000000000);
                direction->Append(direction_as_string);
                flows->Append(flow_counter_for_this_direction);
                packets->Append(speed_in_pps);
                bits->Append(speed_in_bits_per_second);
            }
        }
    
    }

    clickhouse::Block block;

    block.AppendColumn("metricDateTime", metricDateTime);
    block.AppendColumn("direction", direction);
    block.AppendColumn("flows", flows);
    block.AppendColumn("packets", packets);
    block.AppendColumn("bits", bits);

    return write_data_to_clickhousedb(clickhousedb_database, "fastnetmon.total_metrics", block);

}


bool push_traffic_counters_to_clickhousedb(std::string clickhousedb_database) {

    vector_of_packets zero_vector_of_packets;


    map_of_packets* testmap = nullptr;

    testmap = &PacketMap;




    uint64_t unix_timestamp_nanoseconds = get_current_unix_time_in_nanoseconds();

    //auto metricDate = std::make_shared<clickhouse::ColumnDate>();
    auto packetDateTime = std::make_shared<clickhouse::ColumnDateTime>();
    auto source = std::make_shared<clickhouse::ColumnInt8>();
    auto sampleRatio = std::make_shared<clickhouse::ColumnUInt32>();
    auto srcIp = std::make_shared<clickhouse::ColumnUInt32>();
    auto dstIp = std::make_shared<clickhouse::ColumnUInt32>();
    auto srcIpv6 = std::make_shared<clickhouse::ColumnFixedString>(16);
    auto dstIpv6 = std::make_shared<clickhouse::ColumnFixedString>(16);
    auto srcAsn = std::make_shared<clickhouse::ColumnUInt32>();
    auto dstAsn = std::make_shared<clickhouse::ColumnUInt32>();
    auto inputInterface = std::make_shared<clickhouse::ColumnUInt32>();
    auto outputInterface = std::make_shared<clickhouse::ColumnUInt32>();
    auto ipProtocolVersion = std::make_shared<clickhouse::ColumnUInt8>();
    auto ttl = std::make_shared<clickhouse::ColumnUInt8>();
    auto sourcePort = std::make_shared<clickhouse::ColumnUInt16>();
    auto destinationPort = std::make_shared<clickhouse::ColumnUInt16>();
    auto protocol = std::make_shared<clickhouse::ColumnUInt32>();
    auto length = std::make_shared<clickhouse::ColumnUInt64>();
    auto numberOfPackets = std::make_shared<clickhouse::ColumnUInt64>();
    auto flags = std::make_shared<clickhouse::ColumnUInt8>();
    auto ipFragmented = std::make_shared<clickhouse::ColumnInt8>();
    auto ipDontFragment = std::make_shared<clickhouse::ColumnInt8>();
    auto packetPayloadLength = std::make_shared<clickhouse::ColumnInt32>();
    auto packetPayloadFullLength = std::make_shared<clickhouse::ColumnInt32>();
    auto packetDirection = std::make_shared<clickhouse::ColumnInt8>();
    auto agentIpAddress = std::make_shared<clickhouse::ColumnUInt32>();    
    //vector_of_packets pkts;
    typedef std::set<simple_packet_t> set_of_packets;
    set_of_packets pkts;
    set_of_packets zero_pkts;
    
    packet_map_mutex.lock();  
    for (map_of_packets::iterator itr = testmap->begin(); itr != testmap->end(); ++itr) {
	uint32_t subnet_ip = ntohl(itr->first.subnet_address);
	//logger << log4cpp::Priority::INFO << "RRRRRRR"<< subnet_ip<<"\n";

        //pkts.insert(pkts.end(), itr->second.begin(), itr->second.end());
	pkts.insert(itr->second.begin(), itr->second.end());
        itr->second = zero_vector_of_packets;
    }
    packet_map_mutex.unlock();

    //pkts.erase(unique(pkts.begin(), pkts.end()), pkts.end());
    //for (vector_of_packets::iterator vector_itr = pkts.begin(); vector_itr != pkts.end(); ++vector_itr) {
    for (set_of_packets::iterator vector_itr = pkts.begin(); vector_itr != pkts.end(); ++vector_itr) {

        const simple_packet_t* packet = &*vector_itr;

	if (packet->protocol == IPPROTO_UDP or packet->protocol == IPPROTO_TCP){
	    //logger << log4cpp::Priority::INFO << "TTTTTT"<< packe->dst_ip<<"\n";
	    //logger << log4cpp::Priority::INFO << "DUMP: srcint:"<< ntohl(packet->src_ip) <<" srcstr: "<< convert_ip_as_uint_to_string(packet->src_ip) << print_simple_packet(*packet) << "\n";
		
	    packetDateTime->Append(unix_timestamp_nanoseconds/1000000000);
	    source->Append(packet->source);
            sampleRatio->Append(packet->sample_ratio);
            srcIp->Append(ntohl(packet->src_ip));
            dstIp->Append(ntohl(packet->dst_ip));
            srcIpv6->Append("");
            dstIpv6->Append("");
            srcAsn->Append(packet->src_asn);
            dstAsn->Append(packet->dst_asn);
            inputInterface->Append(packet->input_interface);
            outputInterface->Append(packet->output_interface);
            ipProtocolVersion->Append(packet->ip_protocol_version);
            ttl->Append(packet->ttl);
            sourcePort->Append(packet->source_port);
            destinationPort->Append(packet->destination_port);
            protocol->Append(packet->protocol);
            length->Append(packet->length);
            numberOfPackets->Append(packet->number_of_packets);
            flags->Append(packet->flags);
            ipFragmented->Append(packet->ip_fragmented);
            ipDontFragment->Append(packet->ip_dont_fragment);
            packetPayloadLength->Append(packet->packet_payload_length);
            packetPayloadFullLength->Append(packet->packet_payload_full_length);
            packetDirection->Append(packet->packet_direction);
            agentIpAddress->Append(packet->agent_ip_address);

	}
    }
    //pkts = zero_vector_of_packets;
    pkts = zero_pkts;

    clickhouse::Block block;

    //block.AppendColumn("metricDate", metricDate);
    block.AppendColumn("packetDateTime", packetDateTime);
    block.AppendColumn("source", source);
    block.AppendColumn("sampleRatio", sampleRatio);
    block.AppendColumn("srcIp", srcIp);
    block.AppendColumn("dstIp", dstIp);
    block.AppendColumn("srcIpv6", srcIpv6);
    block.AppendColumn("dstIpv6", dstIpv6);
    block.AppendColumn("srcAsn", srcAsn);
    block.AppendColumn("dstAsn", dstAsn);
    block.AppendColumn("inputInterface", inputInterface);
    block.AppendColumn("outputInterface", outputInterface);
    block.AppendColumn("ipProtocolVersion", ipProtocolVersion);
    block.AppendColumn("ttl", ttl);
    block.AppendColumn("sourcePort", sourcePort);
    block.AppendColumn("destinationPort", destinationPort);
    block.AppendColumn("protocol", protocol);
    block.AppendColumn("length", length);
    block.AppendColumn("numberOfPackets", numberOfPackets);
    block.AppendColumn("flags", flags);
    block.AppendColumn("ipFragmented", ipFragmented);
    block.AppendColumn("ipDontFragment", ipDontFragment);
    block.AppendColumn("packetPayloadLength", packetPayloadFullLength);
    block.AppendColumn("packetDirection", packetDirection);
    block.AppendColumn("agentIpAddress", agentIpAddress);

    //logger << log4cpp::Priority::INFO << "Write data to click";
    //logger << log4cpp::Priority::INFO << "time now: "<<  unix_timestamp_nanoseconds/1000000000;

    return write_data_to_clickhousedb(clickhousedb_database, "fastnetmon.traffic", block);


    //return true;
}

// Push per subnet traffic counters to Clickhouse
bool push_network_traffic_counters_to_clickhousedb(std::string clickhousedb_database) {

    auto metricDateTime = std::make_shared<clickhouse::ColumnDateTime>();
    auto network = std::make_shared<clickhouse::ColumnString>();
    auto packets_incoming = std::make_shared<clickhouse::ColumnUInt64>();
    auto packets_outgoing = std::make_shared<clickhouse::ColumnUInt64>();
    auto bits_incoming = std::make_shared<clickhouse::ColumnUInt64>();
    auto bits_outgoing = std::make_shared<clickhouse::ColumnUInt64>();

    for (map_for_subnet_counters_t::iterator itr = PerSubnetAverageSpeedMap.begin(); itr != PerSubnetAverageSpeedMap.end(); ++itr) {
        std::map<std::string, uint64_t> plain_total_counters_map;

        map_element_t* speed         = &itr->second;
        std::string subnet_as_string = convert_subnet_to_string(itr->first);


        fill_main_counters_for_clickhousedb(speed, plain_total_counters_map, false);

    	uint64_t unix_timestamp_nanoseconds = get_current_unix_time_in_nanoseconds();

	metricDateTime->Append(unix_timestamp_nanoseconds/1000000000);
   	network->Append(subnet_as_string);
        packets_incoming->Append(itr->second.in_packets);
        packets_outgoing->Append(itr->second.out_packets);
        bits_incoming->Append(itr->second.in_bytes * 8);
        bits_outgoing->Append(itr->second.out_bytes * 8); 

    }

    clickhouse::Block block;

    block.AppendColumn("metricDateTime", metricDateTime);
    block.AppendColumn("network", network);
    block.AppendColumn("packets_incoming", packets_incoming);
    block.AppendColumn("packets_outgoing", packets_outgoing);
    block.AppendColumn("bits_incoming", bits_incoming);
    block.AppendColumn("bits_outgoing", bits_outgoing);

    return write_data_to_clickhousedb(clickhousedb_database, "fastnetmon.network_metrics", block);

}

// Push host traffic to Clickhouse
bool push_hosts_traffic_counters_to_clickhousedb(std::string clickhousedb_database) {

    map_of_vector_counters_t* current_speed_map = nullptr;

    if (print_average_traffic_counts) {
        current_speed_map = &SubnetVectorMapSpeedAverage;
    } else {
        current_speed_map = &SubnetVectorMapSpeed;
    }

    // Iterate over all networks
    for (map_of_vector_counters_t::iterator itr = current_speed_map->begin(); itr != current_speed_map->end(); ++itr) {
        std::vector<std::pair<std::string, std::map<std::string, uint64_t>>> hosts_vector;

        // Iterate over all hosts in network
        for (vector_of_counters_t::iterator vector_itr = itr->second.begin(); vector_itr != itr->second.end(); ++vector_itr) {
            std::map<std::string, uint64_t> plain_total_counters_map;

            int current_index = vector_itr - itr->second.begin();

            // Convert to host order for math operations
            uint32_t subnet_ip                     = ntohl(itr->first.subnet_address);
            uint32_t client_ip_in_host_bytes_order = subnet_ip + current_index;

            // Convert to our standard network byte order
            uint32_t client_ip = htonl(client_ip_in_host_bytes_order);

            std::string client_ip_as_string = convert_ip_as_uint_to_string(client_ip);

            // Here we could have average or instantaneous speed
            map_element_t* current_speed_element = &*vector_itr;

            // Skip elements with zero speed
            if (current_speed_element->is_zero()) {
                continue;
            }

            fill_main_counters_for_clickhousedb(current_speed_element, plain_total_counters_map, true);

            // Key: client_ip_as_string
            hosts_vector.push_back(std::make_pair(client_ip_as_string, plain_total_counters_map));
        }

        if (hosts_vector.size() > 0) {
            bool result = write_block_of_hosts_traffic_to_clickhousedb(clickhousedb_database, "hosts_traffic", "host", hosts_vector);
            //logger << log4cpp::Priority::INFO << "Write Block OK";

	    if (!result) {
                logger << log4cpp::Priority::INFO << "Write Block of hosts traffic FAILED";
                return false;
            }
        }
    }

    return true;
}


// Write batch of data for particular InfluxDB database
bool write_block_of_hosts_traffic_to_clickhousedb(std::string clickhousedb_database,
                                     std::string measurement,
                                     std::string tag_name,
                                     std::vector<std::pair<std::string, std::map<std::string, uint64_t>>>& hosts_vector) {
    // Nothing to write
    if (hosts_vector.size() == 0) {
        return true;
    }

    uint64_t unix_timestamp_nanoseconds = get_current_unix_time_in_nanoseconds();

  
    auto metricDateTime = std::make_shared<clickhouse::ColumnDateTime>();
    auto host = std::make_shared<clickhouse::ColumnString>();
    auto packets_incoming = std::make_shared<clickhouse::ColumnUInt64>();
    auto packets_outgoing = std::make_shared<clickhouse::ColumnUInt64>();
    auto bits_incoming = std::make_shared<clickhouse::ColumnUInt64>();
    auto bits_outgoing = std::make_shared<clickhouse::ColumnUInt64>();
    auto flows_incoming = std::make_shared<clickhouse::ColumnUInt64>();
    auto flows_outgoing = std::make_shared<clickhouse::ColumnUInt64>();
    auto tcp_packets_incoming = std::make_shared<clickhouse::ColumnUInt64>();
    auto tcp_packets_outgoing = std::make_shared<clickhouse::ColumnUInt64>();
    auto udp_packets_incoming = std::make_shared<clickhouse::ColumnUInt64>();
    auto udp_packets_outgoing = std::make_shared<clickhouse::ColumnUInt64>();
    auto icmp_packets_incoming = std::make_shared<clickhouse::ColumnUInt64>();
    auto icmp_packets_outgoing = std::make_shared<clickhouse::ColumnUInt64>();
    auto fragmented_packets_incoming = std::make_shared<clickhouse::ColumnUInt64>();
    auto fragmented_packets_outgoing = std::make_shared<clickhouse::ColumnUInt64>();
    auto tcp_syn_packets_incoming = std::make_shared<clickhouse::ColumnUInt64>();
    auto tcp_syn_packets_outgoing = std::make_shared<clickhouse::ColumnUInt64>();
    auto tcp_bits_incoming = std::make_shared<clickhouse::ColumnUInt64>();
    auto tcp_bits_outgoing = std::make_shared<clickhouse::ColumnUInt64>();
    auto udp_bits_incoming = std::make_shared<clickhouse::ColumnUInt64>();
    auto udp_bits_outgoing = std::make_shared<clickhouse::ColumnUInt64>();
    auto icmp_bits_incoming = std::make_shared<clickhouse::ColumnUInt64>();
    auto icmp_bits_outgoing = std::make_shared<clickhouse::ColumnUInt64>();
    auto fragmented_bits_incoming = std::make_shared<clickhouse::ColumnUInt64>();
    auto fragmented_bits_outgoing = std::make_shared<clickhouse::ColumnUInt64>();
    auto tcp_syn_bits_incoming = std::make_shared<clickhouse::ColumnUInt64>();
    auto tcp_syn_bits_outgoing = std::make_shared<clickhouse::ColumnUInt64>();


    // Prepare batch for insert
    for (auto& host_traffic : hosts_vector) {
        std::map<std::string, std::string> tags = { { tag_name, host_traffic.first } };
        //metricDate->Append(unix_timestamp_nanoseconds/1000000000);
        metricDateTime->Append(unix_timestamp_nanoseconds/1000000000);
        //std::stringstream buffer;
        //for (auto itr = host_traffic.second.begin(); itr != host_traffic.second.end(); ++itr) {
        //    buffer << itr->first << "=" << itr->second;
        //}
	//logger << log4cpp::Priority::INFO << host_traffic.first <<" # "<< buffer.str()<<"\n";

        host->Append(host_traffic.first);
        packets_incoming->Append(host_traffic.second["packets_incoming"]);
        packets_outgoing->Append(host_traffic.second["packets_outgoing"]);
        bits_incoming->Append(host_traffic.second["bits_incoming"]);
        bits_outgoing->Append(host_traffic.second["bits_outgoing"]);
        flows_incoming->Append(0);
        flows_outgoing->Append(0);
        tcp_packets_incoming->Append(0);
        tcp_packets_outgoing->Append(0);
        udp_packets_incoming->Append(0);
        udp_packets_outgoing->Append(0);
        icmp_packets_incoming->Append(0);
        icmp_packets_outgoing->Append(0);
        fragmented_packets_incoming->Append(0);
        fragmented_packets_outgoing->Append(0);
        tcp_syn_packets_incoming->Append(0);
        tcp_syn_packets_outgoing->Append(0);
        tcp_bits_incoming->Append(0);
        tcp_bits_outgoing->Append(0);
        udp_bits_incoming->Append(0);
        udp_bits_outgoing->Append(0);
        icmp_bits_incoming->Append(0);
        icmp_bits_outgoing->Append(0);
        fragmented_bits_incoming->Append(0);
        fragmented_bits_outgoing->Append(0);
        tcp_syn_bits_incoming->Append(0);
        tcp_syn_bits_outgoing->Append(0);

        //std::string line_protocol_format =
          //  craft_line_for_influxdb_line_protocol(unix_timestamp_nanoseconds, measurement, tags, host_traffic.second);

        //buffer << line_protocol_format << "\n";
    }

    clickhouse::Block block;

    //block.AppendColumn("metricDate", metricDate);
    block.AppendColumn("metricDateTime", metricDateTime);
    block.AppendColumn("host", host);
    block.AppendColumn("packets_incoming", packets_incoming);
    block.AppendColumn("packets_outgoing", packets_outgoing);
    block.AppendColumn("bits_incoming", bits_incoming);
    block.AppendColumn("bits_outgoing", bits_outgoing);
    block.AppendColumn("flows_incoming", flows_incoming);
    block.AppendColumn("flows_outgoing", flows_outgoing);
    block.AppendColumn("tcp_packets_incoming", tcp_packets_incoming);
    block.AppendColumn("tcp_packets_outgoing", tcp_packets_outgoing);
    block.AppendColumn("udp_packets_incoming", udp_packets_incoming);
    block.AppendColumn("udp_packets_outgoing", udp_packets_outgoing);
    block.AppendColumn("icmp_packets_incoming", icmp_packets_incoming);
    block.AppendColumn("icmp_packets_outgoing", icmp_packets_outgoing);
    block.AppendColumn("fragmented_packets_incoming", fragmented_packets_incoming);
    block.AppendColumn("fragmented_packets_outgoing", fragmented_packets_outgoing);
    block.AppendColumn("tcp_syn_packets_incoming", tcp_syn_packets_incoming);
    block.AppendColumn("tcp_syn_packets_outgoing", tcp_syn_packets_outgoing);
    block.AppendColumn("tcp_bits_incoming", tcp_bits_incoming);
    block.AppendColumn("tcp_bits_outgoing", tcp_bits_outgoing);
    block.AppendColumn("udp_bits_incoming", udp_bits_incoming);
    block.AppendColumn("udp_bits_outgoing", udp_bits_outgoing);
    block.AppendColumn("icmp_bits_incoming", icmp_bits_incoming);
    block.AppendColumn("icmp_bits_outgoing", icmp_bits_outgoing);
    block.AppendColumn("fragmented_bits_incoming", fragmented_bits_incoming);
    block.AppendColumn("fragmented_bits_outgoing", fragmented_bits_outgoing);
    block.AppendColumn("tcp_syn_bits_incoming", tcp_syn_bits_incoming);
    block.AppendColumn("tcp_syn_bits_outgoing", tcp_syn_bits_outgoing);

    //logger << log4cpp::Priority::INFO << "Write data to click";
    //logger << log4cpp::Priority::INFO << "time now: "<<  unix_timestamp_nanoseconds/1000000000;

    return write_data_to_clickhousedb(clickhousedb_database, "fastnetmon.host_metrics", block);
}

// Fills special structure which we use to export metrics into InfluxDB
void fill_main_counters_for_clickhousedb(const map_element_t* current_speed_element,
                                     std::map<std::string, uint64_t>& plain_total_counters_map,
                                     bool populate_flow) {
    // Prepare incoming traffic data
    plain_total_counters_map["packets_incoming"] = current_speed_element->in_packets;
    plain_total_counters_map["bits_incoming"]    = current_speed_element->in_bytes * 8;

    // Outdoing traffic
    plain_total_counters_map["packets_outgoing"] = current_speed_element->out_packets;
    plain_total_counters_map["bits_outgoing"]    = current_speed_element->out_bytes * 8;

    if (populate_flow) {
        plain_total_counters_map["flows_incoming"] = current_speed_element->in_flows;
        plain_total_counters_map["flows_outgoing"] = current_speed_element->out_flows;
    }
}

// Prepare string to insert data into InfluxDB
std::string craft_line_for_influxdb_line_protocol(uint64_t unix_timestamp_nanoseconds,
                                                  std::string measurement,
                                                  std::map<std::string, std::string>& tags,
                                                  std::map<std::string, uint64_t>& plain_total_counters_map) {
    std::stringstream buffer;
    buffer << measurement << ",";

    // tag set section
    buffer << join_by_comma_and_equal(tags);
    std::cout<< join_by_comma_and_equal(tags) << "\n";
    buffer << " ";

    // field set section
    for (auto itr = plain_total_counters_map.begin(); itr != plain_total_counters_map.end(); ++itr) {
        buffer << itr->first << "=" << std::to_string(itr->second);
        // it's last element
        if (std::distance(itr, plain_total_counters_map.end()) == 1) {
            // Do not print comma
        } else {
            buffer << ",";
        }
    }

    buffer << " " << std::to_string(unix_timestamp_nanoseconds);
    std::cout<< buffer.str() << "\n";

    return buffer.str();
}
