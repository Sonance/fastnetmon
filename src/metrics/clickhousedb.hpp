#pragma once

#include <string>
#include <vector>

#include "../fastnetmon_types.h"

void clickhouse_push_traffic_thread();
void clickhouse_push_thread();
bool push_traffic_counters_to_clickhousedb(std::string clickhousedb_database);
bool push_network_traffic_counters_to_clickhousedb(std::string clickhousedb_database);
bool push_hosts_traffic_counters_to_clickhousedb(std::string clickhousedb_database);
bool push_total_metrics_counters_to_clickhousedb(std::string clickhousedb_database,
                                             total_counter_element_t total_speed_average_counters_param[4],
                                             bool ipv6);


bool write_block_of_hosts_traffic_to_clickhousedb(std::string clickhousedb_database,
                                     std::string measurement,
                                     std::string tag_name,
                                     std::vector<std::pair<std::string, std::map<std::string, uint64_t>>>& hosts_vector);
void fill_main_counters_for_clickhousedb(const map_element_t* current_speed_element,
                                     std::map<std::string, uint64_t>& plain_total_counters_map,
                                     bool populate_flow);
std::string craft_line_for_influxdb_line_protocol(uint64_t unix_timestamp_nanoseconds,
                                                  std::string measurement,
                                                  std::map<std::string, std::string>& tags,
                                                  std::map<std::string, uint64_t>& plain_total_counters_map);

