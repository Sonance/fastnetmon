#pragma once

#include "fastnetmon_types.h"
#include <stdint.h>
#include <sys/types.h>

bool parse_raw_packet_to_simple_packet(u_char* buffer, int len, simple_packet_t& packet, bool netmap_read_packet_length_from_ip_header);
