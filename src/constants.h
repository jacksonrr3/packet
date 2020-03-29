#pragma once

typedef uint8_t byte;

//Ethernet
constexpr auto ETH_MAC_SIZE = 6;
constexpr auto ETH_TYPE_SIZE = 2;
constexpr auto ETH_HDR_SZ = 14;

//IPv4

constexpr auto IPV4_VERSION = 4;
constexpr auto IPV4_HDR_PACKET_SIZE = 2;
constexpr auto IPV4_HDR_PACKET_ID = 2;
constexpr auto IPV4_HDR_FLAGS_OFFSET = 2;
constexpr auto IPV4_HDR_CHECK_SUM = 2;
constexpr auto IPV4_HDR_IP_SIZE = 4;
constexpr auto IPV4_HDR_MIN_SIZE = 5;
constexpr auto IPV4_HDR_MAX_SIZE = 15;

constexpr auto PORT_SIZE = 2;
//TCP
constexpr auto TCP_NUMBER = 6;
constexpr auto TCP_SN = 4;
constexpr auto TCP_ASC_SN = 4;
constexpr auto TCP_OTH_L = 2;

//UDP
constexpr auto UDP_NUMBER = 17;
constexpr auto UDP_HDR_PART_SZ = 2;
