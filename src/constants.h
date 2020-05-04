#pragma once

typedef uint8_t byte;

constexpr auto BIT_IN_OCTET = 4;

//Ethernet
constexpr auto ETH_MAC_SIZE = 6;
constexpr auto ETH_TYPE_SIZE = 2;
constexpr auto ETH_HDR_SZ = 14;

//IPv4

constexpr auto IPV4_VERSION = 4;
constexpr auto IPV4_HDR_VERSION_BITS = 4;
constexpr auto IPV4_HDR_HEADER_SIZE_BITS = 4;
constexpr auto IPV4_HDR_DSCP_BITS = 6;
constexpr auto IPV4_HDR_ECN_BITS = 2;
constexpr auto IPV4_HDR_PACKET_SIZE = 2;
constexpr auto IPV4_HDR_PACKET_ID = 2;
//constexpr auto IPV4_HDR_OFFSET_BITS = 13;
//constexpr auto IPV4_HDR_FLAGS_BITS = 3;
constexpr auto IPV4_HDR_FLAGS_OFFSET = 2;
constexpr auto IPV4_HDR_CHECK_SUM = 2;
constexpr auto IPV4_HDR_IP_SIZE = 4;
constexpr auto IPV4_HDR_MIN_SIZE = 5;
constexpr auto IPV4_HDR_MAX_SIZE = 15;

constexpr auto IPV4_HDR_SIZE_WITHOUT_OPT = 20;

constexpr auto PORT_SIZE = 2;
//TCP
constexpr auto TCP_NUMBER = 6;
constexpr auto TCP_SN = 4;
constexpr auto TCP_ASC_SN = 4;
constexpr auto TCP_OTH_L = 2;
constexpr auto TCP_HDR_OFFSET_BITS = 4;
constexpr auto TCP_HDR_FLAGS_BITS = 6;
constexpr auto TCP_HEADER_SIZE_MIN = 20; //минимальный размер TCPзаголовка в байтах
constexpr auto TCP_HEADER_SIZE_MAX = 60; //минимальный размер TCPзаголовка в байтах

//UDP
constexpr auto UDP_NUMBER = 17;
constexpr auto UDP_HDR_PART_SZ = 2;
constexpr auto UDP_HEADER_SIZE = 8;		//размер UDPзаголовка в байтах
