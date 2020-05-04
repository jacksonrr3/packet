#pragma once

#include <iostream>
#include <string>
#include <sstream>
#include <vector>
#include <algorithm>
#include <utility>
#include <memory>
#include "other.h"

struct EthHeader {
	byte _dest_mac[ETH_MAC_SIZE];
	byte _source_mac[ETH_MAC_SIZE];
	byte _type[ETH_TYPE_SIZE];
};


struct IPv4Header {
	byte _header_size : IPV4_HDR_HEADER_SIZE_BITS;
	byte _version: IPV4_HDR_VERSION_BITS;
	byte _ecn : IPV4_HDR_ECN_BITS;
	byte _dscp : IPV4_HDR_DSCP_BITS;
	//byte _dscp_ecn;
	byte _packet_size[IPV4_HDR_PACKET_SIZE];
	byte _packet_id[IPV4_HDR_PACKET_ID];
	//uint16_t _offset : IPV4_HDR_OFFSET_BITS;
	//uint16_t _flags : IPV4_HDR_FLAGS_BITS;
	byte _flags_offset[IPV4_HDR_FLAGS_OFFSET];
	byte _live_time;
	byte _l4_protocol;
	byte _header_check_sum[IPV4_HDR_CHECK_SUM];
	byte _src_ip[IPV4_HDR_IP_SIZE];
	byte _dst_ip[IPV4_HDR_IP_SIZE];
};


struct UDP_Header {
	byte _source_port[UDP_HDR_PART_SZ];
	byte _destination_port[UDP_HDR_PART_SZ];
	byte _length[UDP_HDR_PART_SZ];
	byte _checksum[UDP_HDR_PART_SZ];
};


struct TCP_Header {
	byte _source_port[PORT_SIZE];
	//unsigned short _source_port;
	byte _destination_port[PORT_SIZE];
	byte _sequence_number[TCP_SN];
	byte _acknowledgment_number[TCP_ASC_SN];
	byte _reserv_1 : 4; 
	byte _offset : TCP_HDR_OFFSET_BITS;
	byte : 0;
	byte _flags : TCP_HDR_FLAGS_BITS;
	byte _reserv_2 : 2;
	//byte _offset_reserv_flags[TCP_OTH_L];
	byte _window_size[TCP_OTH_L];
	byte _checksum[TCP_OTH_L];
	byte _urgent_point[TCP_OTH_L];
};


class Protocol {
protected:
	std::string _name;
	data _header;
	data _payload;

public:
	virtual void parse(const data& d) = 0;

	const data& header() const;
	const data& payload() const;

	Protocol() {}
	Protocol(const std::string& s):
		_name(s), _header(), _payload() {}
	virtual ~Protocol() = default;

	const std::string& name() const;
	//virtual std::unique_ptr<NetAddress> source() const = 0;
	//virtual std::unique_ptr<NetAddress> destination() const = 0;

	//friend class Packet;
};


class L2ProtoEthernet : public Protocol {
	EthHeader* _eth_h = nullptr;

public:
	L2ProtoEthernet();

	virtual void parse(const data& d)  override;

	//std::unique_ptr<NetAddress> source() const override;
	//std::unique_ptr<NetAddress> destination() const override;

	std::unique_ptr<Mac> source_mac() const;
	std::unique_ptr<Mac> destination_mac() const;

	int get_type();

};


class L3ProtoIPv4 : public Protocol {
	IPv4Header* _ipv4_h = nullptr;
	data _options;
	
public:
	L3ProtoIPv4();

	virtual void parse(const data& d) override;

	std::unique_ptr<Ip> source_ip() const;
	std::unique_ptr<Ip> destination_ip() const;

	byte L4_protocol_type() const;
	
	byte get_hdr_size() const;

	byte get_version() const;

	byte get_ecn() const;

	byte get_dscp() const;

	uint16_t get_packet_size() const;

	uint16_t get_packet_id() const;

	byte get_flags() const;

	uint16_t get_offset() const;

	byte get_live_time() const;

	uint16_t get_checksum() const;

	const data& get_options() const;
};

class L4ProtoUDP : public Protocol {
	UDP_Header* _udp_h = nullptr;

public:
	L4ProtoUDP();

	virtual void parse(const data& d) override;

	std::unique_ptr<Port> destination_port() const;
	std::unique_ptr<Port> source_port() const;

	uint16_t get_length() const;
	uint16_t get_checksum() const;

};


class L4ProtoTCP : public Protocol {
	TCP_Header* _tcp_h = nullptr;
	data _options;
	std::size_t _length;

public:
	L4ProtoTCP();

	virtual void parse(const data& d)  override;

	std::unique_ptr<Port>  destination_port() const;
	std::unique_ptr<Port>  source_port() const;

	unsigned int get_sn() const;

	unsigned int get_asc_sn() const;

	byte get_offset() const;

	byte get_flags() const;
	
	uint16_t get_window_size() const;

	uint16_t get_checksum() const;

	uint16_t get_urgent_point() const;

	const data& get_options() const;

};
