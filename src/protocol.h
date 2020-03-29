#pragma once

#include <iostream>
#include <string>
#include <sstream>
#include <vector>
#include <algorithm>
#include <utility>
#include "other.h"

struct EthHeader {
	byte _dest_mac[ETH_MAC_SIZE];
	byte _source_mac[ETH_MAC_SIZE];
	byte _type[ETH_TYPE_SIZE];
};

struct IPv4Header {
	byte _header_size : 4;
	byte _version: 4;
	byte _dscp_ecn;
	byte _packet_size[IPV4_HDR_PACKET_SIZE];
	byte _packet_id[IPV4_HDR_PACKET_ID];
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
	byte _destination_port[PORT_SIZE];
	byte _sequence_number[TCP_SN];
	byte _acknowledgment_number[TCP_ASC_SN];
	byte _offset_reserv_flags[TCP_OTH_L];
	byte _window_size[TCP_OTH_L];
	byte _checksum[TCP_OTH_L];
	byte _urgent_point[TCP_OTH_L];
};



class Protocol {
protected:
	std::string _name;
	data _header;
	data _payload;

	virtual void parse(const data& d) = 0;

	const data& header() const;
	const data& payload() const;
public:
	Protocol() {}
	Protocol(const std::string& s):
		_name(s), _header(), _payload() {}
	virtual ~Protocol() = default;

	const std::string& name() const;
	virtual std::unique_ptr<NetAddress> source() const = 0;
	virtual std::unique_ptr<NetAddress> destination() const = 0;

	friend class Packet;
};


class L2ProtoEthernet : public Protocol {
	EthHeader* _eth_h;

public:
	L2ProtoEthernet();

	virtual void parse(const data& d)  override;

	std::unique_ptr<NetAddress> source() const override;
	std::unique_ptr<NetAddress> destination() const override;

};


class L3ProtoIPv4 : public Protocol {
	IPv4Header* _ipv4_h;
	data _options;
	
public:
	L3ProtoIPv4();

	virtual void parse(const data& d) override;

	std::unique_ptr<NetAddress> source() const override;
	std::unique_ptr<NetAddress> destination() const override;

	byte L4_protocol_type() const;
};

class L4ProtoUDP : public Protocol {
	UDP_Header* _udp_h;

public:
	L4ProtoUDP();

	virtual void parse(const data& d) override;

	std::unique_ptr<NetAddress> destination() const override;
	std::unique_ptr<NetAddress> source() const override;
};


class L4ProtoTCP : public Protocol {
	TCP_Header* _tcp_h;
	data _options;
	std::size_t _lenght;

public:
	L4ProtoTCP();

	virtual void parse(const data& d)  override;

	std::unique_ptr<NetAddress>  destination() const override;
	std::unique_ptr<NetAddress>  source() const override;
};

