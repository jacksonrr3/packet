#pragma once

#include <iostream>
#include <string>
#include <sstream>
#include <vector>
#include <algorithm>
#include <utility>
#include "other.h"


class Protocol {
protected:
	std::string _name;
	data _header;
	data _payload;

	virtual void parse(const data* data) = 0;

	const data* header() const;
	const data* payload() const;
public:
	Protocol() {}
	virtual ~Protocol() = default;
	
	std::string name() const;
	virtual NetAddress* source() const = 0;
	virtual NetAddress* destination() const = 0;

	friend class Packet;
};


class L2ProtoEthernet : public Protocol {
	data _dest_mac;
	data _source_mac;
	data _type;
public:
	L2ProtoEthernet(); 

	virtual void parse(const data* d)  override;
	
	NetAddress* source() const override;
	NetAddress* destination() const override;

};

class L3ProtoIPv4 : public Protocol {
	byte _version;
	byte _header_size;
	data _dscp_ecn;
	int _packet_size;
	int _packet_id;
	data _flags_offset;
	byte _live_time;
	byte _l4_protocol;
	data _header_check_sum;
	data _src_ip;
	data _dst_ip;
	data _options;

public:
	L3ProtoIPv4();

	virtual void parse(const data* data) override;
		   	 
	NetAddress* source() const override;
	NetAddress* destination() const override;

	byte L4_protocol_type() const;
};

class L4ProtoUDP : public Protocol {
	

	data _source_port;
	data _destination_port;
	int _length;
	int _checksum;
	
public:
	L4ProtoUDP();
	
	virtual void parse(const data* d) override;
	
	NetAddress* destination() const override;
	NetAddress* source() const override;
};


class L4ProtoTCP : public Protocol {
	data _source_port;
	data _destination_port;
	data _sequence_number;
	data _acknowledgment_number;
	std::size_t _offset;
	byte _reserv;
	byte _flags;
	data _window_size;
	data _checksum;
	data _urgent_point;
	data _options;  
	 
public:
	L4ProtoTCP();
	
	virtual void parse(const data* d)  override;
		
	NetAddress* destination() const override;
	NetAddress* source() const override;
};
