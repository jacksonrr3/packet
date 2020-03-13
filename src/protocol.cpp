#include "protocol.h"

	std::string Protocol::name() const 
	{
		return _name;
	}

	const data* Protocol::header() const {
		return &_header;
	}

	const data* Protocol::payload() const {
		return &_payload;
	}


	L2ProtoEthernet::L2ProtoEthernet() 
	{
		_name = "Ethernet_version_2";
	}

	void L2ProtoEthernet::parse(const data* d)  
	{
		_header = { d->ptr, 14 };
		_payload = { d->ptr + 14, d->size - 14 };

		if ((_header.size + _payload.size) < 60) {
			throw ParseError("Error L2 lenght: - less then minimum.");
		}
		_dest_mac = { d->ptr, 6 };
		_source_mac = { d->ptr + 6, 6 };
		_type = { d->ptr + 12, 2 };
	};

	NetAddress* L2ProtoEthernet::source() const 
	{
		NetAddress* temp = new Mac(&_source_mac, "Source_Mac-Address");
		return temp;
	}

	NetAddress* L2ProtoEthernet::destination() const 
	{
		NetAddress* temp = new Mac(&_dest_mac, "Destination_Mac-Address");
		return temp;
	}

	
	L3ProtoIPv4::L3ProtoIPv4() 
	{
		_name = "Internet_Protocol_version_4";
	}

	void L3ProtoIPv4::parse(const data* data) 
	{
		if (data->size < 5 || (data->size * 4) > 65535) {
			throw ParseError("Error L3 packet: - wrong packet size.");
		}

		_version = (data->ptr[0] & 0xF0) >> 4;
		if (_version != 4) {
			throw ParseError("Error L3 header: - wrong version.");
		}

		_header_size = (data->ptr[0] & 0x0F);
		if ((_header_size < 5) || (_header_size > 15)) {
			throw ParseError("Error L3 header: - wrong header size.");
		}

		_dscp_ecn = { data->ptr + 1, 1 };
		_packet_size = data->size;
		_packet_id = data->ptr[4] * 256 + data->ptr[5];
		_flags_offset = { data->ptr + 6, 2 };
		_live_time = data->ptr[8];
		_l4_protocol = data->ptr[9];
		_header_check_sum = { data->ptr + 10, 2 };
		_src_ip = { data->ptr + 12, 4 };
		_dst_ip = { data->ptr + 16, 4 };
		_options = { data->ptr + 20, std::size_t(_header_size * 4 - 20) };

		_header = { data->ptr, _header_size };
		_payload = { data->ptr + _header_size * 4 , data->size - _header_size * 4 };
	};

	NetAddress* L3ProtoIPv4::source() const
	{
		NetAddress* temp = new Ip(&_src_ip, "Source_Ip-Addres");
		return temp;
	}

	NetAddress* L3ProtoIPv4::destination() const 
	{
		NetAddress* temp = new Ip(&_dst_ip, "Destination_Ip-Address");
		return temp;
	}

	byte L3ProtoIPv4::L4_protocol_type() const 
	{
		return _l4_protocol;
	}

	
	L4ProtoUDP::L4ProtoUDP()
	{
		_name = "User_Datagram_Protocol";
	}

	void L4ProtoUDP::parse(const data* d) {
		_source_port = { d->ptr, 2 };
		_destination_port = { d->ptr + 2, 2 };
		_length = d->ptr[4] * 256 + d->ptr[5];
		_checksum = d->ptr[6] * 256 + d->ptr[7];

		_header.ptr = d->ptr;
		_header.size = 8;
		_payload.ptr = d->ptr + 8;
		_payload.size = d->size - 8;

		if (_length != d->size) {
			throw ParseError("Error L4 UDP: - wrong length.");
		}
	};

	NetAddress* L4ProtoUDP::destination() const 
	{
		NetAddress* temp = new Port(&_destination_port, "Destination_Port");
		return temp;
	}

	NetAddress* L4ProtoUDP::source() const
	{
		NetAddress* temp = new Port(&_source_port, "Source_Port");
		return temp;
	}

	
	L4ProtoTCP::L4ProtoTCP() 
	{
		_name = "Transmission_Control_Protocol";
	}

	void L4ProtoTCP::parse(const data* d) 
	{
		_source_port = { d->ptr, 2 };
		_destination_port = { d->ptr + 2, 2 };
		_sequence_number = { d->ptr + 4, 4 };
		_acknowledgment_number = { d->ptr + 8, 4 };
		_offset = d->ptr[12] >> 4;
		_reserv = ((d->ptr[12] & 0b00001111) << 2) + ((d->ptr[13] & 0b11000000) >> 6);
		_flags = d->ptr[13] & 0b00111111;
		_window_size = { d->ptr + 14, 2 };
		_checksum = { d->ptr + 16, 2 };
		_urgent_point = { d->ptr + 18, 2 };

		if ((_offset < 5) || (_offset > 15)) {
			throw ParseError("Error L4 TCP header: - wrong header length.");
		}

		_options = { d->ptr + 20, _offset * 4 - 20 };
		_header.ptr = d->ptr;
		_header.size = d->size - _offset * 4;
		_payload.ptr = d->ptr + _offset * 4;
		_payload.size = d->size - _offset * 4;
	};

	NetAddress* L4ProtoTCP::destination() const 
	{
		NetAddress* temp = new Port(&_destination_port, "Destination_Port");
		return temp;
	}

	NetAddress* L4ProtoTCP::source() const 
	{
		NetAddress* temp = new Port(&_source_port, "Source_Port");
		return temp;
	}

