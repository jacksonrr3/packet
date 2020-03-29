#include "protocol.h"

const std::string& Protocol::name() const
{
	return _name;
}

const data& Protocol::header() const {
	return _header;
}

const data& Protocol::payload() const {
	return _payload;
}


L2ProtoEthernet::L2ProtoEthernet() : Protocol("Ethernet_version_2") {}


void L2ProtoEthernet::parse(const data& d)
{
	if (d.size < 60) {
		throw ParseError("Error L2 lenght: - less then minimum.");
	}
	
	_eth_h = (EthHeader*)d.ptr;
	_header = { d.ptr, ETH_HDR_SZ };
	_payload = { d.ptr + ETH_HDR_SZ, d.size - ETH_HDR_SZ };
};

std::unique_ptr<NetAddress> L2ProtoEthernet::source() const
{
	return std::make_unique<Mac>(_eth_h->_source_mac, "Source_Mac-Address");
}

std::unique_ptr<NetAddress> L2ProtoEthernet::destination() const
{

	return std::make_unique<Mac>(_eth_h->_dest_mac, "Destination_Mac-Address");
}


L3ProtoIPv4::L3ProtoIPv4():Protocol("Internet_Protocol_version_4"){}

void L3ProtoIPv4::parse(const data& data)
{
	if (data.size < 5 || (data.size * 4) > 65535) {
		throw ParseError("Error L3 packet: - wrong packet size.");
	}

	_ipv4_h = (IPv4Header*)(data.ptr);

	if (_ipv4_h->_version != IPV4_VERSION) {
		throw ParseError("Error L3 header: - wrong version.");
	}

	if ((_ipv4_h->_header_size < IPV4_HDR_MIN_SIZE) || 
		(_ipv4_h->_header_size > IPV4_HDR_MAX_SIZE)) {
		throw ParseError("Error L3 header: - wrong header size.");
	}

	if (_ipv4_h->_header_size * 4 - 20) {
		_options = { data.ptr + 20, std::size_t(_ipv4_h->_header_size * 4 - 20) };
	}

	_header = { data.ptr, (std::size_t)(_ipv4_h->_header_size * 4) };
	_payload = { data.ptr + _ipv4_h->_header_size * 4 , data.size - _ipv4_h->_header_size * 4 };
};

std::unique_ptr<NetAddress> L3ProtoIPv4::source() const
{
	return std::make_unique<Ip>(_ipv4_h->_src_ip, "Source_Ip-Addres");
}

std::unique_ptr<NetAddress> L3ProtoIPv4::destination() const
{
	return std::make_unique<Ip>(_ipv4_h->_dst_ip, "Destination_Ip-Address");
}

byte L3ProtoIPv4::L4_protocol_type() const
{
	return _ipv4_h->_l4_protocol;
}


L4ProtoUDP::L4ProtoUDP():Protocol("User_Datagram_Protocol"){}

void L4ProtoUDP::parse(const data& data) {

	if (data.size < 8 || data.size > 65507) {
		throw ParseError("Error L4 UDP: - wrong length.");
	}
	_udp_h = (UDP_Header*)(data.ptr);

	_header = { data.ptr, 9 };
	_payload = { data.ptr + 8, data.size - 8 };
	
	if ((_udp_h->_length[0]*256 + _udp_h->_length[1]) != data.size) {
		throw ParseError("Error L4 UDP: - wrong length.");
	}
};

std::unique_ptr<NetAddress> L4ProtoUDP::destination() const
{
	return std::make_unique<Port>(_udp_h->_destination_port, "Destination_Port");
}

std::unique_ptr<NetAddress> L4ProtoUDP::source() const
{
	return std::make_unique<Port>(_udp_h->_source_port, "Destination_Port");
}


L4ProtoTCP::L4ProtoTCP() :Protocol("Transmission_Control_Protocol") {}

void L4ProtoTCP::parse(const data& d)
{
	_tcp_h = (TCP_Header*)(d.ptr);

	_lenght = d.ptr[12] >> 4;

	if ((_lenght < 5) || (_lenght > 15)) {
		throw ParseError("Error L4 TCP header: - wrong header length.");
	}
	if (_lenght * 4 - 20) {
		_options = { d.ptr + 20, (std::size_t)(_lenght * 4 - 20) };
	}
	_header = { d.ptr, d.size - _lenght * 4 };
	_payload = { d.ptr + _lenght * 4 , d.size - _lenght * 4 };
};

std::unique_ptr<NetAddress> L4ProtoTCP::destination() const
{
	return std::make_unique<Port>(_tcp_h->_destination_port, "Destination_Port");
}

std::unique_ptr<NetAddress> L4ProtoTCP::source() const
{
	return std::make_unique<Port>(_tcp_h->_source_port, "Source_Port");
}
