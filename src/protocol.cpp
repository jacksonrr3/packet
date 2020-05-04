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


//Protocol Eth 
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

std::unique_ptr<Mac> L2ProtoEthernet::source_mac() const
{
	return std::make_unique<Mac>(_eth_h->_source_mac, "Source_Mac-Address");
}

std::unique_ptr<Mac> L2ProtoEthernet::destination_mac() const
{

	return std::make_unique<Mac>(_eth_h->_dest_mac, "Destination_Mac-Address");
}

int L2ProtoEthernet::get_type() {
	return _eth_h->_type[0];
}

//Protocol IPv4 
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

	if (_ipv4_h->_header_size * BIT_IN_OCTET - IPV4_HDR_SIZE_WITHOUT_OPT) {
		_options = { data.ptr + IPV4_HDR_SIZE_WITHOUT_OPT, 
			std::size_t(_ipv4_h->_header_size * BIT_IN_OCTET - IPV4_HDR_SIZE_WITHOUT_OPT) };
	}

	_header = { data.ptr, (std::size_t)(_ipv4_h->_header_size * BIT_IN_OCTET) };
	_payload = { data.ptr + _ipv4_h->_header_size * BIT_IN_OCTET ,
		data.size - _ipv4_h->_header_size * BIT_IN_OCTET };
};

std::unique_ptr<Ip> L3ProtoIPv4::source_ip() const
{
	return std::make_unique<Ip>(_ipv4_h->_src_ip, "Source_Ip-Addres");
}

std::unique_ptr<Ip> L3ProtoIPv4::destination_ip() const
{
	return std::make_unique<Ip>(_ipv4_h->_dst_ip, "Destination_Ip-Address");
}

byte L3ProtoIPv4::L4_protocol_type() const
{
	return _ipv4_h->_l4_protocol;
}

byte L3ProtoIPv4::get_hdr_size() const {
	return _ipv4_h->_header_size;
}

byte L3ProtoIPv4::get_version() const {
	return _ipv4_h->_version;
}

byte L3ProtoIPv4::get_ecn() const {
	return _ipv4_h->_ecn;
}

byte L3ProtoIPv4::get_dscp() const {
	return _ipv4_h->_dscp;
}

uint16_t L3ProtoIPv4::get_packet_size() const {
	auto p = _ipv4_h->_packet_size;
	return p[0] * 256 + p[1];
}

uint16_t L3ProtoIPv4::get_packet_id() const {
	auto p = _ipv4_h->_packet_id;
	return p[0] * 256 + p[1];
}

byte L3ProtoIPv4::get_flags() const {
	return _ipv4_h->_flags_offset[0] >> 5;
}

uint16_t L3ProtoIPv4::get_offset() const {
	auto p = _ipv4_h->_flags_offset;
	return (p[0] & 0b00011111) * 256 + p[1];
}

byte L3ProtoIPv4::get_live_time() const {
	return _ipv4_h->_live_time;
}

uint16_t L3ProtoIPv4::get_checksum() const {
	auto p = _ipv4_h->_header_check_sum;
	return p[0] * 256 + p[1];
}

const data& L3ProtoIPv4::get_options() const {
	return _options;
}


//Protocol UDP 
L4ProtoUDP::L4ProtoUDP() :Protocol("User_Datagram_Protocol") {}

void L4ProtoUDP::parse(const data& data) {

	if (data.size < UDP_HEADER_SIZE || data.size > 65507) {
		throw ParseError("Error L4 UDP: - wrong length.");
	}
	_udp_h = (UDP_Header*)(data.ptr);

	_header = { data.ptr, UDP_HEADER_SIZE };
	_payload = { data.ptr + UDP_HEADER_SIZE, data.size - UDP_HEADER_SIZE };

	if ((_udp_h->_length[0] * 256 + _udp_h->_length[1]) != data.size) {
		//if ((_udp_h->_length) != data.size) {
		throw ParseError("Error L4 UDP: - wrong length.");
	}
};

std::unique_ptr<Port> L4ProtoUDP::destination_port() const
{
	return std::make_unique<Port>(_udp_h->_destination_port, "Destination_Port");
}

std::unique_ptr<Port> L4ProtoUDP::source_port() const
{
	return std::make_unique<Port>(_udp_h->_source_port, "Source_Port");
}

uint16_t L4ProtoUDP::get_length() const {
	return _udp_h->_length[0] * 256 + _udp_h->_length[1];
}

uint16_t L4ProtoUDP::get_checksum() const {
	return _udp_h->_checksum[0] * 256 + _udp_h->_checksum[1];
}


//Protocol TCP 
L4ProtoTCP::L4ProtoTCP() :Protocol("Transmission_Control_Protocol") {}

void L4ProtoTCP::parse(const data& data)
{
	if (data.size < 8 || data.size > 65507) {
		throw ParseError("Error L4 UDP: - wrong length.");
	}

	_tcp_h = (TCP_Header*)(data.ptr);

	//_length = d.ptr[12] >> 4;
	_length = _tcp_h->_offset * BIT_IN_OCTET; // длина заголовка в байтах

	auto f = _tcp_h->_flags;
	if ((_length < TCP_HEADER_SIZE_MIN) ||
		(_length > TCP_HEADER_SIZE_MAX)) {
		throw ParseError("Error L4 TCP header: - wrong header length.");
	}
	if (_length  - TCP_HEADER_SIZE_MIN) {
		_options = { data.ptr + TCP_HEADER_SIZE_MIN, 
			(std::size_t)(_length  - TCP_HEADER_SIZE_MIN) };
	}
	_header = { data.ptr, _length };
	_payload = { data.ptr + _length, 
		data.size - _length};
};

std::unique_ptr<Port> L4ProtoTCP::destination_port() const
{
	return std::make_unique<Port>(_tcp_h->_destination_port, "Destination_Port");
}

std::unique_ptr<Port> L4ProtoTCP::source_port() const
{
	return std::make_unique<Port>(_tcp_h->_source_port, "Source_Port");
}

unsigned int L4ProtoTCP::get_sn() const {
	auto p = _tcp_h->_sequence_number;
	return (((p[0] * 256) + p[1]) * 256 + p[2]) * 256 + p[3];
}

unsigned int L4ProtoTCP::get_asc_sn() const {
	auto p = _tcp_h->_acknowledgment_number;
	return (((p[0] * 256) + p[1]) * 256 + p[2]) * 256 + p[3];
}

byte L4ProtoTCP::get_offset() const {
	return _tcp_h->_offset;
}

byte L4ProtoTCP::get_flags() const {
	return _tcp_h->_flags;
}

uint16_t L4ProtoTCP::get_window_size() const {
	auto p = _tcp_h->_window_size;
	return p[0] * 256 + p[1];
}

uint16_t L4ProtoTCP::get_checksum() const {
	auto p = _tcp_h->_checksum;
	return p[0] * 256 + p[1];
}

uint16_t L4ProtoTCP::get_urgent_point() const {
	auto p = _tcp_h->_urgent_point;
	return p[0] * 256 + p[1];
}

const data& L4ProtoTCP::get_options() const {
	return _options;
}

