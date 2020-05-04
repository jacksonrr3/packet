#include "other.h"


ParseError::ParseError(std::string error)
	: runtime_error(error) {}


data::data() = default;
data::data(byte* p, const std::size_t& l) :ptr(p), size(l) {}

data& data::operator=(const data& d)
{
	ptr = d.ptr;
	size = d.size;
	return *this;
}

 
Mac::Mac(byte* d, const std::string s) : NetAddress({ d , ETH_MAC_SIZE }, s){}

std::string Mac::to_string() const
{
	std::stringstream ss;
	ss << std::hex << (int)ptr[0] << "." << (int)ptr[1] << "." <<
		(int)ptr[2] << "." << (int)ptr[3] << "." <<
		(int)ptr[4] << "." << (int)ptr[5];
	return std::string(ss.str());
};

const std::string& Mac::type() const
{
	return _type;
}

Ip::Ip(byte* d, const std::string s) :NetAddress({ d, IPV4_HDR_IP_SIZE }, s){}

std::string Ip::to_string() const
{
	return std::to_string(ptr[0]) + "." +
		std::to_string(ptr[1]) + "." +
		std::to_string(ptr[2]) + "." +
		std::to_string(ptr[3]);
}

const std::string& Ip::type() const
{
	return _type;
}

Port::Port(byte* d, const std::string s): NetAddress({ d, PORT_SIZE }, s){}

std::string Port::to_string() const
{
	return std::to_string(ptr[0] * 256 + ptr[1]);
}

const std::string& Port::type() const
{
	return _type;
}

