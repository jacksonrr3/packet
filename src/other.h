#pragma once

#include <iostream>
#include <string>
#include <sstream>
#include <vector>
#include <algorithm>
#include <utility>
#include <exception>


constexpr auto ETH_HDR_SZ = 14;		typedef uint8_t byte;


class ParseError : public std::exception
{
private:
	std::string m_error;

public:
	ParseError(std::string error);

	const char* what() const noexcept;

};


struct data {
	byte* ptr = nullptr;
	std::size_t size = 0;

	data();// {}
	data(byte* p, const std::size_t& l);// :ptr(p), size(l) {}
	data& operator=(const data& d);
};


class NetAddress : public data {
protected:
	std::string _type;
public:
	~NetAddress() {}
	virtual std::string to_string() const = 0;
	virtual std::string type() const = 0;
};


class Mac : public NetAddress {
	Mac(const data* d, const std::string s);
public:
	std::string to_string() const override;
	std::string type() const override;

	friend class L2ProtoEthernet;
};


class Ip : public NetAddress {

	Ip(const data* d, const std::string s);
public:
	std::string to_string() const override;
	std::string type() const override;

	friend class L3ProtoIPv4;
};


class Port : public NetAddress {
	Port(const data* d, const std::string s);
public:
	std::string to_string() const override;
	std::string type() const override;

	friend class L4ProtoUDP;
	friend class L4ProtoTCP;
};
