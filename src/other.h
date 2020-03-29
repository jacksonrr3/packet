#pragma once

#include <iostream>
#include <string>
#include <sstream>
#include <vector>
#include <algorithm>
#include <utility>
#include <exception>
#include "constants.h"


class ParseError : public std::runtime_error
{

public:
	ParseError(std::string error);
};


struct data {
	byte* ptr = nullptr;
	std::size_t size = 0;

	data();
	data(byte* p, const std::size_t& l);
	data& operator=(const data& d);
};


class NetAddress : public data {
protected:
	std::string _type;
public:
	NetAddress(const data& d, const std::string s): data(d), _type(s) {}
	~NetAddress() {}
	virtual std::string to_string() const = 0;
	virtual const std::string& type() const = 0;
};


class Mac : public NetAddress {
public:
	Mac(byte* d, const std::string s);

	std::string to_string() const override;
	const std::string& type() const override;

	friend class L2ProtoEthernet;
};


class Ip : public NetAddress {
public:
	Ip(byte* d, const std::string s);

	std::string to_string() const override;
	const std::string& type() const override;

	friend class L3ProtoIPv4;
};


class Port : public NetAddress {
public:
	Port(byte* d, const std::string s);

	std::string to_string() const override;
	const std::string& type() const override;

	friend class L4ProtoUDP;
	friend class L4ProtoTCP;
};
