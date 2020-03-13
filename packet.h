#pragma once

#include <iostream>
#include <string>
#include <sstream>
#include <vector>
#include <array>
#include <algorithm>
#include <utility>
#include <memory>
#include "protocol.h"


class Packet {
	std::shared_ptr<Protocol> _l2;
	std::shared_ptr<Protocol> _l3;
	std::shared_ptr<Protocol> _l4;

	byte _l3_version;
	byte _l4_type;
	
	Packet(const Packet& p) = delete;
	Packet& operator=(const Packet& p) = delete;

public:
	Packet() = default;
	
	void parse(unsigned char* d, std::size_t lenght);
	
	std::shared_ptr<Protocol> l2() const;
	std::shared_ptr<Protocol> l3() const;
	std::shared_ptr<Protocol> l4() const;

};
