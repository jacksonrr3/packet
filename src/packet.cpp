#include "packet.h"

void Packet::parse(unsigned char* d, std::size_t lenght) {
	_l2 = std::make_shared<L2ProtoEthernet>();
	_l2->parse(&data(d, lenght));
	
	_l3 = std::make_shared<L3ProtoIPv4>();
	_l3->parse(_l2->payload());
	_l4_type = (std::dynamic_pointer_cast<L3ProtoIPv4>(_l3))->L4_protocol_type();

	if (_l4_type == 6) {
		_l4 = std::make_shared<L4ProtoTCP>();
	}
	if (_l4_type == 17) {
		_l4 = std::make_shared<L4ProtoUDP>();
	}

	_l4->parse(_l3->payload());
}

std::shared_ptr<Protocol> Packet::l2() const
{
	return _l2;
}

std::shared_ptr<Protocol> Packet::l3() const
{
	return _l3;
}

std::shared_ptr<Protocol> Packet::l4() const {
	return _l4;
}

