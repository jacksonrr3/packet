#include <iostream>
#include <string>
#include <vector>
#include <array>


class Protocol {
public:
	Protocol() = default;
	virtual ~Protocol() = default;
};

class L2ProtoEthernet : public Protocol {
	std::array<unsigned char, 6> dest_mac_;
	std::array<unsigned char, 6> source_mac_;
	std::array<unsigned char, 2> type_;

public:
	L2ProtoEthernet() {}
	void set(unsigned char * data){
		for (int i = 0; i < 6; i++) {
			dest_mac_[i] = data[i];
		}
		for (int i = 6; i < 12; i++) {
			source_mac_[i-6] = data[i];
		}
		for (int i = 12; i < 14; i++) {
			type_[i - 12] = data[i];
		}
	}

	std::string dstmac() {
	
	}

	std::string srcmac() {

	}

};

class L3ProtoIPv4 : public Protocol {
	std::vector<unsigned char> ip_header_;

public:
	L3ProtoIPv4() {}
	void set(unsigned char* data, std::size_t header_lenght) {
		for (int i = 0; i < header_lenght; i++) {
			ip_header_.push_back(data[i]);
		}
	}
};


class L4ProtoUDP : public Protocol {
	std::vector<unsigned char> udp_header_;

public:
	L4ProtoUDP() {}
	void set(unsigned char* data) {
		for (int i = 0; i < 8; i++) {
			udp_header_.push_back(data[i]);
		}
	}
};


class Packet {
	
	L2ProtoEthernet * l2_frame_;
	L3ProtoIPv4 * l3_packet_;
	L4ProtoUDP * l4_datagram_;
	std::vector<unsigned char> data_;

	Packet(unsigned char * data, std::size_t lenght) {
		l2_frame_->set(data);
		
		l3_packet_->set(data+12, 16);
		
		l4_datagram_->set(data+32);
	
	}

	Protocol* l2() {
		return l2_frame_;
	}

};
