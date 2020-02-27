#pragma once

#include <iostream>
#include <string>
#include <sstream>
#include <vector>
#include <array>
#include <algorithm>
#include <utility>


class Protocol {

public:
	Protocol() = default;
	virtual ~Protocol() = default;

	virtual std::string dstmac() = 0;
	virtual std::string srcmac() = 0;

	virtual std::string scrip() = 0;
	virtual std::string dstip() = 0;

};

class L2ProtoEthernet : public Protocol {
	std::array<unsigned char, 6> dest_mac_;
	std::array<unsigned char, 6> source_mac_;
	std::array<unsigned char, 2> type_;

public:
	L2ProtoEthernet(unsigned char* data) {
		std::copy_n(data, 6, dest_mac_.begin());
		std::copy_n((data + 6), 6, source_mac_.begin());
		std::copy_n((data + 12), 2, type_.begin());
	}

	std::string dstmac() {
		std::stringstream ss;
		ss << std::hex << (int)dest_mac_[0] << " " << (int)dest_mac_[1] << " " <<
			(int)dest_mac_[2] << " " << (int)dest_mac_[3] << " " <<
			(int)dest_mac_[4] << " " <<	(int)dest_mac_[5];
		return std::move(std::string(ss.str()));
	}

	std::string srcmac() {
		std::stringstream ss;
		ss << std::hex << (int)source_mac_[0] << " " << (int)source_mac_[1] << " " <<
			(int)source_mac_[2] << " " << (int)source_mac_[3] << " " <<
			(int)source_mac_[4] << " " << (int)source_mac_[5];
		return std::move(std::string(ss.str()));
	}

	std::string scrip() { return ""; }
	std::string dstip() { return ""; }

};

class L3ProtoIPv4 : public Protocol {
	//std::array<unsigned char, 60> ip_header_;
	char version_;
	char header_size_;
	unsigned char dscp_;
	char ecn_;
	int packet_size_;
	int packet_id_;
	char flags_;
	int offset_;
	unsigned char live_time_;
	unsigned char l4_protocol_;
	int header_check_sum_;
	std::array<unsigned char, 4> src_ip_;
	std::array<unsigned char, 4> dst_ip_;
	std::vector<unsigned char> options_;  //поле может быть пустым

public:
	L3ProtoIPv4(unsigned char* data, std::size_t header_lenght) {
		//std::copy_n(data, header_lenght, ip_header_.begin());
		version_ = (data[0] & 0xF0) >> 4;
		header_size_ = (data[0] & 0x0F);		//размер заголовка в 4-ех байтных "словах"
		dscp_ = data[1] >> 2;
		ecn_ = data[1] & 0b00000011;
		packet_size_ = data[2] * 256 + data[3];
		packet_id_ = data[4] * 256 + data[5];
		flags_ = data[6] >> 5;
		offset_ = (data[6] & 0b00011111) * 256 + data[7];
		live_time_ = data[8];
		l4_protocol_ = data[9];
		header_check_sum_ = data[10] * 256 + data[11];
		std::copy_n(data + 12, 4, src_ip_.begin());
		std::copy_n(data + 16, 4, dst_ip_.begin());
		options_.resize((header_size_ * 4) - 20);
		std::copy_n(data + 20, (header_size_ * 4) - 20, options_.begin());
	}

	std::string scrip() {
		return std::to_string(src_ip_[0]) + "." +
			std::to_string(src_ip_[1]) + "." +
			std::to_string(src_ip_[2]) + "." +
			std::to_string(src_ip_[3]);
	}

	std::string dstip() {
		return std::to_string(dst_ip_[0]) + "." +
			std::to_string(dst_ip_[1]) + "." +
			std::to_string(dst_ip_[2]) + "." +
			std::to_string(dst_ip_[3]);
	}

	virtual std::string dstmac() { return ""; }
	virtual std::string srcmac() { return ""; }

};


class L4ProtoUDP : public Protocol {
	//std::array<unsigned char, 8> udp_header_;
	int source_port_;
	int destination_port_;
	int length_;
	int checksum_;
	std::vector<unsigned char> data_;   // вектор с данным 

public:
	L4ProtoUDP(unsigned char* data) {
	//	std::copy_n(data, 8, udp_header_.begin());
		source_port_ = data[0] * 256 + data[1];
		destination_port_ = data[2] * 256 + data[3];
		length_ = data[4] * 256 + data[5];
		checksum_ = data[6] * 256 + data[7];
		data_.resize(length_ - 8);
		std::copy_n(data + 8, length_ - 8, data_.begin());
	}

	std::string dstmac() { return ""; }
	std::string srcmac() { return ""; }

	std::string scrip() { return ""; }
	std::string dstip() { return ""; }
};

class L4ProtoTCP : public Protocol {
	//std::array<unsigned char, 8> udp_header_;
	int source_port_;
	int destination_port_;
	unsigned long int sequence_number_;
	unsigned long int acknowledgment_number_;
	char offset_;
	unsigned char reserv_;
	unsigned char flags_;
	int window_size_;
	int checksum_;
	int urgent_point_;
	std::vector<unsigned char> options_;  //поле может быть пустым
	std::vector<unsigned char> data_;   // вектор с данным 

public:
	L4ProtoTCP(unsigned char* data, std::size_t length) {
		//std::copy_n(data, 8, udp_header_.begin());
		source_port_ = data[0] * 256 + data[1];
		destination_port_ = data[2] * 256 + data[3];
		sequence_number_ = ((data[4] * 256 + data[5]) * 256 + data[6]) * 256 + data[7];
		acknowledgment_number_ = ((data[8] * 256 + data[9]) * 256 + data[10]) * 256 + data[11];
		offset_ = data[12] >> 4;
		reserv_ = (data[12] & 0b00001111) << 2 + (data[13] & 0b11000000) >> 6;
		flags_ = data[13] & 0b00111111;
		window_size_ = data[14] * 256 + data[15];
		checksum_ = data[16] * 256 + data[17];
		urgent_point_ = data[18] * 256 + data[19];
		options_.resize((offset_ * 4) - 20);
		std::copy_n(data + 20, (offset_ * 4) - 20, options_.begin());
		data_.resize(length - (offset_ * 4));
		std::copy_n(data + (offset_ * 4), length - (offset_ * 4), data_.begin());
	}

	std::string dstmac() { return ""; }
	std::string srcmac() { return ""; }

	std::string scrip() { return ""; }
	std::string dstip() { return ""; }

};


class Packet {

	std::size_t packet_lenght_;					//длинна пакета
	unsigned char* packet_ = nullptr;			//указатель на пакет данных, равен указателю на заголовок 2-го уровня
	std::size_t l2_header_lenght_ = 14;			//длинна заголовка 2-го уровня в байтах
	unsigned char* l3_ip_ = nullptr;			//указатель на залоговок 3-го уровня
	std::size_t l3_header_lenght_;				//длинна заголовка 3-го уровня в байтах
	unsigned char* l4_ = nullptr;				//указатель на залоговок 4-го уровня
	unsigned char l4_type_;						//тип протокола 4-го уровня

	bool l2_chsum_ = true;						//проверка контрольной суммы
	bool l3_chsum_ = true;						//проверка контрольной суммы
	bool l4_chsum_ = true;						//проверка контрольной суммы

	//unsigned char* data_ = nullptr;			//указатель на данные. 

	Packet(const Packet& p) = delete;
	Packet& operator=(const Packet& p) = delete;

public:

	Packet(unsigned char* data, std::size_t lenght) :
		packet_lenght_(lenght),
		packet_(data)
	{
		l3_ip_ = packet_ + l2_header_lenght_;
		l3_header_lenght_ = (packet_[l2_header_lenght_] & 0x0F) * 4;
		l4_ = l3_ip_ + l3_header_lenght_;
		l4_type_ = l3_ip_[9];

		//реализовать подсчет контрольных сумм
	}

	bool is_packet_correct() {
		return (l2_chsum_ && l3_chsum_ && l4_chsum_);
	};

	L2ProtoEthernet* l2() {
		if (l2_chsum_) {
			return new L2ProtoEthernet(packet_);
		}
		else {
			return nullptr;
		}
	}

	Protocol* l3() {
		if (l3_chsum_) {
			return new L3ProtoIPv4(packet_ + l2_header_lenght_, l3_header_lenght_);
		}
		else {
			return nullptr;
		}
	}

	Protocol* l4() {
		if (l4_chsum_) {
			if (l4_type_ == 17) {
				return new L4ProtoUDP(l4_);
			}
			if (l4_type_ == 6) {
				return new L4ProtoTCP(l4_, packet_lenght_ - (l2_header_lenght_ + l3_header_lenght_));
			}
		}
		else {
			return nullptr;
		}
	}

};
