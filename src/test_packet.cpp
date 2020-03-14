#define BOOST_TEST_MODULE packet_test_module
#include <vector>
#include "packet.h"
#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(packet_test_suite)

BOOST_AUTO_TEST_CASE(packet_test_udp)
{
    std::vector<unsigned char> vec_udp = { 0xe8, 0x5a, 0xa7, 0x20, 0x10, 0x02, 0x18, 0x31, 0xbf, 0x0c, 0x20, 0x95, 0x08, 0x00, 0x45, 0x00, 0x05, 0x62, 0xc5, 0xb1, 0x40, 0x00, 0x80, 0x11, 0x00, 0x00, 0xc0, 0xa8, 0x0a, 0x02, 0x40, 0xe9, 0xa5, 0x5f, 0xd7, 0x16, 0x01, 0xbb, 0x05, 0x4e, 0xb6,0x52, 0xc3, 0x51, 0x30, 0x34, 0x36, 0x50 , 0xdd, 0x63, 0x56, 0x18, 0xf5, 0x27, 0xf7, 0x2a, 0x00, 0x00, 0x00, 0x01, 0xfb, 0xc0, 0xce, 0xb7, 0xbd, 0x2d, 0x95, 0xa1, 0xcb, 0xe9, 0x02, 0xaf, 0xa0, 0x01, 0x04, 0x00, 0x43, 0x48, 0x4c, 0x4f, 0x19, 0x00, 0x00, 0x00, 0x50, 0x41, 0x44, 0x00, 0xe6, 0x01, 0x00, 0x00, 0x53, 0x4e, 0x49, 0x00, 0xfa, 0x01, 0x00, 0x00, 0x53, 0x54, 0x4b, 0x00, 0x30, 0x02, 0x00, 0x00, 0x56, 0x45, 0x52, 0x00, 0x34, 0x02, 0x00, 0x00, 0x43, 0x43, 0x53, 0x00, 0x44, 0x02, 0x00, 0x00, 0x4e, 0x4f, 0x4e, 0x43, 0x64, 0x02, 0x00, 0x00, 0x41, 0x45, 0x41, 0x44, 0x68, 0x02, 0x00, 0x00, 0x55, 0x41, 0x49, 0x44, 0x98, 0x02, 0x00, 0x00, 0x53, 0x43, 0x49, 0x44, 0xa8, 0x02, 0x00, 0x00, 0x54, 0x43, 0x49, 0x44, 0xac, 0x02, 0x00, 0x00, 0x50, 0x44, 0x4d, 0x44, 0xb0, 0x02, 0x00, 0x00, 0x53, 0x4d, 0x48, 0x4c, 0xb4, 0x02, 0x00, 0x00, 0x49, 0x43, 0x53, 0x4c, 0xb8, 0x02, 0x00, 0x00, 0x4e, 0x4f, 0x4e, 0x50, 0xd8, 0x02, 0x00, 0x00, 0x50, 0x55, 0x42, 0x53, 0xf8, 0x02, 0x00, 0x00, 0x4d, 0x49, 0x44, 0x53
    , 0xfc, 0x02, 0x00, 0x00, 0x53, 0x43, 0x4c, 0x53, 0x00, 0x03, 0x00, 0x00, 0x4b, 0x45, 0x58, 0x53, 0x04, 0x03, 0x00, 0x00, 0x58, 0x4c, 0x43, 0x54, 0x0c, 0x03, 0x00, 0x00, 0x43, 0x53, 0x43, 0x54, 0x0c, 0x03, 0x00, 0x00, 0x43, 0x4f, 0x50, 0x54, 0x14, 0x03, 0x00, 0x00, 0x43, 0x43, 0x52, 0x54, 0x24, 0x03, 0x00, 0x00, 0x49, 0x52, 0x54, 0x54, 0x28, 0x03, 0x00, 0x00, 0x43, 0x46, 0x43, 0x57, 0x2c, 0x03, 0x00, 0x00, 0x53, 0x46, 0x43, 0x57, 0x30, 0x03, 0x00, 0x00, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d
    , 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d
    , 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x66, 0x6f, 0x6e, 0x74, 0x73, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x61, 0x70, 0x69, 0x73, 0x2e, 0x63, 0x6f, 0x6d, 0x36, 0xf5, 0x39, 0xac, 0x11, 0xd7, 0xf3, 0x45, 0x3f, 0x20, 0x23, 0xf3, 0x0c, 0x92, 0x3c, 0xf1, 0x86, 0xc4, 0x8c, 0x99, 0xf8, 0x64, 0xb8, 0xff, 0xf1, 0xe1, 0x6f, 0x66, 0x27, 0x1a, 0x84, 0xfa, 0x72, 0x53, 0xf7, 0xfa, 0x91, 0xb5, 0x36, 0xac, 0xe7, 0x87, 0x7c, 0xe7, 0x84, 0xdd, 0x4a, 0xae, 0x84, 0x2d, 0x17, 0x4e, 0xd1, 0x95, 0x51, 0x30, 0x34, 0x36, 0x01, 0xe8, 0x81, 0x60, 0x92, 0x92, 0x1a, 0xe8, 0x7e, 0xed, 0x80, 0x86, 0xa2, 0x15, 0x82, 0x91, 0x5e, 0x56, 0x2c, 0x97, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x9b, 0x4f, 0x99, 0xd8, 0xb9, 0xdc, 0xf4, 0x64, 0x6c, 0x2d, 0xda, 0x53, 0x24, 0x68, 0x7a, 0x1d, 0x9a, 0x51, 0x44, 0x07, 0x41, 0x45, 0x53, 0x47, 0x43, 0x68, 0x72, 0x6f, 0x6d, 0x65, 0x2f, 0x38, 0x30, 0x2e, 0x30, 0x2e, 0x33, 0x39, 0x38, 0x37, 0x2e, 0x31, 0x32, 0x32, 0x20, 0x57, 0x69, 0x6e, 0x64, 0x6f, 0x77, 0x73, 0x20, 0x4e, 0x54, 0x20, 0x31, 0x30, 0x2e, 0x30, 0x3b, 0x20, 0x57, 0x69, 0x6e, 0x36, 0x34, 0x3b, 0x20, 0x78, 0x36, 0x34, 0x21, 0x80, 0xb6, 0x58, 0x91, 0x73, 0x70, 0x80, 0xd5, 0x20, 0x38, 0x00, 0xb2, 0x17, 0x45, 0x07, 0x00, 0x00, 0x00, 0x00, 0x58, 0x35, 0x30, 0x39, 0x01, 0x00, 0x00, 0x00
    , 0x1e, 0x00, 0x00, 0x00, 0x40, 0x89, 0x20, 0x8f, 0xd0, 0xdf, 0x22, 0xc3, 0xb3, 0x1e, 0x6e, 0xc6, 0xa1, 0x67, 0xeb, 0x41, 0x71, 0xd3, 0x77, 0x96, 0x79, 0x80, 0x9f, 0x3b, 0x7a, 0x46, 0xd3, 0x1e, 0xed, 0x21, 0x04, 0x3e, 0x34, 0xe0, 0x94, 0x41, 0x24, 0x40, 0x13, 0x37, 0x1b, 0xf7, 0x92, 0x00, 0xaf, 0x77, 0xba, 0x6e, 0x88, 0x4c, 0xd7, 0x80, 0x2d, 0xa3, 0x6f, 0x6b, 0x03, 0x14, 0x00, 0x44, 0xf7, 0xc1, 0x0c, 0x33, 0x64, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x43, 0x32, 0x35, 0x35, 0x6d, 0x8c, 0xd3, 0x28, 0x96, 0xae, 0x39, 0x82, 0x35, 0x52, 0x54, 0x4f, 0x41, 0x43, 0x4b, 0x44, 0x6d, 0x8c, 0xd3, 0x28, 0x96, 0xae, 0x39, 0x82, 0x60, 0x32, 0xcb, 0x92, 0xa0, 0x41, 0x4d, 0xdf, 0xf8, 0x5e, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x00, 0x00, 0x00, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    , 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

		
    	Packet p_udp;
	p_udp.parse(vec_udp.data(), vec_udp.size());
	auto l2_udp = p_udp.l2();
   	auto l3_udp = p_udp.l3();
    	auto l4_udp = p_udp.l4();
	
  	BOOST_REQUIRE_EQUAL(l2_udp->name(), "Ethernet_version_2");
	BOOST_REQUIRE_EQUAL(l2_udp->destination()->to_string(),"e8.5a.a7.20.10.2");
	BOOST_REQUIRE_EQUAL(l2_udp->source()->to_string() , "18.31.bf.c.20.95");
		
	BOOST_REQUIRE_EQUAL(l3_udp->name(), "Internet_Protocol_version_4");
	BOOST_REQUIRE_EQUAL(l3_udp->destination()->to_string() , "64.233.165.95");
	BOOST_REQUIRE_EQUAL(l3_udp->source()->to_string(), "192.168.10.2");

	BOOST_REQUIRE_EQUAL(l4_udp->name(), "User_Datagram_Protocol");
	BOOST_REQUIRE_EQUAL(l4_udp->destination()->to_string(), "443");
	BOOST_REQUIRE_EQUAL(l4_udp->source()->to_string() , "55062");
  
   
  //BOOST_REQUIRE_EQUAL(TestString, test);
  //BOOST_CHECK(l2_name && mac_dest && mac_src && l3_name && ip_dest && ip_src && l4_name && port_dest && port_src);
  
}

BOOST_AUTO_TEST_CASE(packet_test_tcp)
{
    std::vector<unsigned char> vec_tcp = { 0xe8, 0x5a, 0xa7, 0x20, 0x10, 0x02, 0x18, 0x31, 0xbf, 0x0c, 0x20, 0x95, 0x08, 0x00, 0x45, 0x00, 0x00, 0x34,
			0x7b, 0xd4, 0x40, 0x00, 0x80, 0x06, 0x00, 0x00, 0xc0, 0xa8, 0x0a, 0x02, 0x0d, 0x21, 0xf2, 0xcc, 0xef, 0x84, 0x01, 0xbb, 0x03, 0x3a, 0xde, 0x04, 0x00,
			0x00, 0x00, 0x00, 0x80, 0x02, 0xfa, 0xf0, 0xca, 0xbe, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4, 0x01, 0x03, 0x03, 0x08, 0x01, 0x01, 0x04, 0x02 };
    
    	Packet p_tcp;
	p_tcp.parse(vec_tcp.data(), vec_tcp.size());
	auto l2_tcp = p_tcp.l2();
    	auto l3_tcp = p_tcp.l3();
    	auto l4_tcp = p_tcp.l4();

   // BOOST_REQUIRE_EQUAL(TestString, test);
    BOOST_CHECK(true);
  
}

BOOST_AUTO_TEST_SUITE_END()
