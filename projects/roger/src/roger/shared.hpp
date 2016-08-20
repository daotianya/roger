#ifndef _ROGER_SHARED_HPP
#define _ROGER_SHARED_HPP


#include <wawo.h>
#include "SuperCargo.hpp"

namespace roger {

	using namespace wawo;
	using namespace wawo::algorithm;
	using namespace wawo::net::peer;
	using namespace wawo::net::core;
	using namespace wawo::net;

	int GetLocalIp( char* addr, u32_t size ) {

		std::vector<wawo::net::AddrInfo> ips;
		WAWO_ENV_INSTANCE->GetLocalIpList(ips);

		std::for_each( ips.begin(),ips.end(), []( wawo::net::AddrInfo const ip ) {
			WAWO_WARN("[ips]ip: %s", ip.ip.CStr() );
		});
		WAWO_ASSERT( ips.size() > 0 );

		std::vector<wawo::net::AddrInfo>::iterator it = std::find_if( ips.begin(), ips.end(), [](wawo::net::AddrInfo const& info) {
			if(
				wawo::strncmp(info.ip.CStr(), "112.74.7",8) == 0
			) {
				return true;
			}
			return false;
		});

		if( it == ips.end() ) {
			it = std::find_if( ips.begin(), ips.end(), [](wawo::net::AddrInfo const& info) {
				if (
					wawo::strncmp(info.ip.CStr(), "172.31.31.", 10) == 0 ||
					wawo::strncmp(info.ip.CStr(), "192.168.2.", 10) == 0 ||
					wawo::strncmp(info.ip.CStr(), "192.168.1.", 10) == 0 ||
					wawo::strncmp(info.ip.CStr(), "192.168.0.", 10) == 0 ||
					wawo::strncmp(info.ip.CStr(), "10.", 3) == 0
//					wawo::strncmp(info.ip.CStr() , "192.168.", 8) == 0
				) {
					return true;
				}
				return false;
			});
		}

		WAWO_ASSERT( it != ips.end() );
		WAWO_ASSERT( it->ip.Len() <= size );
		memset( addr, 0, size);
		memcpy( addr,it->ip.CStr(), it->ip.Len());

		return it->ip.Len();
	}


	typedef wawo::net::core::TLP::HLenPacket SLenProtocol;
	typedef wawo::net::peer::Cargo<wawo::net::core::TLP::Stream> ClientPeer;
	typedef wawo::net::peer::Cargo<wawo::net::core::TLP::Stream> ServerPeer;

	typedef SuperCargo<wawo::net::core::TLP::DH_SymmetricEncrypt>	RogerEncryptedPeer;
	typedef wawo::net::CargoNode<RogerEncryptedPeer>				RogerEncryptedNode;
	typedef u32_t ClientPeerIdT;

	typedef u8_t RogerCmdT;
	typedef i32_t RogerErrorCodeT;


	enum Socks5Addressing {
		ADDR_IPV4	= 0x01,
		ADDR_DOMAIN = 0x03,
		ADDR_IPV6	= 0x04
	};

	enum Socks5Cmd {
		S5C_CONNECT		= 0x01,
		S5C_BIND		= 0x02,
		S5C_UDP			= 0x03
	};
	const int ENCRYPT_BUFFER_CFG = wawo::net::SBCT_MEDIUM_UPPER;
}

#define EP_SEND_PACKET(retval,rep,cpeer_id,packet) \
	do { \
		WWSP<wawo::net::peer::message::StreamPacket> _PM( new wawo::net::peer::message::StreamPacket(cpeer_id, packet ) ); \
		retval = rep->DoSendMessage( _PM ); \
		(void) &retval; \
	} while(0)

#define EP_SEND_PEER_CLIENT_PACKET(retval,rep,cpeer_id,packet) EP_SEND_PACKET(retval,rep,cpeer_id, packet)
#define EP_SEND_PEER_SERVER_PACKET(retval,rep,cpeer_id,packet) EP_SEND_PACKET(retval,rep,cpeer_id, packet)

//#define _DEBUG_SOCKET
#endif
