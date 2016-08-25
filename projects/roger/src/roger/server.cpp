#ifdef _DEBUG
	#define VLD_DEBUG_ON 1
#endif

#if defined(WIN32) && defined(VLD_DEBUG_ON) && VLD_DEBUG_ON
	#include <vld.h>
	void _Test_VLD() {
		int* p = new int(12345678);
		*p ++;
	}
#endif

#include "shared.hpp"

using namespace wawo;

namespace roger {

	struct RequestCtx {

		enum ConnFinFlag {
			F_NONE = 0,
			F_CLIENT_FIN = 0x01,
			F_SERVER_FIN = 0x02,
			F_BOTH_FIN = (F_CLIENT_FIN|F_SERVER_FIN)
		};

		enum S5State {
			S5_WAIT_AUTH,
			S5_AUTH_DONE,
			S5_CONNECTED,
			S5_CONNECTING_S5SP,
			S5_BIND,
			S5_ERROR,
			S5_S5SP_CLOSED
		};

		wawo::thread::SpinMutex mutex;
		WWRP<RogerEncryptedPeer> rep;

		ClientPeerIdT cpeer_id;
		roger::RogerErrorCodeT cpeer_fin_ec;

		WWRP<wawo::algorithm::BytesRingBuffer> s5_reqbuffer; //request buffer
		S5State s5_state;
		SocketAddr s5_dst_addr;
		u8_t s5_ver;
		WWRP<ServerPeer> s5_sp;
		int fin_flag; //when fin_flag reach F_FIN_BOTH_SIDE, delete from epctx
		int s5_sp_ec;


		void FlushReqBuffer() {
			WAWO_ASSERT( s5_reqbuffer != NULL );
			WAWO_ASSERT( s5_sp != NULL );
			WAWO_ASSERT( s5_state == RequestCtx::S5_CONNECTED );

			u32_t rbs = s5_reqbuffer->BytesCount();
			if( rbs == 0 ) { return ; }

			WWSP<Packet> outpack( new Packet( rbs ) );
			s5_reqbuffer->Read( outpack->Begin(), rbs );
			outpack->MoveRight(rbs);
			WAWO_ASSERT( s5_reqbuffer->BytesCount() == 0 );

			WWSP<message::PacketMessage> _PM( new message::PacketMessage( outpack ) );
			int srt = s5_sp->DoSendMessage(_PM) ;

			if( srt != wawo::OK ) {
				WAWO_WARN("[server][%u] forward buffer to http server failed: %d, close SP", cpeer_id, srt );
				s5_sp->Close(srt);
			}
		}
	};

	typedef std::map<ClientPeerIdT, WWSP<RequestCtx> > RequestCtxMap;
	typedef std::pair<ClientPeerIdT, WWSP<RequestCtx> > RequestCtxPair;

	struct EpCtx {
		wawo::thread::SharedMutex mutex;
		RequestCtxMap rctxs;
	};

	struct SpCtx {
		WWSP<RequestCtx> rctx;
	};

	typedef wawo::net::CargoNode<ServerPeer> HttpServerNode;

	class Socks5Node :
		public HttpServerNode,
		public RogerEncryptedNode
	{
		enum NodeState {
			S_IDLE,
			S_RUN,
			S_EXIT
		};

		typedef ServerPeer::PeerEventT			HSPEvtT;
		typedef RogerEncryptedPeer::PeerEventT	REPEvtT;

		typedef wawo::net::Listener_Abstract< typename ServerPeer::PeerEventT > HSPListenerT;
		typedef wawo::net::Listener_Abstract< typename RogerEncryptedPeer::PeerEventT> REPListenerT;

		typedef std::vector< WWRP<RogerEncryptedPeer> > RepVec;
		typedef std::vector< WWRP<ServerPeer> > ServerPeersVec;
	private:

		wawo::thread::SharedMutex m_state_mutex;
		NodeState m_state;

		wawo::thread::SpinMutex m_reps_mutex;
		RepVec m_reps;

		wawo::thread::SpinMutex m_sps_mutex;
		ServerPeersVec m_sps;

		wawo::thread::SpinMutex m_sps_connecting_mutex;
		ServerPeersVec m_sps_connecting;

		wawo::net::SocketAddr m_listenaddr;
	public:
		Socks5Node(): m_state(S_IDLE) {}
		~Socks5Node() {}

		int Start( wawo::net::SocketAddr const& listen_addr ) {

			wawo::thread::LockGuard<SharedMutex> lg(m_state_mutex);

            m_listenaddr = listen_addr;

			int prt = HttpServerNode::Start();
			if( prt != wawo::OK ) {
				HttpServerNode::Stop();
				return prt;
			}

			int srt = RogerEncryptedNode::Start();
			if( srt != wawo::OK ) {
				RogerEncryptedNode::Stop();
				HttpServerNode::Stop();
				return srt;
			}

			int lrt = RogerEncryptedNode::StartListen(m_listenaddr, roger::sbc );
			if( lrt != wawo::OK ) {
				RogerEncryptedNode::Stop();
				HttpServerNode::Stop();
                WAWO_INFO("[server] listen on: %s failed, rt: %d", m_listenaddr.AddressInfo().CStr() , lrt );
				return lrt;
			}

			WAWO_INFO("[server] listen on: %s success", m_listenaddr.AddressInfo().CStr() );
			m_state=S_RUN;
			return wawo::OK;
		}

		void Stop() {

			wawo::thread::LockGuard<SharedMutex> lg(m_state_mutex);
			m_state=S_EXIT;

			{
				wawo::thread::LockGuard<SpinMutex> lg_reps(m_reps_mutex);
				std::for_each( m_reps.begin(),m_reps.end(),[](WWRP<RogerEncryptedPeer> const& rep ) {
					rep->Close(-111);
					_HandleREPClose(rep,true);
				});
				m_reps.clear();
			}

			{
				LockGuard<SpinMutex> lg_sps_connecting(m_sps_connecting_mutex);
				std::for_each( m_sps_connecting.begin(), m_sps_connecting.end(), [this](WWRP<ServerPeer> const& sp) {
					SpCtx* spctx = (SpCtx*) sp->GetContext<SpCtx>();
					if( spctx != NULL ) {
						WAWO_DELETE( spctx );
						sp->SetContext<SpCtx>(NULL);
					}
					sp->Close(-112);
				});
				m_sps_connecting.clear();
			}

			{
				LockGuard<SpinMutex> lg_sps(m_sps_mutex);
				std::for_each( m_sps.begin(), m_sps.end(), [this](WWRP<ServerPeer> const& sp) {
					SpCtx* spctx = (SpCtx*) sp->GetContext<SpCtx>();
					if( spctx != NULL ) {
						WAWO_DELETE( spctx );
						sp->SetContext<SpCtx>(NULL);
					}
					sp->Close(-112);
				});
				m_sps.clear();
			}

			RogerEncryptedNode::Stop();
			HttpServerNode::Stop();
		}

		void static _HandleREPClose(WWRP<RogerEncryptedPeer> const& rep, bool delete_sp = false ) {
			EpCtx* epctx = (EpCtx*) rep->GetContext<EpCtx>();
			WAWO_ASSERT( epctx != NULL );
			rep->SetContext<EpCtx>(NULL);

			WAWO_WARN("server", "ep disconneted" );
			std::for_each( epctx->rctxs.begin(), epctx->rctxs.end(), [&]( RequestCtxPair const& pair ) {
				WWSP<RequestCtx> rctx = pair.second;
				if( rctx->s5_sp != NULL ) {
					rctx->s5_sp->Close(wawo::E_SOCKET_FORCE_CLOSE);

					if( delete_sp ) {
						SpCtx* spctx = (SpCtx*) ( rctx->s5_sp->GetContext<SpCtx>() );
						if( spctx != NULL ) {
							WAWO_ASSERT( spctx != NULL );
							WAWO_DELETE( spctx );
							rctx->s5_sp->SetContext<SpCtx>(NULL);
						}
					}
				}
			});

			WAWO_DELETE(epctx);
		}
		void OnPeerMessage(WWRP<HSPEvtT> const& evt) {
			SharedLockGuard<SharedMutex> lg_state(m_state_mutex);
			if (m_state != S_RUN) {
				return;
			}

			SpCtx* spctx = (SpCtx*)evt->GetPeer()->GetContext<SpCtx>();
			WAWO_ASSERT(spctx != NULL);
			WWSP<RequestCtx> rctx = spctx->rctx;
			LockGuard<SpinMutex> lg(rctx->mutex);

			WWSP<message::PacketMessage> incoming = evt->GetIncoming();
			WAWO_ASSERT(incoming != NULL);

			WWSP<Packet> const& inpack = incoming->GetPacket();

			WAWO_ASSERT(rctx != NULL);
			WAWO_ASSERT(rctx->cpeer_id != 0);
			WAWO_ASSERT(rctx->rep != NULL);
			WAWO_ASSERT(rctx->s5_state == RequestCtx::S5_CONNECTED);
			int retval;
			EP_SEND_PEER_SERVER_PACKET(retval, rctx->rep, rctx->cpeer_id, inpack);
			if (retval != wawo::OK) {
				WAWO_WARN("[server][%u]send xtm to client failed: %d", rctx->cpeer_id, retval);
				evt->GetPeer()->Close();
			}
		}

		void OnPeerConnected(WWRP<HSPEvtT> const& evt) {

			SharedLockGuard<SharedMutex> lg_state(m_state_mutex);
			if (m_state != S_RUN) {
				return;
			}

			SpCtx* spctx = (SpCtx*)evt->GetPeer()->GetContext<SpCtx>();
			WAWO_ASSERT(spctx != NULL);
			WWSP<RequestCtx> rctx = spctx->rctx;
			LockGuard<SpinMutex> lg(rctx->mutex);

			WAWO_ASSERT(rctx->s5_sp == evt->GetPeer());
			WAWO_ASSERT(rctx->s5_state == RequestCtx::S5_CONNECTING_S5SP);
			rctx->s5_state = RequestCtx::S5_CONNECTED;

			//resp CONNECT ok
			SocketAddr addr_local = evt->GetSocket()->GetLocalAddr();
			WAWO_INFO("[server][%u][%s]<--->[#%d:%s] new sp connected", rctx->cpeer_id, addr_local.AddressInfo().CStr(), evt->GetSocket()->GetFd(), evt->GetSocket()->GetRemoteAddr().AddressInfo().CStr());

			WWSP<Packet> resppack(new Packet(64));
			resppack->Write<u8_t>(rctx->s5_ver);
			resppack->Write<u8_t>(0);
			resppack->Write<u8_t>(0);
			resppack->Write<u8_t>(ADDR_IPV4);
			resppack->Write<u32_t>(addr_local.GetHostSequenceUlongIp());
			resppack->Write<u16_t>(addr_local.GetHostSequencePort());

			{
				LockGuard<SpinMutex> lg_sps_connecting(m_sps_connecting_mutex);
				ServerPeersVec::iterator it = std::find(m_sps_connecting.begin(), m_sps_connecting.end(), evt->GetPeer());
				WAWO_ASSERT(it != m_sps_connecting.end());
				m_sps_connecting.erase(it);
			}

			{
				LockGuard<SpinMutex> lg_sps(m_sps_mutex);
				ServerPeersVec::iterator it = std::find(m_sps.begin(), m_sps.end(), evt->GetPeer());
				WAWO_ASSERT(it == m_sps.end());
				m_sps.push_back(evt->GetPeer());
			}

			rctx->FlushReqBuffer();
			if (rctx->fin_flag&RequestCtx::F_CLIENT_FIN) {
				evt->GetSocket()->Shutdown(SHUTDOWN_WR, rctx->cpeer_fin_ec);
			}
			int retval;
			EP_SEND_PEER_SERVER_PACKET(retval, rctx->rep, rctx->cpeer_id, resppack);

			if (retval != wawo::OK) {

				rctx->rep->Stream_CloseWrite(rctx->cpeer_id);
				rctx->fin_flag = RequestCtx::F_SERVER_FIN;
				WAWO_INFO("[server][%u]response cmd connect failed, close stream connection", rctx->cpeer_id);

				return;
			}

			HttpServerNode::NodeAbstractT::OnPeerConnected(evt);
		}

		void OnPeerSocketError(WWRP<HSPEvtT> const& evt) {

			SharedLockGuard<SharedMutex> lg_state(m_state_mutex);
			if (m_state != S_RUN) {
				return;
			}

			SpCtx* spctx = (SpCtx*)evt->GetPeer()->GetContext<SpCtx>();
			WAWO_ASSERT(spctx != NULL);
			WWSP<RequestCtx> rctx = spctx->rctx;

			LockGuard<SpinMutex> lg(rctx->mutex);
			WAWO_ASSERT(rctx->s5_state == RequestCtx::S5_CONNECTING_S5SP);
			rctx->s5_state = RequestCtx::S5_ERROR;
			rctx->fin_flag = RequestCtx::F_SERVER_FIN;
			rctx->s5_sp = NULL;

			WAWO_INFO("[server][%u]server peer error: %d, close", rctx->cpeer_id, evt->GetCookie().int32_v);
			evt->GetSocket()->Close();

			int retval;
			retval = rctx->rep->Stream_CloseWrite(rctx->cpeer_id);
			WAWO_ASSERT(retval == wawo::OK);
			(void)retval;

			WAWO_DELETE(spctx);
			evt->GetPeer()->SetContext<SpCtx>(NULL);
			{
				LockGuard<SpinMutex> lg_sps_connecting(m_sps_connecting_mutex);
				ServerPeersVec::iterator it = std::find(m_sps_connecting.begin(), m_sps_connecting.end(), evt->GetPeer());
				WAWO_ASSERT(it != m_sps_connecting.end());
				m_sps_connecting.erase(it);
			}
		}

		void OnPeerSocketReadShutdown(WWRP<HSPEvtT> const& evt) {
			SharedLockGuard<SharedMutex> lg_state(m_state_mutex);
			if (m_state != S_RUN) {
				return;
			}

			SpCtx* spctx = (SpCtx*)evt->GetPeer()->GetContext<SpCtx>();
			WAWO_ASSERT(spctx != NULL);
			WWSP<RequestCtx> rctx = spctx->rctx;
			LockGuard<SpinMutex> lg(rctx->mutex);

			int retval;
			retval = rctx->rep->Stream_CloseWrite(rctx->cpeer_id);
			WAWO_ASSERT(retval == wawo::OK);
			rctx->fin_flag |= RequestCtx::F_SERVER_FIN;
			(void)retval;

		}

		void OnPeerClose(WWRP<HSPEvtT> const& evt) {
			SharedLockGuard<SharedMutex> lg_state(m_state_mutex);
			if (m_state != S_RUN) {
				return;
			}

			SpCtx* spctx = (SpCtx*)evt->GetPeer()->GetContext<SpCtx>();
			WAWO_ASSERT(spctx != NULL);
			WWSP<RequestCtx> rctx = spctx->rctx;
			LockGuard<SpinMutex> lg(rctx->mutex);
			WAWO_INFO("[server][%u]server peer close: %d", rctx->cpeer_id, evt->GetCookie().int32_v);

			rctx->s5_sp = NULL;
			rctx->s5_state = RequestCtx::S5_S5SP_CLOSED;

			int ec = evt->GetCookie().int32_v;
			(void)&ec;

			WAWO_DELETE(spctx);
			evt->GetPeer()->SetContext<SpCtx>(NULL);
			{
				LockGuard<SpinMutex> lg_sps(m_sps_mutex);
				ServerPeersVec::iterator it = std::find(m_sps.begin(), m_sps.end(), evt->GetPeer());
				WAWO_ASSERT(it != m_sps.end());
				m_sps.erase(it);
			}

			HttpServerNode::NodeAbstractT::OnPeerClose(evt);
		}

		int AsyncConnectHost(WWRP<ServerPeer> const& peer, WWRP<Socket> const& bsocket ) {
			WAWO_ASSERT( peer != NULL );
			WAWO_ASSERT( bsocket != NULL );

			WAWO_DEBUG("[server]async connect: %s", bsocket->GetRemoteAddr().AddressInfo().CStr() );
			int rt = HttpServerNode::Connect( peer, bsocket, true );

			WAWO_RETURN_V_IF_NOT_MATCH(rt, rt == wawo::OK );
			LockGuard<SpinMutex> lg_sps_connecting(m_sps_connecting_mutex);
			m_sps_connecting.push_back(peer);
			return rt;
		}

		void OnPeerMessage(WWRP<REPEvtT> const& evt) {
			SharedLockGuard<SharedMutex> lg_state(m_state_mutex);
			if (m_state != S_RUN) {
				return;
			}

			WAWO_ASSERT(evt->GetIncoming() != NULL);
			WWSP<Packet> const& inpack = evt->GetIncoming()->GetPacket();

			ClientPeerIdT cpeer_id = evt->GetIncoming()->GetStreamId();
			int stream_message_type = evt->GetIncoming()->GetType();

			switch (stream_message_type) {
			case message::T_ACCEPTED:
				{
					HandleClientConnected(evt->GetPeer(), cpeer_id);
				}
				break;
			case message::T_FIN:
				{
					HandleClientFin(evt->GetPeer(), cpeer_id, inpack);
				}
				break;
			case message::T_CONTENT:
				{
					HandleClientPacket(evt->GetPeer(), cpeer_id, evt->GetIncoming()->GetPacket() );
				}
				break;
			default:
				{
					WAWO_THROW_EXCEPTION("unknown message type of stream packet");
				}
			}
		}

		void OnPeerConnected(WWRP<REPEvtT> const& evt) {
			SharedLockGuard<SharedMutex> lg_state(m_state_mutex);
			if (m_state != S_RUN) {
				return;
			}

			EpCtx* ctx = evt->GetPeer()->GetContext<EpCtx>();
			WAWO_ASSERT(ctx == NULL);
			ctx = new EpCtx();
			evt->GetPeer()->SetContext<EpCtx>(ctx);
			wawo::thread::LockGuard<wawo::thread::SpinMutex> lg_reps(m_reps_mutex);
			m_reps.push_back(evt->GetPeer());

			WAWO_INFO("roger[###%u]rep connected", evt->GetPeer()->GetId());
			RogerEncryptedNode::NodeAbstractT::OnPeerConnected(evt);
		}

		void OnPeerClose(WWRP<REPEvtT> const& evt) {

			SharedLockGuard<SharedMutex> lg_state(m_state_mutex);
			if (m_state != S_RUN) {
				return;
			}

			_HandleREPClose(evt->GetPeer());
			wawo::thread::LockGuard<SpinMutex> lg_reps(m_reps_mutex);
			RepVec::iterator it = std::find(m_reps.begin(), m_reps.end(), evt->GetPeer());
			WAWO_ASSERT(it != m_reps.end());
			m_reps.erase(it);

			WAWO_INFO("roger[###%u]rep closed", evt->GetPeer()->GetId());
			RogerEncryptedNode::NodeAbstractT::OnPeerClose(evt);
		}

		void HandleClientConnected( WWRP<RogerEncryptedPeer> const& rep, ClientPeerIdT const& cpeer_id ) {

			EpCtx* epctx = (EpCtx*)rep->GetContext<EpCtx>();
			WAWO_ASSERT( epctx != NULL );
			WAWO_ASSERT( cpeer_id != 0 );

			LockGuard<SharedMutex> lg( epctx->mutex );

#ifdef _DEBUG
			RequestCtxMap::iterator it = epctx->rctxs.find(cpeer_id);
			WAWO_ASSERT( it == epctx->rctxs.end() );
#endif
			WWSP<RequestCtx> _rctx( new RequestCtx() );
			_rctx->rep = rep;
			_rctx->cpeer_id = cpeer_id ;
			_rctx->fin_flag = RequestCtx::F_NONE;

			_rctx->s5_reqbuffer = WWRP<wawo::algorithm::BytesRingBuffer>( new wawo::algorithm::BytesRingBuffer(1024*64) );
			_rctx->s5_state = RequestCtx::S5_WAIT_AUTH;
			_rctx->s5_sp_ec = 0;
			_rctx->s5_sp = NULL;

			RequestCtxPair pair(cpeer_id, _rctx);
			epctx->rctxs.insert(pair);
			WAWO_INFO("[server] new cpeer: %u", cpeer_id );
		}

		void HandleClientFin(WWRP<RogerEncryptedPeer> const& rep, ClientPeerIdT const& cpeer_id, WWSP<Packet> const& inpacket ) {

			WAWO_ASSERT(rep != NULL );
			WAWO_ASSERT(cpeer_id != 0);
			WAWO_ASSERT(inpacket == NULL);

			EpCtx* epctx = (EpCtx*)rep->GetContext<EpCtx>();
			WAWO_ASSERT( epctx != NULL );

			LockGuard<SharedMutex> lg_epctx ( epctx->mutex );
			RequestCtxMap::iterator it = epctx->rctxs.find(cpeer_id);
			WAWO_ASSERT( it != epctx->rctxs.end() );

			WWSP<RequestCtx> rctx = it->second;
			WAWO_ASSERT( rctx != NULL );

			wawo::thread::LockGuard<SpinMutex> lg_rctx( rctx->mutex );

			rctx->cpeer_fin_ec = -555;

			rctx->fin_flag |= RequestCtx::F_CLIENT_FIN;

			switch (rctx->s5_state) {
			case RequestCtx::S5_CONNECTED:
				{
					WAWO_ASSERT(rctx->s5_sp != NULL);
					rctx->FlushReqBuffer();
					WWRP<Socket> s5sp_socket = rctx->s5_sp->GetSocket();
					if (s5sp_socket != NULL) {
						s5sp_socket->Shutdown(SHUTDOWN_WR, rctx->cpeer_fin_ec);
					}
				}
				break;
			case RequestCtx::S5_CONNECTING_S5SP:
				{
					WAWO_ASSERT(rctx->s5_sp != NULL);
					WWRP<Socket> s5sp_socket = rctx->s5_sp->GetSocket();
					if (s5sp_socket != NULL) {
						s5sp_socket->Shutdown(SHUTDOWN_WR, rctx->cpeer_fin_ec);
					}
				}
				break;
			case RequestCtx::S5_WAIT_AUTH:
			case RequestCtx::S5_AUTH_DONE:
				{
					WAWO_ASSERT(rctx->s5_sp == NULL);
					WAWO_ASSERT(!(rctx->fin_flag&RequestCtx::F_SERVER_FIN) );
				}
				break;
			case RequestCtx::S5_ERROR:
			case RequestCtx::S5_S5SP_CLOSED:
				{
					WAWO_ASSERT(rctx->fin_flag==RequestCtx::F_BOTH_FIN);
				}
				break;
				case RequestCtx::S5_BIND:
				{
				}
				break;
			}

			int retval;
			retval = rctx->rep->Stream_CloseRead(rctx->cpeer_id);
			WAWO_INFO("[server][%u] stream_closeread, send rt: %d", rctx->cpeer_id, retval);
			WAWO_ASSERT(retval == wawo::OK);


			//static u64_t last_chk_t = wawo::time::curr_seconds();
			//u64_t now = wawo::time::curr_seconds();
			//if( (now-last_chk_t) > 2 ) {
			RequestCtxMap::iterator it_check_fin = epctx->rctxs.begin();
			while( it_check_fin != epctx->rctxs.end() ) {
				RequestCtxMap::iterator _it_check_fin = it_check_fin;
				++it_check_fin;
				if( _it_check_fin->second->fin_flag == RequestCtx::F_BOTH_FIN ) {
					WAWO_INFO("[server] remove cpeer: %u", _it_check_fin->second->cpeer_id);
					epctx->rctxs.erase(_it_check_fin);
				}
			}
			//}
		}

		void HandleClientPacket(WWRP<RogerEncryptedPeer> const& rep, ClientPeerIdT const& cpeer_id, WWSP<Packet> const& inpacket ) {

			WAWO_ASSERT(rep != NULL );
			WAWO_ASSERT(cpeer_id != 0);
			WAWO_ASSERT( inpacket->Length() > 0 );

			EpCtx* epctx = (EpCtx*)rep->GetContext<EpCtx>();
			WAWO_ASSERT( epctx != NULL );

			SharedLockGuard<SharedMutex> lg_epctx ( epctx->mutex );
			RequestCtxMap::iterator it = epctx->rctxs.find(cpeer_id);
			WAWO_ASSERT( it != epctx->rctxs.end() );

			WWSP<RequestCtx> rctx = it->second;
			WAWO_ASSERT( rctx != NULL );

			wawo::thread::LockGuard<SpinMutex> lg_rctx( rctx->mutex );
			WAWO_ASSERT( rctx->s5_reqbuffer->LeftCapacity() >= inpacket->Length() );
			rctx->s5_reqbuffer->Write( inpacket->Begin(), inpacket->Length() );

			switch (rctx->s5_state)
			{
			case RequestCtx::S5_WAIT_AUTH:
				{
					if( rctx->s5_reqbuffer->BytesCount() >= 3 ) {
						//latest firefox ver,,always request with 0x05 0x01 0x00

						wawo::byte_t v_and_nmthods[2];
						rctx->s5_reqbuffer->Peek( v_and_nmthods, 2 );
						u8_t nmethods = (v_and_nmthods[1] & 0xff);

						u32_t hc = nmethods+2;
						if( rctx->s5_reqbuffer->BytesCount() < (hc) ) {
							return ;
						}

						//we always response with 0x05 0x00
						WWSP<Packet> resppack( new Packet(64) );
						resppack->Write<u8_t>(5);
						resppack->Write<u8_t>(0);

						int retval;
						EP_SEND_PEER_SERVER_PACKET( retval, rctx->rep, rctx->cpeer_id, resppack );

						if( retval != wawo::OK ) {
							WAWO_FATAL("[server][%u] response cmd auth failed, %d", rctx->cpeer_id, retval );
							rctx->rep->Stream_CloseWrite(rctx->cpeer_id);
							rctx->fin_flag = RequestCtx::F_SERVER_FIN;
							return ;
						}

						rctx->s5_state = RequestCtx::S5_AUTH_DONE;
						rctx->s5_reqbuffer->Skip(hc);
					}
				}
				break;
			case RequestCtx::S5_AUTH_DONE:
				{
					//check vcra
					// ver
					// cmd
					// rsv
					// atype
					if( rctx->s5_reqbuffer->BytesCount() < 5 ) {
						return ;
					}

					wawo::byte_t vcra[5];
					rctx->s5_reqbuffer->Peek( vcra, 5 );

					u32_t addr_len = 0;
					u32_t rlen = 0;
					if( ((vcra[3])&(0xff)) == ADDR_IPV4 ) {
						//tcp v4
						addr_len = 4;
						rlen = 4 + addr_len + 2;
					} else if( ((vcra[3])&(0xff)) == ADDR_IPV6 ) {
						//tcp v6
						addr_len = 16;
						rlen = 4 + addr_len + 2;
					} else if( ((vcra[3])&(0xff)) == ADDR_DOMAIN ) {
						//domainname
						//first octet is len
						//todo
						//addr_len = 0xFF&

						u8_t dlen = vcra[4]&0xFF;

						//vcra + len + domain
						rlen = 4 + 1 + dlen;
						WAWO_INFO("[server][%u]atype(domain): %d", rctx->cpeer_id, vcra[3] );
					} else {
						WAWO_FATAL("[server][%u]unknown atype: %d", rctx->cpeer_id, vcra[3] );
						return ;
					}

					if( rctx->s5_reqbuffer->BytesCount() < rlen ) {
						return ;
					}

					u8_t ver = rctx->s5_reqbuffer->Read<u8_t>();
					u8_t cmd = rctx->s5_reqbuffer->Read<u8_t>();
					u8_t rsv = rctx->s5_reqbuffer->Read<u8_t>();
					u8_t at  = rctx->s5_reqbuffer->Read<u8_t>();

					(void) &ver;
					(void) &cmd;
					(void) &rsv;
					(void) &at;

					ipv4::Ip dst_addrv4 = 0;
					ipv4::Port dst_port = 0;

					rctx->s5_ver = ver;

					if( at == ADDR_IPV4 ) {
						dst_addrv4 = rctx->s5_reqbuffer->Read<u32_t>();
						dst_port = rctx->s5_reqbuffer->Read<u16_t>();
						SocketAddr addr;

						WAWO_ASSERT( dst_addrv4 != 0 );
						WAWO_ASSERT( dst_port != 0 );

						addr.SetNetSequenceUlongIp( htonl(dst_addrv4) );
						addr.SetNetSequencePort( htons(dst_port) );
						rctx->s5_dst_addr = addr;

					} else if ( at == ADDR_IPV6 ){
						WAWO_THROW_EXCEPTION( "unsupported dst addr format (ADDR_IPV6)" );
					} else if( at == ADDR_DOMAIN ) {
						char domain[128] = {0};

						u8_t dlen = rctx->s5_reqbuffer->Read<u8_t>();
						u8_t drlen = rctx->s5_reqbuffer->Read( (wawo::byte_t*)domain, dlen );
						WAWO_LOG_INFO("[server]CMD: %d, target domain: %s" , cmd, domain );
						dst_port = rctx->s5_reqbuffer->Read<u16_t>();

						SocketAddr addr;

						int filter = AIF_F_INET | AIF_ST_STREAM;
						wawo::Len_CStr ip;
						int gret = GetOneIpAddrByHost(domain, ip, filter );
						if( gret != wawo::OK ) {
							WAWO_FATAL( "[server]Host lookup failed: %d, send close socket", gret );
							int retval;
							retval = rctx->rep->Stream_CloseWrite(cpeer_id);

							rctx->fin_flag = RequestCtx::F_SERVER_FIN;
							rctx->s5_state = RequestCtx::S5_ERROR;

							(void)retval;
							return ;
						}

						int cret = wawo::net::ConvertToNetSequenceUlongIpFromIpAddr(ip.CStr(), dst_addrv4 );
						if( cret != wawo::OK ) {
							WAWO_FATAL( "[server]convert addr from ip to net bytes format failed: %d, send close socket", cret );
							int retval;
							retval = rctx->rep->Stream_CloseWrite(cpeer_id);

							rctx->fin_flag = RequestCtx::F_SERVER_FIN;
							rctx->s5_state = RequestCtx::S5_ERROR;
							(void)retval;

							return ;
						}

						addr.SetNetSequenceUlongIp( (dst_addrv4) );
						addr.SetNetSequencePort(htons(dst_port) );

						rctx->s5_dst_addr = addr;
						WAWO_ASSERT( dst_addrv4 != 0 );

						(void) &drlen;
					} else {
						WAWO_THROW_EXCEPTION( "unsupported dst addr format(UNKNOWN)" );
					}

					switch( cmd ) {
					case S5C_CONNECT:
						{
							WWRP<ServerPeer> s5sp ( new ServerPeer() );
							WAWO_ASSERT( !rctx->s5_dst_addr.IsNullAddr() );

							WWRP<Socket> bsocket( new Socket(rctx->s5_dst_addr, GetBufferConfig(SBCT_MEDIUM), F_AF_INET, ST_STREAM, P_TCP) );

							SpCtx* spctx = new SpCtx();
							WAWO_ASSERT( spctx != NULL );

							spctx->rctx = rctx ;
							s5sp->SetContext(spctx);

							rctx->s5_state = RequestCtx::S5_CONNECTING_S5SP;
							rctx->s5_sp = s5sp;

							int async_conn = AsyncConnectHost( s5sp, bsocket );
							if( async_conn != wawo::OK ) {

								WAWO_DELETE(spctx);
								s5sp->SetContext<SpCtx>(NULL);
								int retval;
								retval = rctx->rep->Stream_CloseWrite(cpeer_id);
								WAWO_INFO("[server][%u][%s] stream_closewrite (async connect server failed: %d)", rctx->cpeer_id, rctx->s5_dst_addr.AddressInfo().CStr(), async_conn);

								rctx->s5_sp = NULL;
								rctx->s5_state = RequestCtx::S5_ERROR;
								rctx->fin_flag = RequestCtx::F_SERVER_FIN;
								rctx->s5_sp_ec = 0;
								(void)retval;
								return ;
							}

							WAWO_INFO("[server][%u][%s] async connecting ...", rctx->cpeer_id, rctx->s5_dst_addr.AddressInfo().CStr() );
							return ;
						}
						break;
					case S5C_BIND:
						{
							WAWO_THROW_EXCEPTION("unsupported cmd (BIND)");
						}
						break;
					case S5C_UDP:
						{
							WAWO_THROW_EXCEPTION("unsupported cmd (S5C_UDP)");
						}
						break;
					default:
						{
							WAWO_THROW_EXCEPTION("unsupported cmd (UNKNOWN)");
							return ;
						}
						break;
					}
				}
				break;
			case RequestCtx::S5_CONNECTING_S5SP:
				{
					break;
				}
				break;
			case RequestCtx::S5_CONNECTED:
				{
					rctx->FlushReqBuffer();
				}
				break;
			default:
				{
					WAWO_FATAL("[roger]unknown s5pctx state: %d", rctx->s5_state );
				}
				break;
			}
		}
	};
}

int main(int argc, char** argv) {
	WAWO_INFO("[roger]server start...");
	{

        wawo::net::SocketAddr listen_addr;
        if( argc != 3 ) {
            WAWO_WARN("[roger] listen address not specified, we'll use 0.0.0.0:12120 ");
            listen_addr = wawo::net::SocketAddr("0.0.0.0",12120 );
        } else {
            wawo::Len_CStr ip(argv[1]);
            wawo::u16_t port = wawo::to_u32(argv[2]) & 0xFFFF;
            listen_addr = wawo::net::SocketAddr(ip.CStr(), port );
        }

		wawo::app::App app;
		WWRP<roger::Socks5Node> node( new roger::Socks5Node() );
		int rt = node->Start(listen_addr);
		(void) &rt;

		WAWO_RETURN_V_IF_NOT_MATCH( rt, rt==wawo::OK );
		app.RunUntil();
		node->Stop();
	}
	WAWO_INFO("[roger]server exiting...");
}
