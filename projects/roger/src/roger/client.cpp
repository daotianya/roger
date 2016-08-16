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

namespace roger {

	class HttpServer :
		public wawo::net::HttpNode {

		typedef HttpNode::PeerT PeerT;
		typedef HttpNode::PeerEventT PeerEventT;
		typedef HttpNode::MessageT MessageT;
		wawo::Len_CStr m_pac;
	public:

		void SetPac(wawo::Len_CStr const& pac) {
			m_pac = pac;
		}

		void OnPeerMessage( WWRP<PeerEventT> const& pevt) 
		{
			WWSP<MessageT> const& message = pevt->GetIncoming();
			WWRP<PeerT> const& peer = pevt->GetPeer();
			WAWO_ASSERT(message->GetType() == wawo::net::peer::message::Http::T_REQUEST);
			WAWO_INFO("[HttpServer]request url: %s", message->GetUrl().CStr());

			WWSP<wawo::net::peer::message::Http> resp(new wawo::net::peer::message::Http());
			resp->SetCode(200);
			resp->SetStatus("OK");

			wawo::net::peer::http::Version ver = {1,1};
			resp->SetVersion(ver);

			resp->AddHeader("Content-Type", "application/x-ns-proxy-autoconfig");
			resp->AddHeader("Connection", "close");

			wawo::Len_CStr host = message->GetHeader().Get("Host");
			WAWO_ASSERT(host.Len() != 0);

			std::vector<wawo::Len_CStr> host_and_port;
			wawo::split( host,":",host_and_port );
			WAWO_ASSERT(host_and_port.size() == 2);

			int http_addr_pos = wawo::strpos(m_pac.CStr(), "ROGER_HTTP_SERVER_ADDR");
			
			if (http_addr_pos == -1) {
				WAWO_FATAL("[HttpServer] invalid proxy.pac file");
				peer->Close();
				return;
			}

			wawo::Len_CStr new_lcstr;
			new_lcstr = m_pac.Substr(0, http_addr_pos - 0) + host_and_port[0] + m_pac.Substr(http_addr_pos + wawo::strlen("ROGER_HTTP_SERVER_ADDR"), m_pac.Len() - (http_addr_pos + wawo::strlen("ROGER_HTTP_SERVER_ADDR")));
			resp->SetBody(new_lcstr);

			int resprt = peer->Respond(resp, message);
			WAWO_INFO("[HttpServer]resp: %d", resprt);
			peer->Close();
		}
	};


	struct ClientPeerCtx {
		SpinMutex mutex;
		ClientPeerIdT cpeer_id;
		WWRP<RogerEncryptedPeer> rep;
	};

	typedef wawo::net::CargoNode<ClientPeer>		ClientNode;

	typedef ClientNode::PeerEventT CPEvtT;
	typedef RogerEncryptedNode::PeerEventT REPEvtT;

	class Client:
		public ClientNode,
		public RogerEncryptedNode
	{
		enum State {
			S_IDLE,
			S_RUN,
			S_EXIT
		};

	private:
		wawo::thread::SharedMutex m_mutex;
		State m_state;

		SpinMutex m_eps_mutex;
		std::vector< WWRP<RogerEncryptedPeer> > m_eps ;
		u32_t m_max_eps;

		typedef std::map<ClientPeerIdT, WWRP<ClientPeer> > ClientPeersMap;
		typedef std::pair<ClientPeerIdT, WWRP<ClientPeer> > ClientPeerPair;

		SharedMutex m_cps_mutex;
		ClientPeersMap m_cps;

		SocketAddr m_saddr;

	public:
		typedef Listener_Abstract<CPEvtT> CPListenerT;
		typedef Listener_Abstract<REPEvtT> REPListenerT;

		Client( SocketAddr const& server_addr, u32_t const& max_ep ):
			m_state(S_IDLE),
			m_max_eps(max_ep),
			m_saddr(server_addr)
		{}

		virtual ~Client() {
			WAWO_ASSERT( m_state == S_IDLE || m_state == S_EXIT );
		}

		int Start() {
			LockGuard<SharedMutex> lg( m_mutex );

			int bnode_rt = ClientNode::Start();
			if(bnode_rt != wawo::OK ) {
				ClientNode::Stop();
				return bnode_rt;
			}

			int repp_rt = RogerEncryptedNode::Start();
			if( repp_rt != wawo::OK ) {
				ClientNode::Stop();
				RogerEncryptedNode::Stop();
				return repp_rt;
			}

			int rt = InitEp();

			WAWO_RETURN_V_IF_NOT_MATCH(rt, rt == wawo::OK);
			m_state = S_RUN;

			return wawo::OK;
		}

		int InitEp() {
			LockGuard<SpinMutex> lg_eps( m_eps_mutex );
			while( m_eps.size() < m_max_eps ) {
				int rt = _ConnectOneEp();

				wawo::sleep(64);
				//WAWO_RETURN_V_IF_NOT_MATCH(rt, rt==wawo::OK);
			}

			return wawo::OK;
		}

		int _ConnectOneSocket( WWRP<RogerEncryptedPeer> const& ep, super_cargo::PoolType const& t ) {
			WWRP<Socket> bsocket(new Socket(m_saddr, GetBufferConfig(ENCRYPT_BUFFER_CFG), F_AF_INET, ST_STREAM, P_TCP));

			int connrt = RogerEncryptedNode::Connect(ep, bsocket);
			if (connrt != wawo::OK) {
				return connrt;
			}

			int tndrt = bsocket->TurnOnNoDelay();
			if (tndrt != wawo::OK) {
				ep->Close();
				return tndrt;
			}
			ep->AttachSocket(bsocket);

			int joinrt = ep->Socket_SndJoin(bsocket,t);
			if (joinrt != wawo::OK) {
				ep->DetachSocket(bsocket);
				return joinrt;
			}

			int tbrt = bsocket->TurnOnNonBlocking();
			if (tbrt != wawo::OK) {
				ep->DetachSocket(bsocket);
				return tbrt;
			}

			KeepAliveVals vals;
			vals.onoff = 1;
			vals.idle = 30 * 1000;
			vals.interval = 3*1000;
			int keepalivert = bsocket->SetKeepAliveVals(vals);

			if (keepalivert != wawo::OK) {
				ep->DetachSocket(bsocket);
				return keepalivert;
			}

			return RogerEncryptedNode::WatchPeerSocket(bsocket, wawo::net::IOE_READ);
		}

#define SUPER_CARGO_PEER_DATA_SOCKETS_COUNT 6
#define SUPER_CARGO_PEER_ARQ_SOCKETS_COUNT 4

		int _ConnectOneEp() {
			WWRP<RogerEncryptedPeer> _ep(new RogerEncryptedPeer());

			for (int i = 0; i < SUPER_CARGO_PEER_DATA_SOCKETS_COUNT; ) {
				int connrt = _ConnectOneSocket(_ep,super_cargo::T_DATA);
				if (connrt == wawo::OK) {
					++i;
				}
			}
			for (int i = 0; i < SUPER_CARGO_PEER_ARQ_SOCKETS_COUNT; ) {
				int connrt = _ConnectOneSocket(_ep, super_cargo::T_ARQ);
				if (connrt == wawo::OK) {
					++i;
				}
			}
			RogerEncryptedNode::AddPeer(_ep);
			RogerEncryptedNode::WatchPeerEvent(_ep, PE_MESSAGE);
			RogerEncryptedNode::WatchPeerEvent(_ep, PE_SOCKET_CONNECTED);
			RogerEncryptedNode::WatchPeerEvent(_ep, PE_SOCKET_RD_SHUTDOWN);
			RogerEncryptedNode::WatchPeerEvent(_ep, PE_SOCKET_WR_SHUTDOWN);
			RogerEncryptedNode::WatchPeerEvent(_ep, PE_SOCKET_CLOSE);
			RogerEncryptedNode::WatchPeerEvent(_ep, PE_CLOSE);
			m_eps.push_back(_ep);

			return wawo::OK;
		}
		
		void Stop() {
			{
				LockGuard<SharedMutex> lg( m_mutex );
				m_state = S_EXIT;
			}
			
			LockGuard<SharedMutex> lg_cps( m_cps_mutex );
			std::for_each( m_cps.begin(), m_cps.end(), [](ClientPeerPair const& pair) {
				ClientPeerIdT cpeer_id = pair.first;
				WWRP<ClientPeer> cpeer = pair.second;

				ClientPeerCtx* cpctx = (ClientPeerCtx*) cpeer->GetContext<ClientPeerCtx>();
				WAWO_DELETE(cpctx);
				cpeer->SetContext<ClientPeerCtx>(NULL);
			});

			ClientNode::Stop();
			RogerEncryptedNode::Stop();

			std::for_each( m_cps.begin(), m_cps.end(), [this](ClientPeerPair const& pair ) {
				pair.second->UnRegister( WWRP<CPListenerT>(this), true );
			});
			m_cps.clear();

			std::for_each( m_eps.begin(), m_eps.end(), [this](WWRP<RogerEncryptedPeer> const& ep ) {
				ep->UnRegister( WWRP<REPListenerT>(this), true );
			});
			m_eps.clear();
		}

		int StartProxy() {
			SocketAddr laddr( "0.0.0.0", 12122 );
			return ClientNode::StartListen(laddr);
		}

		void OnPeerMessage(WWRP<REPEvtT> const& evt) {

			SharedLockGuard<SharedMutex> lg_state(m_mutex);
			if (m_state != S_RUN) {
				WAWO_FATAL("[roger]service already exit");
				return;
			}

			WWSP<Packet> inpack = evt->GetIncoming()->GetPacket();

			ClientPeerIdT cpeer_id = evt->GetIncoming()->GetStreamId();
			u8_t cmd = evt->GetIncoming()->GetType();

			SharedLockGuard<SharedMutex> slg(m_cps_mutex);
			ClientPeersMap::iterator it = m_cps.find(cpeer_id);
			if (it == m_cps.end()) {
				if (cmd == message::T_CONTENT) {
					WAWO_WARN("[client][%u] roger encrypted peer incoming message, cmd: %d, but no cp found, pack len: %d", cpeer_id, cmd, inpack->Length());
				} else {
					WAWO_WARN("[client][%u] roger encrypted peer incoming message, cmd: %d, but no cp found, pack len: %d", cpeer_id, cmd, 0 );
				}
				return;
			}

			WWRP<ClientPeer> cp = it->second;
			WAWO_ASSERT(cp != NULL);
			ClientPeerCtx* cpctx = (ClientPeerCtx*)cp->GetContext<ClientPeerCtx>();
			LockGuard<SpinMutex> lg(cpctx->mutex);

			switch (cmd) {
			case message::T_FIN:
				{
					WWRP<Socket> socket = cp->GetSocket();
					if (socket != NULL) {
						WAWO_INFO("[client][%u][#%d:%s]receive T_FIN", cpeer_id, socket->GetFd(), socket->GetRemoteAddr().AddressInfo().CStr() );
						socket->Shutdown(SHUTDOWN_WR);
					} else {
						WAWO_WARN("[client][%u]receive T_FIN, no socket found (may detached already)", cpeer_id );
					}
				}
				break;
			case message::T_ACCEPTED:
				{}
				break;
			case message::T_CONTENT:
				{
					WWSP<message::PacketMessage> bp_packet(new message::PacketMessage(inpack));
					int rt = cp->DoSendMessage(bp_packet);
					if (rt != wawo::OK) {
						WAWO_WARN("[client][%u]receive C_CONTENT, but forward to browser failed, close CP, failed code: %d", cpeer_id, rt);
						cp->Close(rt);
					}
				}
				break;
			}
		}


		void OnPeerSocketClose(WWRP<REPEvtT> const& evt) {
			WWSP<super_cargo::SocketPool> skp = evt->GetPeer()->GetSKP();
 			u32_t data_s = skp->GetSocketCount(super_cargo::T_DATA);

			super_cargo::PoolType t;
			if (data_s < SUPER_CARGO_PEER_DATA_SOCKETS_COUNT) {
				t = super_cargo::T_DATA;
			}
			else {
				t = super_cargo::T_ARQ;
			}

			int connrt;
			u64_t try_t = 8; //try 8 seconds
			u64_t begin = wawo::time::curr_seconds();
			u64_t end = begin;

			do {
				connrt = _ConnectOneSocket(evt->GetPeer(), t);
				if (connrt == wawo::OK) {
					break;
				}
				end = wawo::time::curr_seconds();
			} while (((end - begin)<try_t) && (m_state == S_RUN));

			RogerEncryptedNode::NodeAbstractT::OnPeerSocketClose(evt);
		}

		void OnPeerClose(WWRP<REPEvtT> const& evt) {
			SharedLockGuard<SharedMutex> lg_state(m_mutex);
			if (m_state != S_RUN) {
				WAWO_FATAL("[roger]service already exit");
				return;
			}

			WAWO_WARN("[client]ep closed: %d", evt->GetCookie().int32_v);
			LockGuard<SpinMutex> lg_eps(m_eps_mutex);
			std::vector< WWRP<RogerEncryptedPeer> >::iterator it = std::find(m_eps.begin(), m_eps.end(), evt->GetPeer());
			WAWO_ASSERT(it != m_eps.end());
			m_eps.erase(it);

			SharedLockGuard<SharedMutex> lg_cpp(m_cps_mutex);
			std::for_each(m_cps.begin(), m_cps.end(), [this, evt](ClientPeerPair const& pair) {
				ClientPeerCtx* cpctx = (ClientPeerCtx*)pair.second->GetContext<ClientPeerCtx>();
				if (cpctx->rep == evt->GetPeer()) {
					pair.second->Close(evt->GetCookie().int32_v);
				}
			});

			u64_t try_t = 120; //try 60 seconds
			u64_t begin = wawo::time::curr_seconds();
			u64_t end = begin;

			int try_rt = false;
			
			do {
				try_rt = _ConnectOneEp();
				if (try_rt == wawo::OK) {
					break;
				}
				end = wawo::time::curr_seconds();
			} while (((end - begin)<try_t) && (m_state == S_RUN));

			begin = wawo::time::curr_seconds();
			end = begin;

			while ((try_rt == wawo::OK) && (m_eps.size()<m_max_eps) && (end - begin)<120) {
				try_rt = _ConnectOneEp();
				end = wawo::time::curr_seconds();
			}

			if (m_eps.size() == 0) {
				WAWO_THROW_EXCEPTION("!no eps available");
			}
		}

		void OnPeerConnected(WWRP<CPEvtT> const& evt) {

			WAWO_ASSERT(evt->GetPeer() != NULL);

			SharedLockGuard<SharedMutex> lg_state(m_mutex);
			if (m_state != S_RUN) {
				WAWO_FATAL("[roger]service already exit");
				evt->GetPeer()->UnRegister( WWRP<CPListenerT>(this) );
				return;
			}

			WAWO_ASSERT(evt->GetPeer() != NULL);
			LockGuard<SpinMutex> lg_eps(m_eps_mutex);
			if (m_eps.size() == 0) {
				WAWO_FATAL("[roger]no eps available, just return");
				evt->GetPeer()->UnRegister(WWRP<CPListenerT>(this));
				return;
			}

			ClientPeerCtx* cpctx = new ClientPeerCtx();
			WAWO_ASSERT(m_eps.size() > 0);
			static std::atomic<int> rep_idx = 0;
			int idx = wawo::atomic_increment(&rep_idx);
			idx = (idx) % m_eps.size();
			cpctx->rep = m_eps[idx];

			u16_t port = evt->GetSocket()->GetRemoteAddr().GetHostSequencePort();
			u64_t ts = wawo::time::curr_seconds();
			u16_t fs_factor = ts % 0xFFFF;
			u32_t cookie = (fs_factor << 16) | port;

			u32_t stream_id;
			int openrt = cpctx->rep->Stream_Open(cookie,stream_id);
			if ( openrt != wawo::OK ) {
				WAWO_FATAL("[roger] open stream failed: %d", openrt);
				evt->GetPeer()->UnRegister(WWRP<CPListenerT>(this));
				WAWO_DELETE(cpctx);
				return;
			}
			cpctx->cpeer_id = stream_id;
			evt->GetPeer()->SetContext<roger::ClientPeerCtx>(cpctx);
			
			LockGuard<SharedMutex> lg(m_cps_mutex);
			ClientPeerPair pair(cpctx->cpeer_id, evt->GetPeer());
			m_cps.insert(pair);

			WAWO_INFO("[client]new stream %u <---> #%d:%s", stream_id, evt->GetSocket()->GetFd(), evt->GetSocket()->GetRemoteAddr().AddressInfo().CStr());
			ClientNode::NodeAbstractT::OnPeerConnected(evt);
		}

		void OnPeerMessage(WWRP<CPEvtT> const& evt) {
			SharedLockGuard<SharedMutex> lg_state(m_mutex);
			if (m_state != S_RUN) {
				WAWO_FATAL("[roger]service already exit");
				return;
			}

			WAWO_ASSERT(evt->GetIncoming() != NULL);
			WWSP<Packet> inpack = evt->GetIncoming()->GetPacket();

			ClientPeerCtx* cpctx = (ClientPeerCtx*)evt->GetPeer()->GetContext<ClientPeerCtx>();
			WAWO_ASSERT(cpctx != NULL);

			LockGuard<SpinMutex> lg(cpctx->mutex);
			WAWO_ASSERT(cpctx->rep != NULL);
			WAWO_ASSERT(cpctx->cpeer_id != 0);

			int retval;
			EP_SEND_PEER_CLIENT_PACKET(retval, cpctx->rep, cpctx->cpeer_id, inpack);
			if (retval != wawo::OK) {
				WAWO_WARN("[client][%u]stream_closewrite, send xtm to server failed: %d", cpctx->cpeer_id, retval);
				cpctx->rep->Stream_CloseWrite(cpctx->cpeer_id);
				return;
			}
		}

		void OnPeerClose(WWRP<CPEvtT> const& evt) {
			SharedLockGuard<SharedMutex> lg_state(m_mutex);
			if (m_state != S_RUN) {
				WAWO_FATAL("[roger]service already exit");
				return;
			}

			LockGuard<SharedMutex> lg(m_cps_mutex);
			ClientPeerCtx* cpctx = (ClientPeerCtx*)evt->GetPeer()->GetContext<ClientPeerCtx>();
			ClientPeerIdT cpeer_id = cpctx->cpeer_id;
			WAWO_DELETE(cpctx);
			evt->GetPeer()->SetContext<ClientPeerCtx>(NULL);

			ClientPeersMap::iterator it = m_cps.find(cpeer_id);
			WAWO_ASSERT(it != m_cps.end());

			WAWO_INFO("[client]remove stream %u <---> #%d:%s, close code: %d", cpeer_id, evt->GetSocket()->GetFd(), evt->GetSocket()->GetRemoteAddr().AddressInfo().CStr(), evt->GetCookie().int32_v);
			m_cps.erase(it);

			ClientNode::NodeAbstractT::OnPeerClose(evt);
		}

		void OnPeerSocketReadShutdown(WWRP<CPEvtT> const& evt) {
			SharedLockGuard<SharedMutex> lg_state(m_mutex);
			if (m_state != S_RUN) {
				WAWO_FATAL("[roger]service already exit");
				return;
			}

			ClientPeerCtx* cpctx = (ClientPeerCtx*)evt->GetPeer()->GetContext<ClientPeerCtx>();
			WAWO_ASSERT(cpctx != NULL);
			WAWO_ASSERT(cpctx->cpeer_id != 0);
			WAWO_ASSERT(cpctx->rep != NULL);

			int retval;
			retval = cpctx->rep->Stream_CloseWrite(cpctx->cpeer_id);
			WAWO_ASSERT(retval == wawo::OK);
			WAWO_INFO("[client]stream_closewrite %u <---> #%d:%s", cpctx->cpeer_id, evt->GetSocket()->GetFd(), evt->GetSocket()->GetRemoteAddr().AddressInfo().CStr());
		}

		void OnPeerSocketWriteShutdown(WWRP<CPEvtT> const& evt) {
			SharedLockGuard<SharedMutex> lg(m_mutex);
			if (m_state != S_RUN) {
				WAWO_FATAL("[roger]service already exit");
				return;
			}

			ClientPeerCtx* cpctx = (ClientPeerCtx*)evt->GetPeer()->GetContext<ClientPeerCtx>();
			WAWO_ASSERT(cpctx != NULL);

			WAWO_ASSERT(cpctx->cpeer_id != 0);
			WAWO_ASSERT(cpctx->rep != NULL);

			int retval;
			retval = cpctx->rep->Stream_CloseRead(cpctx->cpeer_id);
			WAWO_ASSERT(retval == wawo::OK);
			WAWO_INFO("[client]stream_closeread %u <---> #%d:%s", cpctx->cpeer_id, evt->GetSocket()->GetFd(), evt->GetSocket()->GetRemoteAddr().AddressInfo().CStr());
		}
	};
}

int main(int argc, char** argv) {

	wawo::Len_CStr computer_name;
	WAWO_ENV_INSTANCE->GetLocalComputerName(computer_name);

	WAWO_WARN("[roger]server start...");
	if (argc != 3) {
		WAWO_FATAL("[roger] invalid parameter, usage: roger ip port");
		return -1;
	}

	wawo::net::AddrInfo info;
	info.ip = wawo::Len_CStr( argv[1] );
	info.port = wawo::to_u32(argv[2])&0xFFFF;

	wawo::net::SocketAddr addr( info.ip.CStr(), info.port );
	wawo::app::App app;

	WWRP<roger::Client> node( new roger::Client(addr, 1));
	int start_rt = node->Start();
	if( start_rt != wawo::OK) {
		WAWO_FATAL("[roger]start failed, exiting, ec: %d", start_rt );
		system("pause");
		node->Stop();
		return start_rt;
	}

	int sp_rt = node->StartProxy();
	if( sp_rt != wawo::OK) {
		WAWO_FATAL("[roger]start local proxy failed, exiting, ec: %d", sp_rt );
		system("pause");
		node->Stop();
		return sp_rt;
	}

	
	FILE* fp = fopen("proxy.pac", "rb");
	long begin = ftell(fp);
	int seekrt = fseek(fp, 0L, SEEK_END);
	long end = ftell(fp);
	int seekbeg = fseek(fp, 0L, SEEK_SET);
	WWSP<wawo::algorithm::Packet> pacpack(new wawo::algorithm::Packet(end));
	size_t rbytes = fread((char*)pacpack->Begin(), 1, end, fp);
	pacpack->MoveRight(end);
	wawo::Len_CStr pac((char*)pacpack->Begin(), pacpack->Length());
	WWRP<roger::HttpServer> httpServer( new roger::HttpServer() );
	httpServer->SetPac(pac);

	int httpstartrt = httpServer->Start();
	if (httpstartrt != wawo::OK) {
		WAWO_FATAL("[roger]start httpserver failed: %d, exiting", httpstartrt );
		system("pause");
		node->Stop();
		httpServer->Stop();
		return httpstartrt;
	}

	wawo::net::SocketAddr laddr("0.0.0.0", 8088);

	int listenrt = httpServer->StartListen(laddr);
	if (listenrt != wawo::OK) {
		WAWO_FATAL("[roger]listen http server on addr: %s failed: %d, exiting", laddr.AddressInfo().CStr(), listenrt );
		system("pause");
		node->Stop();
		httpServer->Stop();
		return listenrt;
	}

	app.RunUntil();
	node->Stop();
	httpServer->Stop();
	WAWO_WARN("[roger]server exiting...");
}