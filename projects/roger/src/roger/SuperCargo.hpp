#ifndef _WAWO_NET_PEER_SUPER_CARGO_HPP
#define _WAWO_NET_PEER_SUPER_CARGO_HPP

#include <atomic>
#include <vector>
#include <list>
#include <map>

#include <wawo.h>
#include "StreamPacket.hpp"

namespace wawo { namespace net { namespace peer {

	namespace super_cargo {

		enum Error {
			E_SUPER_CARGO_PEER_JSP_FAILED = -44000,
			E_SUPER_CARGO_PEER_SOCKET_NOT_ATTACHED = -44001,
			E_SUPER_CARGO_STREAM_NOT_FOUND = -44002,
			E_SUPER_CARGO_STREAM_SYN_FAILED = -44003,
			E_SUPER_CARGO_STREAM_SYN_INVALID_ACK = -44004,
			E_SUPER_CARGO_STREAM_INVALID_STATE = -44005,
			E_SUPER_CARGO_STREAM_READ_ALREADY_CLOSED = -44006,
			E_SUPER_CARGO_STREAM_WRITE_ALREADY_CLOSED = -44007,
			E_SUPER_CARGO_STREAM_ALREADY_CLOSED = -44008,
			E_SUPER_CARGO_STREAM_FIN_IN_BUFFER = -44009,
			E_SUPER_CARGO_NO_SOCKETS_TO_SND = -44010
		};

		const static u32_t SegmentDataSize = (1400 - (12 + 20)); //mss - segment_header - lowwer pakcet header
		const static u32_t MinChokeSize = 12*1024;
		const static u32_t MaxChokeSize = 32*1024;

		typedef u32_t SuperCargoIdT;

		enum PeerFlagBit {
			F_PEER_JIS		= 1<<0, //JOIN JOIN SOCKET
			F_PEER_JIS_RST	= 1<<1,
			F_STREAM_SYN	= 1<<2, //
			F_STREAM_RST	= 1<<3,
			F_STREAM_ACK	= 1<<4,
			F_STREAM_WND	= 1<<5, //update wnd
			F_STREAM_REQ	= 1<<6, //REQUEST SPECIFIED SEGMENT
			F_STREAM_FIN	= 1<<7, //RESET
			F_STREAM_DAT	= 1<<8,
			F_STREAM_RSND	= 1<<9,
			F_SEG_UNIQUE	= 1<<10, //segment flag, unique message
			F_SEG_FIRST		= 1<<11, //segment flag, message begin segment
			F_SEG_MIDDLE	= 1<<12,
			F_SEG_LAST		= 1<<13  //segment flag, message end segment

		};

		struct SegmentHeader {
			u16_t flag;
			u32_t stream_id;
			u32_t seq;
			u32_t ack;
		};

		struct Segment {
			SegmentHeader header;
			WWSP<Packet> data;
			WWRP<Socket> socket;
			u64_t ts;
		};

		enum StreamIO {
			STREAM_READ		= 0x01,
			STREAM_WRITE	= 0x02
		};

		enum PoolType {
			T_HANGING =0,
			T_DATA,
			T_ARQ,
			T_MAX
		};

		enum State {
			S_UNCHOKED,
			S_CHOKED
		};

		struct SocketPool {
			const static int SOCKETS_LIMIT = 32;

			struct SocketCtx {
				wawo::thread::SpinMutex mutex;
				WWRP<Socket> socket;
				u64_t lst_snd_time;
				u64_t lst_choke_time;
				u32_t lst_left_snd_buffer_size;
				u8_t type;
				u8_t state;
				u32_t choke_buffer_size;
			};

			SharedMutex m_mutex;
			WWSP<SocketCtx> m_sockets[SOCKETS_LIMIT];

			std::atomic<u8_t> m_last_sidx[T_MAX];
			u8_t m_sockets_count[T_MAX];
			SocketPool()
			{
				for (int i = 0; i < SOCKETS_LIMIT; i++) {
					m_sockets[i] = NULL;
				}

				for (int i = 0; i < T_MAX; i++) {
					m_last_sidx[i] = 0;
					m_sockets_count[i] = 0;
				}
			}

			~SocketPool() {}

			int SndPacket(WWSP<Packet> const& pack, PoolType const& t) {

				WAWO_ASSERT(t == T_DATA || t == T_ARQ);
				SharedLockGuard<SharedMutex> slg(m_mutex);
				if (m_sockets_count[t] == 0) {
					return wawo::E_PEER_NO_SOCKET_ATTACHED;
				}

				u8_t idx = 0;
				int dosndrt = E_SUPER_CARGO_NO_SOCKETS_TO_SND;

				do {
					u8_t sidx = wawo::atomic_increment(&m_last_sidx[t]) % SOCKETS_LIMIT;
					if (m_sockets[sidx] == NULL) {
						continue;
					}

					LockGuard<SpinMutex> lg(m_sockets[sidx]->mutex);
					if (m_sockets[sidx]->type == t) {
						++idx;

						WAWO_ASSERT(m_sockets[sidx]->socket != NULL);
						WWRP<Socket> const& socket = m_sockets[sidx]->socket;
#if WAWO_ISGNU
						u32_t leftbuffersize;
						int getlrt = socket->GetLeftSndQueue(leftbuffersize);
						if (getlrt<0) {
							WAWO_FATAL("[roger]get socket snd queue failed: %d", getlrt);
							socket->Close(getlrt);
							continue;
						}

						u64_t now = wawo::time::curr_milliseconds();
						if (m_sockets[sidx]->state == S_CHOKED) {

							if (leftbuffersize != 0) {

								u32_t last_snd = (m_sockets[sidx]->lst_left_snd_buffer_size - leftbuffersize);

								if ( (last_snd==0) && ((now - m_sockets[sidx]->lst_choke_time) >= 30000) ) {
									m_sockets[sidx]->socket->Shutdown(wawo::net::SHUTDOWN_RDWR,-999);
									WAWO_FATAL("[roger]close rep for snd choke");
									continue;
								}

								if (m_sockets[sidx]->lst_left_snd_buffer_size < leftbuffersize) {
									char tmp[256] = { 0 };
									snprintf(tmp, sizeof(tmp) / sizeof(tmp[0]), "skp logic issue: lst_left: %u, left: %u", m_sockets[sidx]->lst_left_snd_buffer_size, leftbuffersize );
									WAWO_THROW_EXCEPTION(tmp);
								}

								if (last_snd<(m_sockets[sidx]->lst_left_snd_buffer_size>>1)) {
									m_sockets[sidx]->lst_left_snd_buffer_size = leftbuffersize;
									continue;
								}

								m_sockets[sidx]->state = S_UNCHOKED;
								m_sockets[sidx]->lst_choke_time = 0;
								u32_t choke_size = (m_sockets[sidx]->choke_buffer_size - 1024);
								m_sockets[sidx]->choke_buffer_size = WAWO_MAX(choke_size, MinChokeSize);

								WAWO_WARN("[roger] unchoke socket: #%d:%s, left: %u", socket->GetFd(), socket->GetRemoteAddr().AddressInfo().CStr(), leftbuffersize);
							}
							else {
								m_sockets[sidx]->state = S_UNCHOKED;
								m_sockets[sidx]->lst_choke_time = 0;
								m_sockets[sidx]->choke_buffer_size = MinChokeSize;
								WAWO_WARN("[roger] unchoke socket: #%d:%s, left: %u", socket->GetFd(), socket->GetRemoteAddr().AddressInfo().CStr(), leftbuffersize);
							}
						}
						else {
							if ( (m_sockets[sidx]->lst_left_snd_buffer_size >0) && (leftbuffersize == 0)) {
								u32_t choke_size = (m_sockets[sidx]->choke_buffer_size + 1024);
								m_sockets[sidx]->choke_buffer_size = WAWO_MIN(choke_size, MaxChokeSize);
							} else {

								if (leftbuffersize > m_sockets[sidx]->choke_buffer_size) {
									u32_t last_snd = (m_sockets[sidx]->lst_left_snd_buffer_size - leftbuffersize);
									if ( last_snd<(leftbuffersize>>1) || (leftbuffersize> (MaxChokeSize<<1)) ) {
										m_sockets[sidx]->lst_left_snd_buffer_size = leftbuffersize;
										m_sockets[sidx]->state = S_CHOKED;
										m_sockets[sidx]->lst_choke_time = now;

										WAWO_WARN("[roger] choke socket: #%d:%s, left buffer: %u", socket->GetFd(), socket->GetRemoteAddr().AddressInfo().CStr(), leftbuffersize);
										continue;
									}
								}

								u32_t choke_size = (m_sockets[sidx]->choke_buffer_size - 1024);
								m_sockets[sidx]->choke_buffer_size = WAWO_MAX(choke_size, MinChokeSize);
							}
						}
#endif

						dosndrt = socket->SendPacket(pack, 0);
						if (dosndrt == wawo::OK) {
#if WAWO_ISGNU
							m_sockets[sidx]->lst_snd_time = now;
							m_sockets[sidx]->lst_left_snd_buffer_size = leftbuffersize + pack->Length();
#endif
							break;
						}
						if (dosndrt != wawo::E_SOCKET_SEND_IO_BLOCK) {
							WAWO_DEBUG("[super_cargo][#%d:%s] socket snd failed: %d", socket->GetFd(), socket->GetRemoteAddr().AddressInfo().CStr(), dosndrt);
							socket->Close(dosndrt);
						}
					}

				} while ( (idx<m_sockets_count[t]) );

				return dosndrt;
			}

			void Add(WWRP<Socket> const& socket) {
				WAWO_ASSERT(socket != NULL);

				LockGuard<SharedMutex> lg(m_mutex);
				for (int i = 0; i < SOCKETS_LIMIT; i++) {
					if ( (m_sockets[i] != NULL ) && socket == m_sockets[i]->socket ) {
						WAWO_THROW_EXCEPTION("[socket pool]duplicated socket add for socket pool");
					}
				}

				for (int i = 0; i < SOCKETS_LIMIT; i++) {
					if (m_sockets[i] == NULL) {
						m_sockets[i] = WWSP<SocketCtx>(new SocketCtx());
						m_sockets[i]->socket = socket;
						m_sockets[i]->lst_snd_time = wawo::time::curr_milliseconds();
						m_sockets[i]->lst_choke_time = 0;
						m_sockets[i]->lst_left_snd_buffer_size = 0;
						m_sockets[i]->type = T_HANGING;
						m_sockets[i]->state = S_UNCHOKED;
						m_sockets[i]->choke_buffer_size = MinChokeSize;
						++m_sockets_count[T_HANGING];
						return;
					}
				}

				WAWO_WARN("[socket pool] no available slot, close socket");
				socket->Close(-777);
			}

			void Remove(WWRP<Socket> const& socket) {
				LockGuard<SharedMutex> lg(m_mutex);
				for (int i = 0; i < SOCKETS_LIMIT; i++) {
					if ( (m_sockets[i] != NULL) && m_sockets[i]->socket == socket) {
						--m_sockets_count[m_sockets[i]->type];
						WAWO_DEBUG("[SocketPool] remove socket: %d", i);
						m_sockets[i] = NULL;
						return;
					}
				}

				WAWO_WARN("[socket pool] socket not found in pool");
			}

			void UpdateSocketState(WWRP<Socket> const& socket, PoolType const& type) {
				WAWO_ASSERT(socket != NULL);
				LockGuard<SharedMutex> lg(m_mutex);
				for (int i = 0; i < SOCKETS_LIMIT; i++) {
					if ((m_sockets[i] != NULL) && (m_sockets[i]->socket == socket) ) {
						LockGuard<SpinMutex> lg(m_sockets[i]->mutex);
						if (m_sockets[i]->type != T_HANGING) {
							WAWO_THROW_EXCEPTION("[socket pool] socket invalid pool type");
						}
						m_sockets[i]->type = type;
						++m_sockets_count[type];
						--m_sockets_count[T_HANGING];
						return;
					}
				}
				WAWO_THROW_EXCEPTION("[socket pool] socket not found in pool");
			}

			void GetSockets(std::vector< WWRP<Socket> >& sockets) {
				SharedLockGuard<SharedMutex> slg(m_mutex);
				for (int i = 0; i < SOCKETS_LIMIT; i++) {
					if (m_sockets[i] != NULL && m_sockets[i]->socket != NULL ) {
						sockets.push_back(m_sockets[i]->socket);
					}
				}
			}

			bool HaveSocket(WWRP<Socket> const& socket) {
				SharedLockGuard<SharedMutex> slg(m_mutex);
				for (int i = 0; i < SOCKETS_LIMIT; i++) {
					if ((m_sockets[i] != NULL) && m_sockets[i]->socket == socket) {
						return true;
					}
				}
				return false;
			}

			u8_t GetSocketCount(PoolType const& t) {
				SharedLockGuard<SharedMutex> slg(m_mutex);
				return m_sockets_count[t];
			}
		};
	}
}}}

//asc order
inline bool SegmentSeqLess(WWSP<wawo::net::peer::super_cargo::Segment> const& left, WWSP<wawo::net::peer::super_cargo::Segment> const& right) {
	return left->header.seq < right->header.seq;
}

namespace std {
	inline void swap(WWSP<wawo::net::peer::super_cargo::Segment>& a, WWSP<wawo::net::peer::super_cargo::Segment>& b) {
		wawo::swap(a, b);
	}
}

#define SP_TEST_SEGFLAG(segment,_flag) ((segment).header.flag&_flag)

#define SP_ASSEMBLE_SEGMENT( _flag,_stream_id,_seq,_ack,_data,segment) \
	do { \
		(segment).header.flag =_flag; \
		(segment).header.stream_id = _stream_id; \
		(segment).header.seq = _seq; \
		(segment).header.ack = _ack; \
		(segment).data = _data; \
		(segment).ts = 0; \
	}while(0)

//one seg, one packet
#define SP_SEGMENT_TO_PACKET(segment,packet) \
	do { \
		WAWO_ASSERT(packet != NULL); \
		packet->Write<u16_t>((segment).header.flag); \
		packet->Write<u32_t>((segment).header.stream_id); \
		packet->Write<u32_t>((segment).header.seq); \
		packet->Write<u32_t>((segment).header.ack); \
		(((segment).data != NULL)&&(segment).data->Length())&&packet->Write((segment).data->Begin(), (segment).data->Length()); \
	} while(0)

//one packet , one seg
#define SP_SEGMENT_FROM_PACKET(segment,packet) \
	do { \
		WAWO_ASSERT( packet != NULL ); \
		WAWO_ASSERT(packet->Length() >= sizeof(u16_t)*7 ); \
		(segment).header.flag = packet->Read<u16_t>(); \
		(segment).header.stream_id = packet->Read<u32_t>(); \
		(segment).header.seq = packet->Read<u32_t>(); \
		(segment).header.ack = packet->Read<u32_t>(); \
		(segment).data = packet; \
	} while (0)

namespace wawo { namespace net { namespace peer {

	using namespace super_cargo;

	template <class _TLP>
	class SuperCargo;

	template <class _TLP>
	class SuperCargoPool:
		public wawo::Singleton< SuperCargoPool<_TLP> >
	{
		typedef SuperCargo<_TLP> SuperCargoT;
		typedef std::map<SuperCargoIdT, WWRP<SuperCargoT> > SuperCargoMap;
		typedef std::pair<SuperCargoIdT, WWRP<SuperCargoT> > SuperCargoPair;
	private:
		std::atomic<SuperCargoIdT> m_auto_increment_id;
		SpinMutex		m_super_cargo_peers_mtx;
		SuperCargoMap	m_super_cargo_peers;			//SuperCargo peers

	public:
		SuperCargoPool() :
			m_auto_increment_id(1)
		{
		}

		SuperCargoIdT MakeSuperCargoId() {
			return wawo::atomic_increment<SuperCargoIdT>(&m_auto_increment_id);
		}

		void AddSuperCargo(SuperCargoIdT const& id, WWRP<SuperCargoT> const& SuperCargo) {
			LockGuard<SpinMutex> lg(m_super_cargo_peers_mtx);
			WAWO_ASSERT(id != 0);
			SuperCargoPair pair(id, SuperCargo);
			m_super_cargo_peers.insert(pair);
		}

		WWRP<SuperCargoT> FindSuperCargo(SuperCargoIdT const& id) {
			LockGuard<SpinMutex> lg(m_super_cargo_peers_mtx);
			WAWO_ASSERT(id != 0);
			typename SuperCargoMap::iterator it = m_super_cargo_peers.find(id);
			if (it == m_super_cargo_peers.end()) {
				return NULL;
			}
			return it->second;
		}
	};


	template <class _TLP>
	class SuperCargo:
		public Peer_Abstract,
		public core::Listener_Abstract<SocketEvent>,
		public core::Dispatcher_Abstract< PeerEvent< SuperCargo<_TLP> > >
	{

	public:
		typedef _TLP TLPT;
		typedef SuperCargo<_TLP> MyT;
		typedef SuperCargo<_TLP> SuperCargoT;
		typedef core::Listener_Abstract<SocketEvent> ListenerT;
		typedef core::Dispatcher_Abstract< PeerEvent< MyT > > DispatcherT;

		typedef PeerEvent<MyT> PeerEventT;
		typedef message::StreamPacket MessageT;

		typedef std::vector< WWSP<Segment> > SegmentVector;
		typedef std::list< WWSP<Segment> > SegmentList;

		struct SndState {
			u32_t next; //next sqe to send
			u32_t una;  //unacknowledge seq which has been deliveried
			u32_t wnd;

			u32_t dsn; //data sequence number which used for new segment to delivery

			SegmentVector segments;
		};

		struct RcvState {
			u32_t next; //next seq expected
			u32_t wnd;

			//delivery to upper layer if the segments[0].seq == next
			SegmentList segments;
			SegmentList arqs;
		};

		enum StreamState {
			SS_IDLE,
			SS_SYN_SENT,		//wait ack
			SS_ESTABLISHED,		//read/write ok
			SS_FIN_SENT,		//can only read, call shutdown read,		-> close
			SS_FIN_RECV,		//can only write, call shutdown send(fin)	-> close
			SS_WAIT_CLOSE,
			SS_ERROR,			//
			SS_CLOSED			//could be removed from stream list
		};

		struct Stream:
			public wawo::RefObject_Abstract
		{
			ConditionAny m_cond;
			SpinMutex m_mutex;
			StreamState m_state;
			u8_t m_iocflag; //io close flag

			SndState m_ss;
			RcvState m_rs;

			WWSP<Packet> m_buffer_packet;
			u32_t m_cookie;
			u32_t m_id;
			bool m_need_notify;
			u64_t m_syn_start_timer;
			u64_t m_error_timer;
			u64_t m_arq_timer;
			u64_t m_arq_req_resp_time;

			Stream() :
				m_state(SS_IDLE),
				m_iocflag(0),
				m_cookie(0),
				m_id(0),
				m_need_notify(false),
				m_syn_start_timer(0)
			{
				m_ss.next = 0;
				m_ss.una = 0;
				m_ss.dsn = 0;

				m_rs.next = 0;
			}
			~Stream() {}

			int Open(WWRP<SuperCargoT> const& supercargo, u32_t const& cookie, bool async = false ) {
				LockGuard<SpinMutex> lg(m_mutex);
				WAWO_ASSERT(m_state == SS_IDLE);

				int sndrt = _SndSyn(supercargo,cookie);
				WAWO_RETURN_V_IF_NOT_MATCH(sndrt, sndrt ==wawo::OK);
				m_syn_start_timer = wawo::time::curr_seconds();
				m_state = SS_SYN_SENT;
				WAWO_RETURN_V_IF_MATCH(sndrt, async == true);

				m_need_notify = true;
				m_cond.wait<SpinMutex>(m_mutex);

				if ( (m_rs.segments.size() == 0) || m_state == SS_ERROR) {
					return E_SUPER_CARGO_STREAM_SYN_FAILED;
				}
				WAWO_ASSERT(SS_SYN_SENT == m_state);

				m_rs.segments.sort(SegmentSeqLess);
				WWSP<Segment> synackseg = m_rs.segments.front();
				m_rs.segments.pop_front();
				WAWO_ASSERT(m_cookie == synackseg->header.stream_id);

				if (m_ss.una == synackseg->header.ack) {
					m_iocflag = 0;
					m_state = SS_ESTABLISHED;
					m_rs.next = synackseg->header.seq + 1;
					m_id = synackseg->header.stream_id;
					return wawo::OK;
				}

				return E_SUPER_CARGO_STREAM_SYN_INVALID_ACK;
			}

			int _SndSyn(WWRP<SuperCargoT> const& supercargo, u32_t const& cookie) {
				WAWO_ASSERT( m_cookie > 0 );

				WWSP<Packet> cookie_data(new Packet());
				cookie_data->Write<u32_t>(m_cookie);

				WWSP<Segment> synseg(new Segment());
				SP_ASSEMBLE_SEGMENT(
					F_STREAM_SYN,
					m_cookie,
					m_ss.dsn, //my syn seq
					m_rs.next, //expect to receive ack
					cookie_data,
					*synseg
				);
				m_ss.segments.push_back(synseg);
				int flush_ec;
				int fcount = _FlushSegments(supercargo,flush_ec);

				if ((fcount == 1)&&flush_ec == wawo::OK) {
					m_ss.una = m_ss.dsn;
					m_ss.dsn++;
				} else {
					return flush_ec;
				}

				return flush_ec;
			}

			int _SndARQ( WWSP<SocketPool> const& skp, u32_t const& seq ) {
				WWSP<Packet> seqpack(new Packet() );
				seqpack->Write<u8_t>(1);
				seqpack->Write<u32_t>(seq);
				WWSP<Segment> arqseg(new Segment());
				SP_ASSEMBLE_SEGMENT(
					F_STREAM_REQ,
					m_id,
					m_ss.dsn, //don't ++
					m_rs.next,
					seqpack,
					*arqseg
				);

				return _SndSegment(skp,arqseg);
			}

			int SndPacket(WWSP<Packet> const& packet) {
				LockGuard<SpinMutex> lg(m_mutex);

				if (m_iocflag&STREAM_WRITE) {
					return E_SUPER_CARGO_STREAM_WRITE_ALREADY_CLOSED;
				}

				if (packet->Length() <= SegmentDataSize) {
					WWSP<Segment> segment(new Segment());
					SP_ASSEMBLE_SEGMENT(
						F_STREAM_DAT|F_SEG_UNIQUE,
						m_cookie,
						m_ss.dsn++,
						m_rs.next,
						packet,
						*segment
					);
					m_ss.segments.push_back(segment);
				} else {
					u16_t segment_flag_state = F_SEG_FIRST;
					WAWO_ASSERT(packet->Length() > SegmentDataSize);

					do {

						WWSP<Packet> segpacket(new Packet(1400));
						u32_t cut_size = packet->Length() > SegmentDataSize ? SegmentDataSize : packet->Length();
						u32_t brc = packet->Read(segpacket->Begin(), cut_size);
						WAWO_ASSERT(cut_size == brc);
						segpacket->MoveRight(brc);

						WWSP<Segment> seg(new Segment());

						u16_t curr_segflag;
						if (segment_flag_state == F_SEG_FIRST) {
							curr_segflag = F_SEG_FIRST;
							WAWO_ASSERT(brc == SegmentDataSize);
							segment_flag_state = F_SEG_MIDDLE;
						} else if (segment_flag_state == F_SEG_MIDDLE) {
							if (packet->Length() == 0) {
								curr_segflag = F_SEG_LAST;
							}
							else {
								curr_segflag = F_SEG_MIDDLE;
							}
						} else {}

						SP_ASSEMBLE_SEGMENT(
							F_STREAM_DAT|curr_segflag,
							m_cookie,
							m_ss.dsn++,
							m_rs.next,
							segpacket,
							*seg
						);

						m_ss.segments.push_back(seg);
					} while (packet->Length());
				}

				return wawo::OK;
			}

			int _SndFin() {
				if (m_iocflag&STREAM_WRITE) {
					return E_SUPER_CARGO_STREAM_WRITE_ALREADY_CLOSED;
				}

				WWSP<Segment> synseg(new Segment());
				SP_ASSEMBLE_SEGMENT(
					F_STREAM_FIN,
					m_cookie,
					m_ss.dsn++, //my syn seq
					m_rs.next, //expect to receive ack
					NULL,
					*synseg
				);
				m_ss.segments.push_back(synseg);

				return wawo::OK;
			}

			int CloseRead() {
				LockGuard<SpinMutex> lg(m_mutex);
				if (m_iocflag&STREAM_READ) {
					return E_SUPER_CARGO_STREAM_READ_ALREADY_CLOSED;
				}
				m_iocflag |= STREAM_READ;
				return wawo::OK;
			}

			int CloseWrite() {
				LockGuard<SpinMutex> lg(m_mutex);
				if (m_iocflag&STREAM_WRITE) {
					return E_SUPER_CARGO_STREAM_WRITE_ALREADY_CLOSED;
				}
				int rt = _SndFin();
				WAWO_ASSERT(rt == wawo::OK);
				m_iocflag |= STREAM_WRITE;
				(void)rt;
				return wawo::OK;
			}

			int Close() {
				LockGuard<SpinMutex> lg(m_mutex);
				if (m_iocflag == (STREAM_READ | STREAM_WRITE)) {
					return E_SUPER_CARGO_STREAM_ALREADY_CLOSED;
				}

				if (!(m_iocflag&STREAM_WRITE)) {
					int rt = _SndFin();
					WAWO_ASSERT(rt == wawo::OK);
					m_iocflag |= STREAM_WRITE;
				}
				m_iocflag |= STREAM_READ;

				return wawo::OK;
			}

			int _FlushSegments(WWRP<SuperCargoT> const& supercargo, int& ec_o, u32_t const& max_flushed = 1 ) {

				if (m_ss.segments.size() == 0) {
					ec_o = wawo::OK;
					return 0;
				}
				u32_t flushed = 0;
				WWSP<SocketPool> skp = supercargo->GetSKP();
				SegmentVector::iterator it = m_ss.segments.begin();

				while ( (it != m_ss.segments.end()) &&(flushed<max_flushed) ) {
					if (m_ss.next == (*it)->header.seq) {
						int sndrt = _SndSegment(skp,*it);
						if (sndrt != wawo::OK) {
							ec_o = sndrt;
							break;
						} else {

							(*it)->ts = wawo::time::curr_milliseconds();
							m_ss.next++;
							++flushed;
							ec_o = wawo::OK;

							if (SP_TEST_SEGFLAG( *(*it), F_STREAM_FIN)) {
								if (m_state == SS_ESTABLISHED) {
									m_state = SS_FIN_SENT;
									break;
								}

								if (m_state == SS_FIN_RECV) {
									m_state = SS_WAIT_CLOSE;
									break;
								}
							}
						}
					}
					++it;
				}

				return flushed;
			}

			inline int _SndSegment(WWSP<SocketPool> const& skp, WWSP<Segment> const& segment) {
				WWSP<Packet> packet(new Packet());
				SP_SEGMENT_TO_PACKET(*segment, packet);

				PoolType t= T_DATA;
				if (SP_TEST_SEGFLAG(*segment, F_STREAM_REQ) ||
					SP_TEST_SEGFLAG(*segment, F_STREAM_RSND)
					)
				{
					t = T_ARQ;
				}
#ifdef _DEBUG
				int sndrt = skp->SndPacket(packet,t);
				if (SP_TEST_SEGFLAG(*segment, F_STREAM_REQ)) {
					WAWO_ASSERT(segment->data != NULL);

					WWSP<Packet> arqdatapack(new Packet(*(segment->data)));
					u8_t ct = arqdatapack->Read<u8_t>();
					for (u8_t i = 0; i < ct; i++) {
						u32_t arqseq = arqdatapack->Read<u32_t>();
						WAWO_INFO("[stream][#%u] outgoing REQ<-- (flush): %u, sndrt: %d", m_id, arqseq, sndrt);
					}
				}
				if(SP_TEST_SEGFLAG(*segment, F_STREAM_RSND)) {
					WAWO_INFO("[stream][#%u] outgoing -->REQ (flush): %u, sndrt: %d", m_id, segment->header.seq, sndrt);
				}
				return sndrt;
#else
				return skp->SndPacket(packet,t);
#endif
			}

			void SegmentArrive( WWSP<Segment> const& segment ) {
				LockGuard<SpinMutex> lg(m_mutex);

				if (SP_TEST_SEGFLAG(*segment, F_STREAM_REQ)) {
					WAWO_ASSERT( segment->data != NULL );
#ifdef _DEBUG
					WWSP<Packet> arqdatapack( new Packet( *(segment->data) ) );
					u8_t ct = arqdatapack->Read<u8_t>();
					for (u8_t i = 0; i < ct; i++) {
						u32_t arqseq = arqdatapack->Read<u32_t>();
						WAWO_INFO("[stream][#%u] -->REQ : %u", m_id, arqseq );
					}
#endif
					m_rs.arqs.push_back(segment);
				} else {

//#define _WAWO_DEBUG_RETRANSMIT
#ifdef _WAWO_DEBUG_RETRANSMIT
					u8_t rru = wawo::random_u8();
					if (rru < 6) {
						WAWO_INFO("[stream][#%u] <--REQ (RESP) : %u, drop for: %u", m_id, segment->header.seq, (rru&0xFF) );
						return;
					}
#endif

#ifdef _DEBUG
					if (SP_TEST_SEGFLAG(*segment, F_STREAM_RSND)) {
						WAWO_INFO("[stream][#%u] <--REQ (RESP) : %u", m_id, segment->header.seq );
					}
#endif
					m_rs.segments.push_back(segment);
					if (m_need_notify) {
						m_cond.notify_one();
						m_need_notify = false;
					}
				}
			}

			void Notify() {
				LockGuard<SpinMutex> lg(m_mutex);
				WAWO_ASSERT( m_need_notify );
				m_cond.notify_one();
				m_need_notify = false;
			}

			void _CheckARQ(WWRP<SuperCargoT> const& supercargo) {
				if ((m_rs.arqs.size() != 0) && ( (m_state == SS_ESTABLISHED) || m_state == SS_FIN_SENT || (m_state == SS_FIN_RECV) )) {

					SegmentList::iterator it = m_rs.arqs.begin();
					while (it != m_rs.arqs.end()) {
						WWSP<Segment> segment = (*it);
						WWSP<Packet> packet = segment->data;

						if (packet->Length() <= sizeof(u8_t)) {
							WAWO_THROW_EXCEPTION("invalid arq packet");
						}
						u8_t arqcount = packet->Read<u8_t>();

						u64_t now = wawo::time::curr_milliseconds();
						for (u8_t i = 0; i < arqcount; i++) {
							u32_t arqseq = packet->Read<u32_t>();
							typename SegmentVector::iterator it_to_snd = std::find_if(m_ss.segments.begin(), m_ss.segments.end(), [&arqseq](WWSP<Segment> const& seg) {
								return seg->header.seq == arqseq;
							});

							if (it_to_snd == m_ss.segments.end()) {
								continue;
							}

							(*it_to_snd)->header.flag |= F_STREAM_RSND;

							if ( (now - (*it_to_snd)->ts) > 1000 ) {
								int sndrt = _SndSegment(supercargo->GetSKP(), *it_to_snd);
								WAWO_INFO("[stream][#%u] REQ--> : %u, rt: %d", m_id, arqseq, sndrt);
							}
							else {
								WAWO_INFO("[stream][#%u] (ignore for ts) REQ--> : %u", m_id, arqseq );
							}
						}
						it = m_rs.arqs.erase(it);
					}
				}
			}

			void _AssembleMessages( WWRP<SuperCargoT> const& supercargo ) {

				int segcount = m_rs.segments.size();
				(void)segcount;
				if (m_rs.segments.size() == 0) {
					return;
				}

				m_rs.segments.sort(SegmentSeqLess);
				WWSP<SocketPool> const& skp = supercargo->GetSKP();

				SegmentList::iterator it = m_rs.segments.begin();
				while ( it != m_rs.segments.end() &&
					(m_state == SS_ESTABLISHED || m_state == SS_FIN_SENT|| m_state == SS_ERROR)
				) {

					WWSP<Segment> segment = (*it);
					WWSP<Packet> const& segpack = segment->data;
					WWRP<Socket> const& socket = segment->socket;

					if (segment->header.seq > m_rs.next) {

						u64_t now = wawo::time::curr_milliseconds();
						if (m_state == SS_ESTABLISHED) {
							if ((m_arq_timer == 0)) {
								m_arq_timer = now ;
							} else {
								if ((now - m_arq_timer) > 1000) {
									m_arq_timer = 0;

									for (u32_t i = m_rs.next; i < segment->header.seq;i++) {
										WAWO_INFO("[stream][#%u] REQ<-- : %u", m_id, i );
										int sndarq_rt = _SndARQ(skp, i);
										if (sndarq_rt != wawo::OK) {
											WAWO_INFO("[stream][#%u] REQ<-- : %u failed, rt: %d", m_id, m_rs.next, sndarq_rt);
										}
									}
								}
							}
						}
						break;
					} else if (segment->header.seq == m_rs.next) {

						if (SP_TEST_SEGFLAG(*segment, F_STREAM_RSND)) {
							WAWO_INFO("[stream][#%u] <--REQ (RESP hit): %u", m_id, segment->header.seq);
						}

						m_arq_timer = 0;
						m_rs.next++;
						if (segment->header.ack > m_ss.una) {
							m_ss.una = segment->header.ack;
						}

						if ((m_state != SS_ERROR) && SP_TEST_SEGFLAG(*segment, F_STREAM_DAT)) {
							if (SP_TEST_SEGFLAG(*segment, F_SEG_UNIQUE)) {
								WWSP<MessageT> _m(new MessageT(m_id, segpack));
								WWRP<PeerEventT> pevt(new PeerEventT(PE_MESSAGE, supercargo, socket, _m));
								supercargo->OSchedule(pevt);
							}
							else if (SP_TEST_SEGFLAG(*segment, F_SEG_FIRST)) {
								WAWO_ASSERT(m_buffer_packet == NULL);
								m_buffer_packet = WWSP<Packet>(new Packet());
								m_buffer_packet->Write(segpack->Begin(), segpack->Length());
							}
							else if (SP_TEST_SEGFLAG(*segment, F_SEG_MIDDLE)) {
								WAWO_ASSERT(m_buffer_packet != NULL);
								m_buffer_packet->Write(segpack->Begin(), segpack->Length());
							}
							else if (SP_TEST_SEGFLAG(*segment, F_SEG_LAST)) {
								WAWO_ASSERT(m_buffer_packet != NULL);
								m_buffer_packet->Write(segpack->Begin(), segpack->Length());

								WWSP<MessageT> _m(new MessageT(m_id, m_buffer_packet));
								WWRP<PeerEventT> pevt(new PeerEventT(PE_MESSAGE, supercargo, socket, _m));
								supercargo->OSchedule(pevt);
								m_buffer_packet = NULL;
							}
						}
					} else {
						//ignore
						WAWO_INFO("[stream][#%u] ignore duplicate segment: %u, expect: %u", m_id, segment->header.seq, m_rs.next );
						it = m_rs.segments.erase(it);
						continue;
					}

					if (SP_TEST_SEGFLAG(*segment, F_STREAM_FIN)) {

						if (m_state == SS_ESTABLISHED) {
							m_state = SS_FIN_RECV;
							WWSP<MessageT> _m(new MessageT(m_id, peer::message::T_FIN));
							WWRP<PeerEventT> pevt(new PeerEventT(PE_MESSAGE, supercargo, socket, _m));
							supercargo->OSchedule(pevt);
						}
						else if (m_state == SS_FIN_SENT) {
							m_state = SS_WAIT_CLOSE;
							WWSP<MessageT> _m(new MessageT(m_id, peer::message::T_FIN));
							WWRP<PeerEventT> pevt(new PeerEventT(PE_MESSAGE, supercargo, socket, _m));
							supercargo->OSchedule(pevt);
						}
						else if (m_state == SS_ERROR) {
							m_state = SS_WAIT_CLOSE;
						}
						else {
							//REPLY WITH RST
							WAWO_THROW_EXCEPTION("RST");
						}
					}

					if (SP_TEST_SEGFLAG(*segment, F_STREAM_RST)) {
						WAWO_THROW_EXCEPTION("RST, todo");
					}

					it = m_rs.segments.erase(it);
				}

				{
					SegmentVector::iterator it = m_ss.segments.begin();
					while (it != m_ss.segments.end()) {
						if ((*it)->header.seq < m_ss.una) {
							it = m_ss.segments.erase(it);
						}
						else {
							break;
						}
					}
				}
			}

			int Update( WWRP<SuperCargoT> const& supercargo ) {
				LockGuard<SpinMutex> lg(m_mutex);
				switch (m_state) {
				case SS_IDLE:
					{}
					break;
				case SS_SYN_SENT:
					{
						_CheckARQ(supercargo);
						u64_t now = wawo::time::curr_seconds();
						if ((now - m_syn_start_timer) > 5) {
							m_cond.notify_one();
							int flush_ec;
							_SndFin();
							_FlushSegments(supercargo, flush_ec);
							m_state = SS_ERROR;
							m_error_timer = now;
							m_iocflag = (STREAM_READ | STREAM_WRITE);
						}
					}
					break;
				case SS_ERROR:
					{
						_AssembleMessages(supercargo);
						u64_t now = wawo::time::curr_seconds();
						if ((now - m_error_timer) > 30) {
							m_state = SS_CLOSED;
						}
					}
					break;
				case SS_ESTABLISHED:
					{
						_CheckARQ(supercargo);
						_AssembleMessages(supercargo);
						int flush_ec;
						_FlushSegments(supercargo,flush_ec);
					}
					break;
				case SS_FIN_SENT:
					{
						_CheckARQ(supercargo);
						_AssembleMessages(supercargo);
					}
					break;
				case SS_FIN_RECV:
					{
						_CheckARQ(supercargo);
						int flush_ec;
						_FlushSegments(supercargo,flush_ec);
					}
					break;
				case SS_WAIT_CLOSE:
					{
						if (m_iocflag == (STREAM_READ|STREAM_WRITE)) {
							m_state = SS_CLOSED;
						}
					}
					break;
				case SS_CLOSED:
					{}
					break;
				}

				return m_state;
			}
		};

		typedef SuperCargoPool<_TLP> SuperCargoPoolT;
		SharedMutex m_stream_mutex;
		typedef std::map<u32_t, WWRP<Stream> > StreamMap ;
		typedef std::pair<u32_t, WWRP<Stream> > StreamPair;

	private:
		SuperCargoIdT m_id;
		std::atomic<u32_t> m_cur_stream_id;

		SharedMutex m_mutex;
		WWSP<SocketPool> m_skp; //sockets pool

		SharedMutex m_stream_map_mutex;
		StreamMap m_stream_map;
	public:
		SuperCargo() :
			m_id(0),
			m_cur_stream_id(1),
			m_skp( new SocketPool() )
		{
		}

		explicit SuperCargo(SuperCargoIdT const& id):
			m_id(id)
		{
		}

		virtual ~SuperCargo() {}

		SuperCargoIdT const& GetId() const {
			return m_id;
		}

		void SetId(SuperCargoIdT const& id) {
			m_id = id;
		}

		int Socket_SndJoin(WWRP<Socket> const& socket, PoolType const& t) {

			LockGuard<SharedMutex> lg(m_mutex);
			if( !m_skp->HaveSocket(socket) ) {
				return E_SUPER_CARGO_PEER_SOCKET_NOT_ATTACHED;
			}

			WAWO_ASSERT( socket->IsActive() );
			Segment joinseg;
			WWSP<Packet> data(new Packet());
			data->Write<SuperCargoIdT>(m_id);
			data->Write<u8_t>(t&0xFF);

			SP_ASSEMBLE_SEGMENT(
				super_cargo::F_PEER_JIS,
				0,
				0,
				0,
				data,
				joinseg
			);

			WWSP<Packet> join_pack(new Packet());
			SP_SEGMENT_TO_PACKET(joinseg, join_pack);
			int join_sndrt = socket->SendPacket(join_pack);

			if (socket->IsNonBlocking()) {
				return join_sndrt;
			}

			WWSP<Packet> arrives[1];
			int ec;
			u32_t count = socket->ReceivePackets( arrives, 1, ec );
			WAWO_ASSERT(count == 1);
			WAWO_ASSERT(arrives[0]->Length()>0);

			Segment join_ackseg;
			SP_SEGMENT_FROM_PACKET(join_ackseg, arrives[0]);

			if (!SP_TEST_SEGFLAG(join_ackseg, super_cargo::F_PEER_JIS )) {
				socket->Close(E_SUPER_CARGO_PEER_JSP_FAILED);
				return E_SUPER_CARGO_PEER_JSP_FAILED;
			}

			SuperCargoIdT ack_supid = join_ackseg.data->Read<SuperCargoIdT>();

			if (m_id == 0) {
				//new SuperCargo
				SuperCargoPoolT::GetInstance()->AddSuperCargo(ack_supid, WWRP<MyT>(this) );
				m_id = ack_supid;
			}
			else {
				WAWO_ASSERT(m_id == ack_supid );
			}

			m_skp->UpdateSocketState( socket, t );
			return wawo::OK;
		}

		void UpdateSocketState( WWRP<Socket> const& socket, PoolType t ) {
			SharedLockGuard<SharedMutex> lg(m_mutex);
			m_skp->UpdateSocketState(socket,t);
		}

		int Stream_Open( u32_t const& cookie, u32_t& stream_id_o ) {
			WWRP<Stream> stream(new Stream());
			{
				LockGuard<SharedMutex> lg(m_stream_map_mutex);
				stream->m_cookie = cookie;
				StreamPair pair(cookie, stream);
				WAWO_INFO("[super_cargo] insert stream: %u", cookie );
				m_stream_map.insert(pair);
			}

			int rt = stream->Open( WWRP<SuperCargoT>(this) ,cookie);
			if (rt == wawo::OK) {
				WAWO_ASSERT(stream->m_id != 0);
				stream_id_o = stream->m_id;
			}

			return rt;
		}

		int Stream_Close(u32_t const& stream_id) {
			SharedLockGuard<SharedMutex> lg(m_stream_map_mutex);
			typename StreamMap::iterator it = m_stream_map.find(stream_id);
			if (it == m_stream_map.end()) {
				WAWO_WARN("[super_cargo] stream not found: %u", stream_id);
				return E_SUPER_CARGO_STREAM_NOT_FOUND;
			}
			return it->second->Close();
		}

		int Stream_CloseRead(u32_t const& stream_id) {
			SharedLockGuard<SharedMutex> lg(m_stream_map_mutex);
			typename StreamMap::iterator it = m_stream_map.find(stream_id);

			if (it == m_stream_map.end()) {
				WAWO_WARN("[super_cargo] stream not found: %u", stream_id);
				return E_SUPER_CARGO_STREAM_NOT_FOUND;
			}

			return it->second->CloseRead();
		}

		int Stream_CloseWrite(u32_t const& stream_id) {
			SharedLockGuard<SharedMutex> lg(m_stream_map_mutex);
			typename StreamMap::iterator it = m_stream_map.find(stream_id);
			if (it == m_stream_map.end()) {
				WAWO_WARN("[super_cargo] stream not found: %u", stream_id);
				return E_SUPER_CARGO_STREAM_NOT_FOUND;
			}
			return it->second->CloseWrite();
		}

		int Stream_SndRst(u32_t const& stream_id) {
			WWSP<Segment> rstseg( new Segment() );
			SP_ASSEMBLE_SEGMENT(
				super_cargo::F_STREAM_RST,
				stream_id,
				0,
				0,
				NULL,
				*rstseg
			);

			WWSP<Packet> rstpack(new Packet());
			SP_SEGMENT_TO_PACKET( *rstseg, rstpack);
			SharedLockGuard<SharedMutex> lg(m_mutex);
			return m_skp->SndPacket(rstpack, T_DATA);
		}

		inline WWSP<SocketPool> GetSKP() {
//			SharedLockGuard<SharedMutex> lg(m_mutex);
			return m_skp;
		}

		virtual void AttachSocket(WWRP<Socket> const& socket) {
			LockGuard<SharedMutex> lg(m_mutex);
			WAWO_ASSERT(socket != NULL);

			WWRP<ListenerT> peer_l(this);
			socket->Register(SE_CONNECTED, peer_l);
			socket->Register(SE_PACKET_ARRIVE, peer_l);
			socket->Register(SE_RD_SHUTDOWN, peer_l);
			socket->Register(SE_WR_SHUTDOWN, peer_l);
			socket->Register(SE_CLOSE, peer_l);
			socket->Register(SE_ERROR,peer_l);
			m_skp->Add(socket);
		}

		virtual void DetachSocket(WWRP<Socket> const& socket) {
			LockGuard<SharedMutex> lg(m_mutex);
			WAWO_ASSERT(socket != NULL);
			WWRP<ListenerT> peer_l(this);
			socket->UnRegister(peer_l);
			m_skp->Remove(socket);
		}

		virtual void GetSockets(std::vector< WWRP<Socket> >& sockets) {
			SharedLockGuard<SharedMutex> slg(m_mutex);
			m_skp->GetSockets(sockets);
		}

		virtual bool HaveSocket(WWRP<Socket> const& socket) {
			SharedLockGuard<SharedMutex> slg(m_mutex);
			return m_skp->HaveSocket(socket);
		}

		virtual int Close(int const& close_code = 0) {
			SharedLockGuard<SharedMutex> slg(m_mutex);
			std::vector< WWRP<Socket> > sockets;
			m_skp->GetSockets(sockets);
			if (sockets.size()) {
				std::for_each(sockets.begin(), sockets.end(), [&close_code]( WWRP<Socket> const& s ) {
					s->Close(close_code);
				});
			}
			return wawo::OK;
		}

		virtual void Tick() {
			LockGuard<SharedMutex> lgmap(m_stream_map_mutex);
			typename StreamMap::iterator it = m_stream_map.begin();
			while (it != m_stream_map.end()) {
				int s = it->second->Update( WWRP<SuperCargoT>(this) );
				typename StreamMap::iterator _it = it;
				++it;
				if (s == SS_CLOSED) {
					WAWO_INFO("[super_cargo] erase stream: %u", _it->first );
					m_stream_map.erase(_it);
				}
			}
		}

		int DoSendMessage(WWSP<MessageT> const& message) {
			WAWO_ASSERT(message->GetStreamId() > 0 );
			LockGuard<SharedMutex> lgmap(m_stream_map_mutex);
			typename StreamMap::iterator it = m_stream_map.find(message->GetStreamId());
			if (it == m_stream_map.end()) {
				return E_SUPER_CARGO_STREAM_NOT_FOUND;
			}

			WWSP<Packet> packet_mo;
			int encode_ec = message->Encode(packet_mo);
			WAWO_RETURN_V_IF_NOT_MATCH(encode_ec, encode_ec==wawo::OK);
			return it->second->SndPacket(packet_mo);
		}

		virtual void OnEvent(WWRP<SocketEvent> const& evt) {

			u32_t const& id = evt->GetId();
			int const& ec = evt->GetCookie().int32_v;

			switch (id) {

			case SE_CONNECTED:
				{
					u8_t tos = IPTOS_LOWDELAY | IPTOS_THROUGHPUT;
					int settosrt = evt->GetSocket()->SetTOS(tos);
					if (settosrt != wawo::OK)
					{
						evt->GetSocket()->Close(settosrt);
						WAWO_WARN("[super_cargo] set tos failed: %d", settosrt);
						return ;
					}

					int tnrt = evt->GetSocket()->TurnOnNoDelay();
					if (tnrt != wawo::OK) {
						evt->GetSocket()->Close(tnrt);
						WAWO_WARN("[super_cargo] turn on no delay failed: %d", tnrt );
						return;
					}

					wawo::net::KeepAliveVals vals;
					vals.onoff = 1;
					vals.idle = 30*1000;
					vals.interval = 3*1000;
					vals.probes = 5;

					int kart = evt->GetSocket()->SetKeepAliveVals(vals);
					if (kart != wawo::OK) {
						evt->GetSocket()->Close();
						WAWO_WARN("[super_cargo] turn on keepalive failed: %d", kart);
						return;
					}

					WAWO_ASSERT(HaveSocket(evt->GetSocket())) ;
					WWRP<PeerEventT> pevt1(new PeerEventT(PE_SOCKET_CONNECTED, WWRP<MyT>(this), evt->GetSocket(), ec));
					DispatcherT::OSchedule(pevt1);

					LockGuard<SharedMutex> lg(m_mutex);
					std::vector< WWRP<Socket> > sockets;
					m_skp->GetSockets(sockets);
					if (sockets.size() == 1) {
						WWRP<PeerEventT> pevt2(new PeerEventT(PE_CONNECTED, WWRP<MyT>(this), evt->GetSocket(), ec));
						DispatcherT::OSchedule(pevt2);
					}
				}
				break;
			case SE_PACKET_ARRIVE:
				{
					WWSP<Packet> const& inpack = evt->GetPacket();

					WAWO_ASSERT(inpack != NULL);
					WAWO_ASSERT(inpack->Length()>0);

					WWSP<Segment> in_segment(new Segment());
					SP_SEGMENT_FROM_PACKET(*in_segment, inpack );
#ifdef _DEBUG
					u32_t stream_id = in_segment->header.stream_id;
					if (SP_TEST_SEGFLAG(*in_segment, F_STREAM_REQ)) {
						WAWO_ASSERT(in_segment->data != NULL);
						WWSP<Packet> arqdatapack(new Packet(*(in_segment->data)));
						u8_t ct = arqdatapack->Read<u8_t>();
						for (u8_t i = 0; i < ct; i++) {
							u32_t arqseq = arqdatapack->Read<u32_t>();
							WAWO_INFO("[stream][#%u] incoming -->REQ : %u", stream_id, arqseq);
						}
					}

					if (SP_TEST_SEGFLAG(*in_segment, F_STREAM_RSND)) {
						WAWO_INFO("[stream][#%u] incoming <--REQ (RESP) : %u", stream_id, in_segment->header.seq);
					}
#endif

					if (
						SP_TEST_SEGFLAG(*in_segment, F_STREAM_DAT) ||
						SP_TEST_SEGFLAG(*in_segment, F_STREAM_ACK) ||
						SP_TEST_SEGFLAG(*in_segment, F_STREAM_REQ) ||
						SP_TEST_SEGFLAG(*in_segment, F_STREAM_FIN)
						) {

						SharedLockGuard<SharedMutex> lg(m_stream_map_mutex);
						u32_t const& stream_id = in_segment->header.stream_id;
						typename StreamMap::iterator it = m_stream_map.find(stream_id);
						if (it == m_stream_map.end()) {
							Stream_SndRst(stream_id);
						} else {
							in_segment->socket = evt->GetSocket();
							it->second->SegmentArrive(in_segment);
						}
					}

					if (SP_TEST_SEGFLAG(*in_segment, F_STREAM_SYN)) {
						WAWO_ASSERT(evt->GetSocket()->IsPassive());

						if (in_segment->data == NULL || in_segment->data->Length() != sizeof(u32_t))
						{
							//RST
							WAWO_THROW_EXCEPTION("RST");
							return;
						}

						u32_t cookie = in_segment->header.stream_id;
						LockGuard<SharedMutex> lg(m_stream_map_mutex);
						typename StreamMap::iterator it = m_stream_map.find(cookie);
						WAWO_ASSERT(it == m_stream_map.end() );

						WWRP<Stream> stream(new Stream());

						WWSP<Segment> segment(new Segment());
						SP_ASSEMBLE_SEGMENT(
							F_STREAM_ACK,
							cookie,
							stream->m_ss.dsn,
							in_segment->header.seq,
							NULL,
							*segment
						);

						stream->m_cookie = cookie;
						stream->m_id = cookie;
						stream->m_state = SS_ESTABLISHED;
						(stream->m_ss).una = stream->m_ss.dsn;
						(stream->m_ss).dsn = ((stream->m_ss).dsn + 1);
						(stream->m_ss).next = (stream->m_ss).dsn;
						(stream->m_rs).next = (in_segment->header).seq + 1;

						WWSP<Packet> acksegdata(new Packet());
						SP_SEGMENT_TO_PACKET(*segment, acksegdata);
						int resprt;
						{
							SharedLockGuard<SharedMutex> slg(m_mutex);
							resprt = m_skp->SndPacket(acksegdata, T_DATA );
						}
						//int k = 0;
						//do {
						//	resprt = evt->GetSocket()->SendPacket(acksegdata, 0);
						//	wawo::yield(++k);
						//} while (resprt == wawo::E_SOCKET_SEND_IO_BLOCK);

						if (resprt != wawo::OK) {
							//@todo
							//should iterate other socket for sending,
							//WAWO_THROW_EXCEPTION("resp ack failed");

							WAWO_FATAL("[super_cargo] resp syn ack failed: %d", resprt );
						}

						StreamPair pair(cookie, stream);
						m_stream_map.insert(pair);
						WAWO_INFO("[super_cargo] insert stream: %u", cookie);

						WWSP<MessageT> _m(new MessageT(cookie, peer::message::T_ACCEPTED));
						WWRP<PeerEventT> pevt(new PeerEventT(PE_MESSAGE, WWRP<MyT>(this), evt->GetSocket(), _m));
						DispatcherT::OSchedule(pevt);
					}

					if (SP_TEST_SEGFLAG(*in_segment, F_PEER_JIS)) {

						SuperCargoIdT supid = in_segment->data->Read<SuperCargoIdT>();
						PoolType t = (PoolType)in_segment->data->Read<u8_t>();

						WAWO_ASSERT(t == T_DATA || t== T_ARQ);

						WAWO_ASSERT(evt->GetSocket()->IsPassive());
						WAWO_ASSERT( m_id == 0 );
						WWSP<Packet> ack_pack(new Packet());

						WWRP<MyT> SuperCargo;

						if (supid == 0) {
							SuperCargo = WWRP<MyT>(this);

							SuperCargoIdT new_supid = SuperCargoPoolT::GetInstance()->MakeSuperCargoId();
							WAWO_DEBUG("[super_cargo] new supid: %d", new_supid );

							m_id = new_supid;
							SuperCargoPoolT::GetInstance()->AddSuperCargo(new_supid, WWRP<MyT>(this));

							WWSP<Packet> ack_data(new Packet());
							ack_data->Write<SuperCargoIdT>(new_supid);

							WWSP<Segment> segment(new Segment());
							SP_ASSEMBLE_SEGMENT(
								F_PEER_JIS,
								0,
								0,
								0,
								ack_data,
								*segment
							);
							SP_SEGMENT_TO_PACKET(*segment, ack_pack);
						} else {
							WAWO_ASSERT(supid > 0);
							//find SuperCargo peer by id

							WWSP<Segment> segment( new Segment() );
							WWSP<Packet> ack_data( new Packet() );
							SuperCargo = SuperCargoPoolT::GetInstance()->FindSuperCargo(supid);
							if (SuperCargo == NULL) {
								//send join ack back
								ack_data->Write<SuperCargoIdT>(0);
								SP_ASSEMBLE_SEGMENT(
									F_PEER_JIS_RST,
									0,
									0,
									0,
									ack_data,
									*segment
								);
							} else {
								//send join ack back
								ack_data->Write<SuperCargoIdT>(SuperCargo->GetId());
								SP_ASSEMBLE_SEGMENT(
									F_PEER_JIS,
									0,
									0,
									0,
									ack_data,
									*segment
								);

								SuperCargo->AttachSocket(evt->GetSocket());

								DetachSocket(evt->GetSocket());
								WWRP<PeerEventT> pevt2(new PeerEventT(PE_CLOSE, WWRP<MyT>(this)));
								DispatcherT::OSchedule(pevt2);
							}
							SP_SEGMENT_TO_PACKET(*segment, ack_pack);
						}

						int ack_resprt = evt->GetSocket()->SendPacket(ack_pack);
						(void) ack_resprt;
						if ( (ack_resprt == wawo::OK) && SuperCargo != NULL ) {
							WAWO_ASSERT(SuperCargo != NULL);
							SuperCargo->UpdateSocketState(evt->GetSocket(), t );
						}
					}
				}
				break;
			case SE_RD_SHUTDOWN:
				{
					WWRP<PeerEventT> pevt(new PeerEventT(PE_SOCKET_RD_SHUTDOWN, WWRP<MyT>(this), evt->GetSocket(), ec));
					DispatcherT::OSchedule(pevt);
				}
				break;
			case SE_WR_SHUTDOWN:
				{
					WWRP<PeerEventT> pevt(new PeerEventT(PE_SOCKET_WR_SHUTDOWN, WWRP<MyT>(this), evt->GetSocket(), ec));
					DispatcherT::OSchedule(pevt);
				}
				break;
			case SE_CLOSE:
				{
					DetachSocket(evt->GetSocket());
					WWRP<PeerEventT> pevt1(new PeerEventT(PE_SOCKET_CLOSE, WWRP<MyT>(this), evt->GetSocket(), ec));
					DispatcherT::OSchedule(pevt1);

					SharedLockGuard<SharedMutex> lg(m_mutex);
					std::vector< WWRP<Socket> > sockets;
					m_skp->GetSockets(sockets);
					if (sockets.size() == 0) {
						WWRP<PeerEventT> pevt2(new PeerEventT(PE_CLOSE, WWRP<MyT>(this), evt->GetSocket(), ec));
						DispatcherT::OSchedule(pevt2);

						SharedLockGuard<SharedMutex> stream_lg(m_stream_map_mutex);
						typename StreamMap::iterator it = m_stream_map.begin();
						while (it != m_stream_map.end()) {
							if (it->second->m_need_notify) {
								it->second->Notify();
							}
							++it;
						}
					}
				}
				break;
			case SE_ERROR:
				{
					WWRP<PeerEventT> pevt(new PeerEventT(PE_SOCKET_ERROR, WWRP<MyT>(this), evt->GetSocket(), ec));
					DispatcherT::Trigger(pevt);
				}
				break;
			default:
				{
					char tmp[256] = { 0 };
					snprintf(tmp, sizeof(tmp) / sizeof(tmp[0]), "unknown socket evt: %d", id);
					WAWO_THROW_EXCEPTION(tmp);
				}
				break;
			}
		}
	};

}}}
#endif
