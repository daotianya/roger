#ifndef _WAWO_NET_PEER_MESSAGE_STREAM_PACKET_HPP
#define _WAWO_NET_PEER_MESSAGE_STREAM_PACKET_HPP


#include <wawo/algorithm/Packet.hpp>

namespace wawo { namespace net { namespace peer { namespace message {

	using namespace wawo::algorithm;

	enum StreamEventType {
		T_ACCEPTED,
		T_FIN,
		T_CONTENT
	};

	class StreamPacket
	{
		u32_t m_stream_id;
		StreamEventType m_type;
		WWSP<Packet> m_packet;

	public:
		explicit StreamPacket(u32_t const& stream_id, StreamEventType const& t, WWSP<Packet> const& packet) :
			m_stream_id(stream_id),
			m_type(t),
			m_packet(packet)
		{}
		explicit StreamPacket(u32_t const& stream_id, StreamEventType const& t):
			m_stream_id(stream_id),
			m_type(t),
			m_packet(NULL)
		{}
		explicit StreamPacket( u32_t const& stream_id, WWSP<Packet> const& packet):
			m_stream_id(stream_id),
			m_type(T_CONTENT), 
			m_packet(packet)
		{}

		~StreamPacket() {}

		StreamPacket(StreamPacket const& other):
			m_stream_id(other.m_stream_id),
			m_packet(NULL)
		{
			if (other.m_packet != NULL) {
				m_packet = WWSP<Packet>(new Packet(*other.m_packet));
			}
		}

		StreamPacket& operator =(StreamPacket const& other) {
			StreamPacket(other).Swap(*this);
			return *this;
		}

		void Swap(StreamPacket& other) {
			wawo::swap(m_stream_id,other.m_stream_id);
			m_packet.swap(other.m_packet);
		}

		int Encode(WWSP<Packet>& packet_o) {
			WAWO_ASSERT(m_packet != NULL);
			WWSP<Packet> _p(new Packet(*m_packet));
			packet_o = _p;
			return wawo::OK;
		}

		WWSP<Packet> GetPacket() const { return m_packet; }
		u32_t GetStreamId() const { return m_stream_id; }
		StreamEventType GetType() const { return m_type; }
	};

}}}}
#endif