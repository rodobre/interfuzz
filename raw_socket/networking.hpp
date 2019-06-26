#pragma once

/// Linux low-level socket libraries
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <arpa/inet.h>
#include <features.h>
#include <netinet/ether.h>
#include <unistd.h>

/// Libraries from the C standard
#include <cstring>
#include <cstdint>

/// Libraries from the C++ standard
#include <memory>
#include <string>
#include <vector>

#include "pretty_print.hpp"

typedef int socket_type;
typedef int socket_protocol;

constexpr uint8_t MAC_SIZE = 0x06u;

enum class SocketErrors : uint8_t
{
    CANNOT_CREATE_SOCKET,
    CANNOT_OBTAIN_INTERFACE_IDX,
    CANNOT_BIND_TO_INTERFACE,
    CANNOT_SEND_ENTIRE_PACKET,
    CANNOT_ALLOCATE_BUFFER_MEMORY
};

struct __attribute__ ((packed)) PseudoHeader
{
    uint32_t source_ip;
    uint32_t dest_ip;
    uint8_t reserved;
    uint8_t protocol;
    uint16_t tcp_length;
};

namespace NetworkHelpers
{
    static uint16_t id_datagram = 0;

    /// Compute the IP checksum for the given sequence of bytes
    /// Credits to Richard Stevan
    uint16_t ComputeChecksum(const std::vector<uint8_t>& data)
    {
        long sum = 0;
        uint16_t *temp = (uint16_t*)&data[0];
        ssize_t len = static_cast<ssize_t>(data.size());

        while(len > 1)
        {
            sum += *temp++;
            if(sum & 0x80000000)
                sum = (sum & 0xFFFF) + (sum >> 16);
            len -= 2;
        }

        if(len)
            sum += (uint16_t) *((uint8_t *)temp);

        while(sum >> 16)
            sum = (sum & 0xFFFF) + (sum >> 16);

        return ~sum;
    }

    uint16_t ComputeChecksum(uint8_t* data, ssize_t len, long sum = 0)
    {
        uint16_t *temp = (uint16_t*)data;

        while(len > 1)
        {
            sum += *temp++;
            if(sum & 0x80000000)
                sum = (sum & 0xFFFF) + (sum >> 16);
            len -= 2;
        }

        if(len)
            sum += (uint16_t) *((uint8_t *)temp);

        while(sum >> 16)
            sum = (sum & 0xFFFF) + (sum >> 16);

        return ~sum;
    }

    uint16_t ComputeTCPChecksum(
        const std::shared_ptr<struct iphdr>&    ip_header,
        const std::shared_ptr<struct tcphdr>&   tcp_header,
        const std::vector<uint8_t>&             data
    )
    {
        size_t packet_sz = sizeof(struct tcphdr) + data.size();
        uint8_t* buf = static_cast<uint8_t*>(malloc(packet_sz)), *buf_dup = buf;

        if(buf == nullptr)
            throw SocketErrors::CANNOT_ALLOCATE_BUFFER_MEMORY;

        memset(buf, 0, packet_sz);
        memcpy(buf, tcp_header.get(), sizeof(struct tcphdr));
        memcpy(buf + sizeof(struct tcphdr), &data[0], data.size());

        uint16_t *ip_src = (uint16_t*)&ip_header->saddr, *ip_dst = (uint16_t*)&ip_header->daddr;
        uint16_t sum = 0;
        size_t length = packet_sz;

        sum += *(ip_src++);
        sum += *ip_src;
        sum += *(ip_dst++);
        sum += *ip_dst;
        sum += htons(IPPROTO_TCP);
        sum += htons(length);

        uint16_t checksum = ComputeChecksum(buf, packet_sz, sum) - 1;
        tcp_header->check = checksum;
        free(buf_dup);
        return checksum;
    }

        uint16_t ComputeTCPChecksum(
            uint8_t*                        c_buf,
            size_t                          len
    )
    {
        uint8_t* buf = static_cast<uint8_t*>(malloc(len)), *buf_dup = buf;

        if(buf == nullptr)
            throw SocketErrors::CANNOT_ALLOCATE_BUFFER_MEMORY;

        memcpy(buf, c_buf, len);

        uint16_t *ip_src = (uint16_t*)(c_buf + 26 - sizeof(struct ethhdr)), *ip_dst = (uint16_t*)(c_buf + 30 - sizeof(struct ethhdr));
        uint16_t sum = 0;

        sum += *(ip_src++);
        sum += *ip_src;
        sum += *(ip_dst++);
        sum += *ip_dst;
        sum += htons(IPPROTO_TCP);
        sum += htons(len - sizeof(struct iphdr));

        uint16_t checksum = ComputeChecksum(buf, len, sum) - 0x01;
        free(buf_dup);
        return checksum;
    }

    uint16_t ComputeTCPChecksumSafe(
        const std::shared_ptr<struct iphdr>&    ip_header,
        const std::shared_ptr<struct tcphdr>&   tcp_header,
        const std::vector<uint8_t>&             data
    )
    {
        PseudoHeader pseudo_header;
        pseudo_header.source_ip         = ip_header->saddr;
        pseudo_header.dest_ip           = ip_header->daddr;
        pseudo_header.reserved          = 0x0u;
        pseudo_header.protocol          = IPPROTO_TCP;
        pseudo_header.tcp_length        = htons(sizeof(struct tcphdr) + data.size());

        size_t pseudo_packet_size       = sizeof(PseudoHeader) + sizeof(struct tcphdr) + data.size();
        uint8_t* pseudo_packet          = static_cast<uint8_t*>(malloc(pseudo_packet_size));

        if(pseudo_packet == nullptr)
            throw SocketErrors::CANNOT_ALLOCATE_BUFFER_MEMORY;

        memset(pseudo_packet, 0, pseudo_packet_size);
        memcpy(pseudo_packet, (uint8_t*)&pseudo_header, sizeof(PseudoHeader));
        memcpy(pseudo_packet + sizeof(PseudoHeader), tcp_header.get(), sizeof(struct tcphdr));
        memcpy(pseudo_packet + sizeof(PseudoHeader) + sizeof(struct tcphdr), &data[0], data.size());

        uint16_t checksum = ComputeChecksum(pseudo_packet, pseudo_packet_size);
        free(pseudo_packet);
        tcp_header->check = checksum;
        return checksum;
    }

    std::shared_ptr<struct ethhdr>
    CreateEthernetHeader(const std::string& src_mac, const std::string& dst_mac, int protocol)
    {
        std::shared_ptr<struct ethhdr> eth_header(
            static_cast<struct ethhdr*>(malloc(sizeof(struct ethhdr))),
            [] (struct ethhdr* ptr) -> void { if(ptr != nullptr) free(ptr); }
        );

        // Copy the MAC addresses in the instance fields
        memcpy(eth_header->h_source,    static_cast<void*>(ether_aton(src_mac.c_str())), MAC_SIZE);
        memcpy(eth_header->h_dest,      static_cast<void*>(ether_aton(dst_mac.c_str())), MAC_SIZE);
        eth_header->h_proto = htons(protocol);

        return eth_header;
    }

    std::shared_ptr<struct iphdr>
    CreateIPHeader(const std::string& src_ip, const std::string& dst_ip, uint16_t datalen)
    {
        std::shared_ptr<struct iphdr> ip_header(
            static_cast<struct iphdr*>(malloc(sizeof(struct iphdr))),
            [] (struct iphdr* ptr) -> void { if(ptr != nullptr ) free(ptr); }
        );

        ip_header->version                          = 0x04u;
        ip_header->ihl                              = sizeof(struct iphdr) / 4;
        ip_header->tos                              = 0x0u;
        ip_header->tot_len                          = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + datalen);
        ip_header->id                               = htons(id_datagram++);
        ip_header->frag_off                         = 0x0u;
        ip_header->ttl                              = 0x20u;
        ip_header->protocol                         = IPPROTO_TCP; // default setting for this project
        ip_header->check                            = 0x0u;
        ip_header->saddr                            = inet_addr(src_ip.c_str());
        ip_header->daddr                            = inet_addr(dst_ip.c_str());

        ip_header->check = ComputeChecksum(reinterpret_cast<uint8_t*>(ip_header.get()), ip_header->ihl * 4);
        return ip_header;
    }

    std::shared_ptr<struct tcphdr>
    CreateTCPHeader(uint16_t src_port,      uint16_t dst_port,
                    uint16_t window_size,   uint32_t seq,
                    uint32_t ack_seq)
    {
        std::shared_ptr<struct tcphdr> tcp_header(
            static_cast<struct tcphdr*>(malloc(sizeof(struct tcphdr))),
            [] (struct tcphdr* ptr) { if(ptr != nullptr) free(ptr); }
        );

        tcp_header->source      = htons(src_port);
        tcp_header->dest        = htons(dst_port);
        tcp_header->seq         = htonl(seq);
        tcp_header->ack_seq     = htonl(ack_seq);
        tcp_header->res1        = 0x0u;
        tcp_header->doff        = sizeof(struct tcphdr) / 4;

        // We choose a SYN & RST packet
        tcp_header->syn         = 0x01u;
        tcp_header->rst         = 0x01u;

        tcp_header->window      = htons(window_size);
        tcp_header->check       = 0x0u;
        tcp_header->urg_ptr     = 0x0u;

        return tcp_header;
    }
}

class RawSocket
{
    private:
        socket_type         sock;
        socket_protocol     sock_protocol;

    public:
        RawSocket() noexcept
            :
            sock(),
            sock_protocol()
        {
        }

        RawSocket(const socket_protocol proto)
            :
            sock(),
            sock_protocol()
        {
            sock = socket(PF_PACKET, SOCK_RAW, htons(proto));

            if(sock == -1)
                throw SocketErrors::CANNOT_CREATE_SOCKET;
        }

        ~RawSocket() noexcept
        {
            close(sock);
            sock = 0;
        }

        void BindToInterface(const std::string& interface)
        {
            struct sockaddr_ll socket_addr_lowlevel;
            struct ifreq ifr;

            // Perform zero initialization
            bzero(&socket_addr_lowlevel, sizeof(sockaddr_ll));
            bzero(&ifr, sizeof(ifr));

            strncpy((char*)ifr.ifr_name, interface.c_str(), IFNAMSIZ);

            int interface_idx_status = ioctl(sock, SIOCGIFINDEX, &ifr);
            if(interface_idx_status == -1)
                throw SocketErrors::CANNOT_OBTAIN_INTERFACE_IDX;

            socket_addr_lowlevel.sll_family     = AF_PACKET;
            socket_addr_lowlevel.sll_ifindex    = ifr.ifr_ifindex;
            socket_addr_lowlevel.sll_protocol   = htons(sock_protocol);

            int bind_result = bind(sock, (struct sockaddr*)&socket_addr_lowlevel, sizeof(socket_addr_lowlevel));
            if(bind_result == -1)
                throw SocketErrors::CANNOT_BIND_TO_INTERFACE;
        }

        int64_t WritePacket(const std::vector<uint8_t>& packet)
        {
            ssize_t written_bytes = write(sock, &packet[0], packet.size());
            if(written_bytes != static_cast<ssize_t>(packet.size()))
                return -1;
        }

        int64_t WritePacket(const uint8_t* buf, const ssize_t len)
        {
            ssize_t written_bytes = write(sock, buf, len);
            if(written_bytes != len)
                return -1;
        }
};