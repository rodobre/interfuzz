/*
    Driver program for the packet injection
*/

#include "networking.hpp"
#include "fuzzer.hpp"
#include "xorshift_prng.hpp"
#include <mutex>

int main()
{
    try
    {
        RawSocket sock(ETH_P_ALL);
        sock.BindToInterface("enp6s0");

        std::vector<uint8_t> data_to_send({'P', 'W', 'N', 'E', 'D', '!'});

        auto ether_header   = NetworkHelpers::CreateEthernetHeader("aa:aa:aa:aa:aa:aa",
                                         "bb:bb:bb:bb:bb:bb", ETHERTYPE_IP);
        auto ip_header      = NetworkHelpers::CreateIPHeader("192.168.1.2", "192.168.1.3",
                                        data_to_send.size());
        auto tcp_header     = NetworkHelpers::CreateTCPHeader(1337u, 1337u, 1337u, 1337u, 1337u);
        auto checksum       = NetworkHelpers::ComputeTCPChecksum(ip_header, tcp_header, data_to_send);
        
        std::vector<uint8_t> raw_bytes(sizeof(struct iphdr) + sizeof(struct ethhdr)
                                        + sizeof(struct tcphdr), 0u);

        memcpy(&raw_bytes[0], ether_header.get(), sizeof(struct ethhdr));
        memcpy(&raw_bytes[0] + sizeof(struct ethhdr), ip_header.get(), sizeof(struct iphdr));
        memcpy(&raw_bytes[0] + sizeof(struct ethhdr) + sizeof(struct iphdr),  tcp_header.get(),
                tcp_header->doff * 4);
        
        raw_bytes.insert(raw_bytes.end(), data_to_send.begin(), data_to_send.end());

        Fuzzer<struct tcphdr> interfuzzer(
            tcp_header,
            [&sock, raw_bytes, data_to_send]
            (std::shared_ptr<struct tcphdr>& _ptr, size_t sz,
                 uint32_t thr_id, double frequency) -> void
            {
                PrettyPrint::PrintInfo("Thread [%u] is now online.", thr_id);

                const uint64_t random_case_per_test = 0x4000llu;
                int64_t  result                     = 0x0llu;

                std::vector<std::pair<uint8_t, uint8_t>> set_test(
                    {
                        // Ethernet header
                        // proto
                        {12, 14},

                        // IP header
                        // v+ihl    tos     tot_len      id     frag_off    ttl      proto     // chcksum
                        {14, 15}, {15, 16}, {16, 18}, {18, 20}, {20, 22}, {22, 23}, {23, 24}, // {24, 26}
                            
                        // TCP header
                        //s.port  d.port      seq     ack_seq  res1+doff fin/syn/..  wndsz     urgptr   // chcksum
                        {34, 36}, {36, 38}, {38, 42}, {42, 46}, {46, 47}, {47, 48}, {48, 50}, {52, 54} // {50, 52}
                    }
                );

                const uint64_t thread_count         = std::thread::hardware_concurrency();
                const uint64_t bits_to_fuzz         = set_test.size();
                const uint64_t lower_fuzz_bound     = 0llu;
                const uint64_t upper_fuzz_bound     = (1llu << bits_to_fuzz);
                const uint64_t thread_step          = (upper_fuzz_bound - lower_fuzz_bound) / thread_count;
                const uint64_t thread_lower_bound   = (thr_id * thread_step);
                const uint64_t thread_upper_bound   = ((thr_id + 1) * thread_step);
                const uint64_t eth_hdr_size         = sizeof(struct ethhdr);
                const uint64_t ip_hdr_size          = sizeof(struct iphdr);
                const uint64_t tcp_hdr_size         = sizeof(struct tcphdr);
                const uint64_t full_size            = raw_bytes.size();
                const uint64_t tcp_checksum_size    = raw_bytes.size() - eth_hdr_size;

                std::vector<uint8_t> backup_vector  = raw_bytes;

                PrettyPrint::PrintInfo("Thread [%d] preparing to fuzz bit mask [%ull - %ull]",
                                            thr_id, thread_lower_bound, thread_upper_bound);

                uint64_t current_seed = 0x0llu, tmp_bit = 0x0llu, diff = 0x0llu, old_seed = 0x0llu;

                for(uint64_t i = thread_lower_bound; i < thread_upper_bound; ++i)
                {
                    current_seed = XorshiftPRNG::GetRandomBits<uint64_t>(bits_to_fuzz);
                    old_seed = current_seed;
                    backup_vector = raw_bytes;

                    for(uint64_t random_test = 0llu; random_test < random_case_per_test; ++random_test)
                    {
                        current_seed = old_seed;

                        for(uint64_t bit = 0llu; bit < bits_to_fuzz; ++bit)
                        {
                            tmp_bit = current_seed & 1;

                            if(tmp_bit)
                            {
                                auto& fuzz_pair = set_test[bit];
                                diff = fuzz_pair.second - fuzz_pair.first;

                                if(diff == 0x01llu)
                                {
                                    uint8_t fuzz_bytes = XorshiftPRNG::GetRandomByte();
                                    *(uint8_t*)&backup_vector[fuzz_pair.first] = fuzz_bytes;
                                }
                                else if(diff == 0x02llu)
                                {
                                    uint16_t fuzz_bytes = XorshiftPRNG::Get2RandomBytes();
                                    *(uint16_t*)&backup_vector[fuzz_pair.first] = fuzz_bytes;
                                }
                                else if(diff == 0x04llu)
                                {
                                    uint32_t fuzz_bytes = XorshiftPRNG::Get4RandomBytes();
                                    *(uint32_t*)&backup_vector[fuzz_pair.first] = fuzz_bytes;
                                }
                                else if(diff == 0x08llu)
                                {
                                    uint64_t fuzz_bytes = XorshiftPRNG::Get8RandomBytes();
                                    *(uint64_t*)&backup_vector[fuzz_pair.first] = fuzz_bytes;
                                }
                            }

                            current_seed >>= 0x01llu;
                        }

                        *(uint16_t*)&backup_vector[24] = 0x0;
                        *(uint16_t*)&backup_vector[24] = NetworkHelpers::ComputeChecksum(&backup_vector[eth_hdr_size], ip_hdr_size);
                        *(uint16_t*)&backup_vector[50] = 0x0;
                        *(uint16_t*)&backup_vector[50] = NetworkHelpers::ComputeTCPChecksum(&backup_vector[eth_hdr_size], tcp_checksum_size);

                        #ifdef EXTREME_VERBOSITY
                        result = sock.WritePacket(backup_vector);
                        if(result != 0)
                            PrettyPrint::PrintError("Could not send packet [%d] from thread [%d] with error [%d].",
                                i, thr_id, result);
                        #else
                        sock.WritePacket(backup_vector);
                        #endif
                    }

                    if(frequency != 1.0)
                    {
                        std::this_thread::sleep_for(
                            std::chrono::milliseconds(
                                static_cast<int64_t>(std::ceil((1.0 / frequency) * 1000))
                            )
                        );
                    }
                }

                return;
            },
            0x30u,
            1.0
        );

        interfuzzer.StartFuzzing();
    }
    catch(const SocketErrors& e)
    {
        PrettyPrint::PrintError("Error of type %u caught in try-catch block.",
            static_cast<std::underlying_type<SocketErrors>::type>(e));
    }
    return 0;
}