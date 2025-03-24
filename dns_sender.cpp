#include <pcap.h>
#include <iostream>
#include <vector>
#include <cstring>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <unistd.h>

#define DNS_PORT 53
#define TEMPLATE_PCAP "dns_naver.pcap"

// DNS Request Template Storage
std::vector<uint8_t> dns_request_template;

// Load first DNS request packet from pcap file
bool load_dns_request_template(const char* filename) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_offline(filename, errbuf);
    if (!pcap) {
        std::cerr << "Failed to open pcap: " << errbuf << std::endl;
        return false;
    }

    struct pcap_pkthdr* header;
    const u_char* packet;
    int result = 0;

    while ((result = pcap_next_ex(pcap, &header, &packet)) >= 0) {
        const struct ip* ip_hdr = reinterpret_cast<const struct ip*>(packet + 14); // Skip Ethernet
        if (ip_hdr->ip_p != IPPROTO_UDP)
            continue;

        const struct udphdr* udp_hdr = reinterpret_cast<const struct udphdr*>((u_char*)ip_hdr + ip_hdr->ip_hl * 4);
        if (ntohs(udp_hdr->dest) != DNS_PORT)
            continue;

        size_t packet_len = header->caplen;
        dns_request_template.assign(packet, packet + packet_len);
        pcap_close(pcap);
        std::cout << "Loaded DNS request template (" << packet_len << " bytes)." << std::endl;
        return true;
    }

    std::cerr << "No DNS request packet found in pcap." << std::endl;
    pcap_close(pcap);
    return false;
}

// Modify and send DNS request from template
void send_modified_dns_request(const std::string& new_domain, const std::string& target_ip) {
    if (dns_request_template.empty()) {
        std::cerr << "DNS request template not loaded." << std::endl;
        return;
    }

    // Make a copy of the packet to modify
    std::vector<uint8_t> packet = dns_request_template;

    // Update domain name in DNS query
    size_t eth_len = 14;
    struct ip* ip_hdr = reinterpret_cast<struct ip*>(&packet[eth_len]);
    size_t ip_len = ip_hdr->ip_hl * 4;
    struct udphdr* udp_hdr = reinterpret_cast<struct udphdr*>(&packet[eth_len + ip_len]);
    uint8_t* dns_ptr = &packet[eth_len + ip_len + sizeof(struct udphdr)];

    // Skip 12 bytes DNS header, replace qname
    uint8_t* qname = dns_ptr + 12;
    size_t offset = 0;
    std::vector<uint8_t> encoded;
    for (const auto& label : new_domain) {
        if (label == '.') {
            encoded.push_back(offset);
            offset = 0;
        } else {
            encoded.push_back(label);
            offset++;
        }
    }
    encoded.push_back(offset); // Final label length
    encoded.push_back(0x00);   // Terminate

    std::copy(encoded.begin(), encoded.end(), qname);

    // Update IP header checksum
    ip_hdr->ip_sum = 0;
    uint16_t* ip_words = reinterpret_cast<uint16_t*>(ip_hdr);
    unsigned long sum = 0;
    for (int i = 0; i < ip_len / 2; ++i) sum += ntohs(ip_words[i]);
    sum = (sum & 0xFFFF) + (sum >> 16);
    ip_hdr->ip_sum = htons(~sum);

    // Send packet using raw socket
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) {
        std::cerr << "Failed to create raw socket." << std::endl;
        return;
    }

    int one = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    sockaddr_in dest{};
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = inet_addr(target_ip.c_str());

    if (sendto(sock, packet.data() + eth_len, packet.size() - eth_len, 0,
               (sockaddr*)&dest, sizeof(dest)) < 0) {
        std::cerr << "sendto failed" << std::endl;
    } else {
        std::cout << "Sent modified DNS request to " << target_ip << std::endl;
    }

    close(sock);
}

int main() {
    if (!load_dns_request_template(TEMPLATE_PCAP)) return 1;

    std::string domain = "www.naver.com";
    std::string target_dns_ip = "192.168.127.132";

    send_modified_dns_request(domain, target_dns_ip);
    return 0;
}
