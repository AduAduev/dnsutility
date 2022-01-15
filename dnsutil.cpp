#include <iostream>
#include <pcap.h>
#include <iomanip>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <vector>
#include <map>
#include <iostream>
#include <fstream>

#define SIZE_ETHERNET 14
std::vector<std::string> ipvec;
int count;

class packet_timestamp_info{
        std::string src;
        std::string dest;
        std::chrono::time_point<std::chrono::high_resolution_clock>  time;
};

packet_timestamp_info getaddr(pcap_pkthdr *header, const u_char *packet){
    packet_timestamp_info buf;
    struct ip* lip=(struct ip*)(packet + SIZE_ETHERNET);
    char sourceip[INET_ADDRSTRLEN];
    char destip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(lip->ip_src.s_addr), sourceip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(lip->ip_dst.s_addr), destip, INET_ADDRSTRLEN);
    buf.src=sourceip;
    buf.dest=destip;
    buf.time=std::chrono::high_resolution_clock::now();
    return buf;
}

int main() {
    count=0;
    std::vector<packet_timestamp_info> a;
    std::string interface;
    char errbuf[PCAP_ERRBUF_SIZE+1];

    std::cout << "Введите название интерфейса: ";
    std::cin >> interface;

    pcap_t *pcap_interface = pcap_open_live(interface.data() ,BUFSIZ,1,1,errbuf);

    if (pcap_interface == NULL){
        std::cout <<"Ошибка при открытии:"<< interface.data() << std::endl;
    }

    struct pcap_pkthdr *header;
    const u_char *packet;

    while (count<500){
        count++;
        int bggt = pcap_next_ex(pcap_interface,&header, &packet);     
        a.push_back(getaddr(header,packet));  
    }
    std::vector<packet_timestamp_info> to;
    std::vector<packet_timestamp_info> from;
    for(auto i:a){
        if (i.src==a[0].src){
            from.push_back(i);
        }
        if (i.src==a[0].dest){
            to.push_back(i);
        }
    }
    a.clear();
    std::ofstream out;         
    out.open("test.txt");
    if (out.is_open())
    {
        for(int i = 0; i<from.size()/2;i++){
            auto duration =  std::chrono::duration<double, std::milli>(to[i].time-from[i].time).count();
            out << duration<<"   ms\n";
        }
    }
    
    pcap_close(pcap_interface);

    return 0;
}