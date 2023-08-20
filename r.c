#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/socket.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/rfcomm.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
/*#include <net/ieee80211_radiotap.h>*/

/*
 * struct hdr{
 *     struct ethhdr ehdr;
 *     struct iphdr ihdr;
 * };
*/

/* TODO: if i see problems with the alignment here
 * i can always just use
 *  struct ethhdr* ehdr = (struct ethhdr*)buf;
 *  struct iphdr* ihdr = (struct iphdr*)(buf+sizeof(struct ethhdr));
 */
struct __attribute__((__packed__)) packet{
    struct ethhdr ehdr;
    struct iphdr ihdr;
};

void hexdump(uint8_t* buf, ssize_t br, _Bool onlyalph){
    for(int i = 0; i < br; ++i){
        if(isalpha(buf[i]))printf("%2c ", buf[i]);
        else{
            if(onlyalph){
                printf("   ");
            }
            else printf("%.2hx ", buf[i]);
        }
        if(i % 8 == 0)printf("  ");
        if(i % 16 == 0)puts("");
    }
    puts("");
}

void p_eth_addr(uint8_t* addr){
    for(int i = 0; i < 5; ++i){
        printf("%.2hx:", addr[i]);
    }
    printf("%.2hx\n", addr[5]);
}

int pp_buf(uint8_t* buf, ssize_t br){
    struct packet* p = (struct packet*)buf;
    char ipbuf[18] = {0};
    struct in_addr src, dest;

    if(br < (long)sizeof(struct ethhdr)){
        return 0;
    }
    printf("from: ");
    p_eth_addr(p->ehdr.h_source);
    printf("to: ");
    p_eth_addr(p->ehdr.h_dest);


    if(br < (long)(sizeof(struct ethhdr) + sizeof(struct iphdr))){
        return 1;
    }

    /*
     * printf("sizeof packet, %i, br %i\n", sizeof(struct packet), br);
     * printf("%i == %i\n", ntohs(((struct packet*)buf)->ihdr.saddr), ihdr->saddr);
    */
    /*p_eth_addr(((struct packet*)buf)->ehdr.h_source);*/


    src.s_addr = p->ihdr.saddr;
    dest.s_addr = p->ihdr.daddr;
    printf("packet len: %i\n", ntohs(p->ihdr.tot_len));
    inet_ntop(AF_INET, &src, ipbuf, sizeof(ipbuf));
    printf("saddr: %s\n", ipbuf);
    inet_ntop(AF_INET, &dest, ipbuf, sizeof(ipbuf));
    printf("daddr: %s\n", ipbuf);
/*
 * 
 *     struct packet* pp = buf;
 *     src.s_addr = pp->ihdr.saddr;
 *     inet_ntop(AF_INET, &src, ipbuf, sizeof(ipbuf));
 *     printf("SADDR PACKET: %s\n", ipbuf);
*/
    /*ihdr->daddr;*/
    /*ihdr->saddr*/
    return 2;
}

/* TODO: maybe read more bytes depending on tot_len */
uint8_t* read_packet(int sock, int max_sz, ssize_t* br){
    uint8_t* packet = malloc(max_sz);

    *br = recvfrom(sock, packet, max_sz, 0, NULL, NULL);
    if(*br == -1){
        free(packet);
        packet = NULL;
    }
    return packet;
}

_Bool filter_packet(uint8_t* p, ssize_t br, uint8_t* s_addr, uint8_t* d_addr, in_addr_t s_ip, in_addr_t d_ip){
    /*struct packet* phdr = (struct packet*)p;*/
    struct ethhdr* ehdr = (struct ethhdr*)p;
    struct iphdr* ihdr = (struct iphdr*)p+sizeof(struct ethhdr);
    /*phdr->ihdr.*/

    if(br < (long)sizeof(struct packet))
        return 0;

    if(s_addr && memcmp(s_addr, ehdr->h_source, 6))
        return 0;

    if(d_addr && memcmp(d_addr, ehdr->h_dest, 6))
        return 0;

    if(s_ip && s_ip != ihdr->saddr)
        return 0;

    if(d_ip && d_ip != ihdr->daddr)
        return 0;
    return 1;
}

int main(){
    int sock = socket(AF_INET, SOCK_RAW, 0);
    /*struct ethhdr ehdr;*/
    sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    /*uint8_t buf[2048] = {0};*/
    uint8_t* buf;
    /*
     * struct sockaddr_in sa = 
     *     {.sin_family = AF_INET, .sin_port = 0, .sin_addr.s_addr = INADDR_ANY};
    */
    /*struct sockaddr* sa_i;*/
    /*socklen_t slen_i;*/
    ssize_t br;
    struct in_addr ia_filter;
    inet_pton(AF_INET, "192.168.4.119", &ia_filter);

    /*printf("sock %i\n", sock);*/
    /*br = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr*)&sa_i, &slen_i);*/
    while(1){
        buf = read_packet(sock, 4096, &br);

        if(!buf)continue;
        /*if(!filter_packet(buf, br, NULL, NULL, ia_filter.s_addr, 0)){*/
        if(!filter_packet(buf, br, NULL, NULL, 0, 0)){
            free(buf);
            continue;
        }
        puts("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
        printf("read %li bytes\n", br);

        hexdump(buf, br, 1);
        puts("");
        pp_buf(buf, br);
        free(buf);
    }
}
