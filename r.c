#include <stdio.h>
#include <stdint.h>
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

struct ip_bucket{
    /*in_addr_t ip;*/
    struct packet* head;
    struct ip_bucket* next;
};

struct packet_storage{
    /*
     * uint32_t
     * in_addr_t
    */
    int n_buckets;
    struct ip_bucket** buckets;
};

void init_packet_storage(struct packet_storage* ps, int n_buckets){
    ps->n_buckets = n_buckets;
    ps->buckets = calloc(sizeof(struct ip_bucket*), ps->n_buckets);
}

/* TODO: make this threadsafe */
void insert_packet_storage(struct packet_storage* ps, struct packet* p){
    int idx = p->ihdr.saddr % ps->n_buckets;
    struct ip_bucket* ib = ps->buckets[idx], * tmp;// * prev_i;

    /* create bucket */
    if(!ib){
        ib = (ps->buckets[idx] = malloc(sizeof(struct ip_bucket)));
        /*ib->ip = p->ihdr.saddr;*/
        ib->next = NULL;
        ib->head = p;
    }

    for(struct ip_bucket* i = ib; i; i = i->next){
        if(i->head->ihdr.saddr == p->ihdr.saddr){
            ib = i;
            break;
        }
        /*prev_i = i;*/
    }

    if(ib->head->ihdr.saddr != p->ihdr.saddr){
        tmp = malloc(sizeof(struct ip_bucket));
        tmp->head = p;
        tmp->next = ib;
        /*ib->head = tmp;*/
        ps->buckets[idx] = tmp;
    }
}

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

_Bool filter_packet(uint8_t* p, ssize_t br, uint8_t* s_addr, uint8_t* d_addr, char* s_ip, char* d_ip){
    struct packet* phdr = (struct packet*)p;
    struct in_addr s_ip_filter, d_ip_filter;

    if(s_ip)inet_pton(AF_INET, s_ip, &s_ip_filter);
    if(d_ip)inet_pton(AF_INET, s_ip, &d_ip_filter);
    /*phdr->ihdr.*/

    if(br < (long)sizeof(struct packet))
        return 0;

    if(s_addr && memcmp(s_addr, phdr->ehdr.h_source, 6))
        return 0;

    if(d_addr && memcmp(d_addr, phdr->ehdr.h_dest, 6))
        return 0;

    if(s_ip && s_ip_filter.s_addr != phdr->ihdr.saddr)
        return 0;

    if(d_ip && d_ip_filter.s_addr != phdr->ihdr.daddr)
        return 0;
    return 1;
}


/*
 * TODO:
 * have it sort by src IP AND by eth addr
 * it'll continuously print a 0-n indexed list of addresses and i can enter an integer
 * to print out the packets intercepted for that sender
*/
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
    

    /*printf("sock %i\n", sock);*/
    /*br = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr*)&sa_i, &slen_i);*/
    while(1){
        buf = read_packet(sock, 4096, &br);

        if(!buf)continue;
        /*if(!filter_packet(buf, br, NULL, NULL, "192.168.4.119", 0)){*/
        /*if(!filter_packet(buf, br, NULL, NULL, "192.168.4.63", 0)){*/
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
