#include <stdio.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
/*#include <net/ieee80211_radiotap.h>*/

struct ps_filter{
    uint8_t* s_addr;
    uint8_t* d_addr;
    char* s_ip;
    char* d_ip;
};

/* TODO: if i see problems with the alignment here
 * i can always just use
 *  struct ethhdr* ehdr = (struct ethhdr*)buf;
 *  struct iphdr* ihdr = (struct iphdr*)(buf+sizeof(struct ethhdr));
 */
struct __attribute__((__packed__)) packet{
    struct ethhdr ehdr;
    struct iphdr ihdr;
};

/* no need to waste space by storing address, it's in p */
struct address_packets{
    struct packet* p;
    int len;

    struct address_packets* next;
};

struct ip_bucket{
    int n_packets;
    struct address_packets* head;
    struct ip_bucket* next;
};

struct packet_storage{
    int n_buckets;
    int n_packets;
    struct ip_bucket** buckets;

    _Atomic int idx_filter;
    _Atomic int n_ips, ip_cap;
    in_addr_t* ip_addresses;
};

void init_packet_storage(struct packet_storage* ps, int n_buckets){
    ps->n_buckets = n_buckets;
    ps->buckets = calloc(sizeof(struct ip_bucket*), ps->n_buckets);
    ps->idx_filter = -1;

    ps->ip_cap = 1000;
    ps->n_ips = 0;
    ps->n_packets = 0;
    ps->ip_addresses = malloc(sizeof(in_addr_t)*ps->ip_cap);
}

/* TODO: make this threadsafe */

/*
in summary:

    insert_packet_storage needs to be updated to actually insert into a linked list

    ip_addresses needs to be maintained in insert_packet_storage()

    need to add a new thread to read from stdin to grab which index of ip_addresses has been selected
    for now this same thread will print packets to the screen until another keypress is registered
*/


/*struct address_packets* create*/
struct ip_bucket* create_bucket(struct address_packets* ap){
    struct ip_bucket* ib = malloc(sizeof(struct ip_bucket));

    ib->next = NULL;
    ib->head = ap;
    ib->n_packets = 1;

    return ib;
}

struct address_packets* insert_packet_storage(struct packet_storage* ps, struct packet* p, ssize_t sz){
    int idx = p->ihdr.saddr % ps->n_buckets;
    struct ip_bucket* ib = ps->buckets[idx], * prev_ib = NULL, * tmp_ib;
    struct address_packets* tmp = malloc(sizeof(struct address_packets));

    ++ps->n_packets;

    tmp->len = sz;
    tmp->p = p;
    tmp->next = NULL;

    /* create bucket */
    if(!ib){
        ib = create_bucket(tmp);
        ps->buckets[idx] = ib;
        return tmp;

        /*increment ps->n_ips atomically to reserve an insertion point*/
// TODO: insert into list of addresses in ps->addresses here
// because we've found a new address
// this is then printed out each time insert_packet_storage() returns TRUE
// and referenced when user wants to print something to the screen for a given IP
/*
 *         deal with cap if i need to
 *         insert into addresses
 *         idx will store an IP!
 * 
 *         then we'll use this reference
 *         during p_packet_storage()
 *         with whatever idx_filter is set to
*/
    }

    /* from this point on we'll just be inserting tmp */
    #if 0
    TODO:
        find a bucket with appropriate IP :)
        insert to head of ib->list with tmp :) hehe
    #endif

    for(struct ip_bucket* i = ib; i; i = i->next){
        if(i->head->p->ihdr.saddr == p->ihdr.saddr){
            ib = i;
            prev_ib = tmp_ib;
            break;
        }
        tmp_ib = i;
    }


    /*
     * prev->ib->next
     * prev->ib->new->next
     * need to keep track of prev also, either store it
     * or throughout this fn()
    */
    /* if there's an appropriate bucket but no matching
     * struct address_packets, create it
     */
    /*ib will always be the initial ib if we're in this branch*/
    if(ib->head->p->ihdr.saddr != p->ihdr.saddr){
        tmp_ib = malloc(sizeof(struct ip_bucket*));
        tmp_ib->next = ib;
        tmp_ib->head = NULL;
        ps->buckets[idx] = tmp_ib;
        ib = tmp_ib;

        /*ib->*/
        /*tmp->next = ib->head;*/
        /*ib->head = tmp;*/
        /*ib->head = tmp;*/
        /*ps->buckets[idx] = tmp;*/
        /*insert into ps->addresses here too*/
        /*return;*/
    }

    (void)prev_ib;
    /* if we're here, we have a bucket but juts need to our packet into ib */
    // add to linked list of relevant struct address_packets
    /*ib->head ... */
    /*ib->head*/
    ++ib->n_packets;
    tmp->next = ib->head;
    ib->head = tmp;
    return tmp;
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

void iaddr_to_str(in_addr_t ia, char* buf, ssize_t buflen){
    struct in_addr in;

    in.s_addr = ia;
    inet_ntop(AF_INET, &in, buf, buflen);
}

int pp_buf(struct packet* p, ssize_t br){
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

void p_packet(struct address_packets* ap, _Bool hide_nonalpha){
    hexdump((uint8_t*)ap->p, ap->len, hide_nonalpha);
    puts("");
    pp_buf(ap->p, ap->len);
}

/* TODO: maybe read more bytes depending on tot_len */
// TODO: read only sizeof(packet)
// then read an additional tot_len
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

// prints out all packets for a given user according to the given idx
// actually, this should take in in_addr_t and be CALLED by p_packet_storage()
// this way we can pass either a user specified IP or an ip from the ip list
// that's maintained
void p_packet_storage(struct packet_storage* ps, _Bool summary, struct ps_filter* pf){
    (void)pf;
    int idx = atomic_load(&ps->idx_filter);
    char ipbuf[18] = {0};

    printf("%i total packets read\n", ps->n_packets);
    for(int i = 0; i < ps->n_buckets; ++i){
        if(!ps->buckets[i]){
            continue;
        }
        // if idx == -1 || match
        // we can maybe use filter_packet()
        // we can have a list of n in_addr_t
        // we'll print 
        for(struct ip_bucket* ib = ps->buckets[i]; ib; ib = ib->next){
            iaddr_to_str(ib->head->p->ihdr.saddr, ipbuf, sizeof(ipbuf));
            printf("IP %s: %i packets captured\n", ipbuf, ib->n_packets);
            /* summary mode prints only info about packets (and indices?) */
            if(!summary && (idx == -1 || ps->ip_addresses[idx] == ib->head->p->ihdr.saddr)){
                for(struct address_packets* ap = ib->head; ap; ap = ap->next){
                    p_packet(ap, 1);
                    /*hexdump((uint8_t*)ap->p, ap->len, 1);*/
                }
            }
        }
    }
}

/*
 * read from stdin, any time enter is pressed
 * we set the filter to the corresponding index
 *
 * i'll have a thread to read from stdin continuously
 * if we read empty, set idx to -1
 * otherwise, set to read idx
 *
 * i'll have another thread to print to stdout continuously
 * it'll just call p_packet_storage()
 *
 * how should i have p_packet_storage() stream data as it comes in?
 *
 * maybe it won't
 * it could maybe just print all packets from a given IP 
 * on each press of idx
 *
 * could also have p_packet_storage()
 * as well as stream_packet_storage()
 *
 *
 * if an idx is set we 
*/

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
    struct packet_storage ps;
    struct address_packets* ap;

    init_packet_storage(&ps, 10000);
    

    /*printf("sock %i\n", sock);*/
    /*br = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr*)&sa_i, &slen_i);*/
    while(1){
        buf = read_packet(sock, 4096, &br);

        if(!buf)continue;
        ap = insert_packet_storage(&ps, (struct packet*)buf, br);
        /*if(!filter_packet(buf, br, NULL, NULL, "192.168.4.119", 0)){*/
        /*if(!filter_packet(buf, br, NULL, NULL, "192.168.4.63", 0)){*/
        /*if(!filter_packet(buf, br, NULL, NULL, "192.168.86.108", 0)){*/
        if(!filter_packet(buf, br, NULL, NULL, 0, 0)){
            free(buf);
            continue;
        }
        puts("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
        printf("read %li bytes\n", br);
        p_packet_storage(&ps, 1, NULL);

        (void)ap;
        /*p_packet(ap, 1);*/
        /*free(buf);*/
    }
}
