#include <stdio.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <unistd.h>
#include <pthread.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
/*#include <net/ieee80211_radiotap.h>*/

#define ANSI_CLR "\033[2J"
#define ANSI_HOM "\033[H"

volatile _Bool run = 1;

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

    /* below fields are used for selecting and printing specific ip addresses */
    _Atomic int idx_filter;
    _Atomic int n_ips, ip_cap;
    _Atomic in_addr_t* ip_addresses;
    _Atomic in_addr_t* old_ptr;

    /* TODO: store bucket IP so we can print a header on first packet
     * of new bucket
     */
    /*char bucket_ip[18];*/
    _Atomic (struct address_packets*) ap_print;
};

void exit_loop(int sig){
    (void)sig;
    run = 0;
}

void init_packet_storage(struct packet_storage* ps, int n_buckets){
    ps->n_buckets = n_buckets;
    ps->buckets = calloc(sizeof(struct ip_bucket*), ps->n_buckets);
    ps->idx_filter = -1;

    ps->ip_cap = 100;
    ps->n_ips = 0;
    ps->n_packets = 0;
    ps->ip_addresses = malloc(sizeof(in_addr_t)*ps->ip_cap);
    ps->old_ptr = NULL;
}

/* TODO: make this threadsafe */

/*
TODO:

    ip_addresses needs to be maintained in insert_packet_storage()

    need to add a new thread to read from stdin to grab which index of ip_addresses has been selected
    for now this same thread will print packets to the screen until another keypress is registered
*/


struct ip_bucket* create_bucket(struct address_packets* ap){
    struct ip_bucket* ib = malloc(sizeof(struct ip_bucket));

    ib->next = NULL;
    ib->head = ap;
    ib->n_packets = 1;

    return ib;
}

/*
 * to insert a new ip to in_addr_t* ip_addresses;
 * all we need to do is insert into the next index!
 * if buf isn't big enough, resize, take our time
 * and swap out the pointer atomically
 * once pointer's swapped out, atomically increment n_ips
 *
 * this works because we only insert from one thread
 * the only critical section becomes the reading of indices
*/
/* this does not need to be threadsafe as it will only be called from one thread */

void insert_ip_list(struct packet_storage* ps, struct packet* p){
    _Atomic in_addr_t* tmp, * old_ia;

    if(ps->n_ips == ps->ip_cap){
        ps->ip_cap *= 2;
        tmp = malloc(sizeof(in_addr_t)*ps->ip_cap);
        old_ia = ps->ip_addresses;
        memcpy(tmp, ps->ip_addresses, sizeof(in_addr_t)*ps->n_ips);
        atomic_store(&ps->ip_addresses, tmp);
        /* TODO: this potentially leaks memory
         * if old_ptr is non-null and we're resizing before p_ip_addresses() had
         * the chance to free()
         * we should use CAS() to check if old_ptr is non-null and to swap with 
         * old_ia if it is
         * then, with the old value of old_ptr, we'll free here
         *
         * this is a non-critical fix because it doesn't corrupt data, only leaks mem
         */
        atomic_store(&ps->old_ptr, old_ia);
    }
    ps->ip_addresses[ps->n_ips] = p->ihdr.saddr;
    atomic_store(&ps->n_ips, ps->n_ips+1);
}

/* TODO: insertion isn't threadsafe, there's a chance that we could be
 * reading from an invalid head
 * TODO: update pointer updates to be atomic in insert_packet_storage()
 * this isn't a huge deal though because buckets don't change once initialized
 */
struct ip_bucket* lookup_ip_bucket(struct packet_storage* ps, in_addr_t addr){
    int idx = addr % ps->n_buckets;
    struct ip_bucket* ib;

    for(ib = ps->buckets[idx]; ib; ib = ib->next){
        if(ib->head->p->ihdr.saddr == addr){
            return ib;
        }
    }
    return NULL;
}

struct address_packets* insert_packet_storage(struct packet_storage* ps, struct packet* p, ssize_t sz){
    int idx = p->ihdr.saddr % ps->n_buckets;
    struct ip_bucket* ib = ps->buckets[idx], * tmp_ib;
    struct address_packets* tmp = malloc(sizeof(struct address_packets));

    ++ps->n_packets;

    tmp->len = sz;
    tmp->p = p;
    tmp->next = NULL;

    /* create bucket */
    if(!ib){
        ib = create_bucket(tmp);
        ps->buckets[idx] = ib;
        insert_ip_list(ps, p);
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

    for(struct ip_bucket* i = ib; i; i = i->next){
        if(i->head->p->ihdr.saddr == p->ihdr.saddr){
            ib = i;
            break;
        }
    }


    /* if there's an appropriate bucket but no matching
     * struct address_packets, create it
     */
    if(ib->head->p->ihdr.saddr != p->ihdr.saddr){
        tmp_ib = malloc(sizeof(struct ip_bucket*));
        tmp_ib->next = ib;
        tmp_ib->head = NULL;
        ps->buckets[idx] = tmp_ib;
        ib = tmp_ib;
        insert_ip_list(ps, p);
    }

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

    src.s_addr = p->ihdr.saddr;
    dest.s_addr = p->ihdr.daddr;
    printf("packet len: %i\n", ntohs(p->ihdr.tot_len));
    inet_ntop(AF_INET, &src, ipbuf, sizeof(ipbuf));
    printf("saddr: %s\n", ipbuf);
    inet_ntop(AF_INET, &dest, ipbuf, sizeof(ipbuf));
    printf("daddr: %s\n", ipbuf);
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
 * void select_ip(struct packet_storage* ps, in_addr_t ip){
 *     
 * }
*/

void ip_addresses_op(struct packet_storage* ps, int sel_idx){
    char ipbuf[18] = {0};
    int n_ips = atomic_load(&ps->n_ips);
    /* there's a chance that this has been realloc'd
     * in case of this, free()ing is left to be done here
     * and the old pointer is passed in ps->old_ptr
     * this is always safe because insertion won't occur until
     * after resizing of buffer anyway
     */
    _Atomic in_addr_t* addresses = atomic_load(&ps->ip_addresses);
    // TODO:
    // atomic_compare_exchange_strong() should really be used here
    // to avoid double free()ing
    // there's a possibility that two threads call this function simultaneously
    // and both load old_ptr and try to free it
    // we should CAS() to update old_ptr to NULL once we read it
    _Atomic in_addr_t* old_ptr = atomic_load(&ps->old_ptr);

    if(sel_idx >= 0 && sel_idx < n_ips){
        /*_Atomic struct ip_bucket* aib = lookup_ip_bucket(ps, addresses[sel_idx]);*/
        /*atomic_store(&ps->ap_print, aib);*/
        // TODO: may need to change ib->head to be _Atomic
        atomic_store(&ps->ap_print, lookup_ip_bucket(ps, addresses[sel_idx])->head);
    }
    else{
        /* TODO: is this good behavior?
         * do we want to nullify ap_print when a bad idx is passed?
         */
        atomic_store(&ps->ap_print, NULL);
        for(int i = 0; i < n_ips; ++i){
            iaddr_to_str(addresses[i], ipbuf, sizeof(ipbuf));
            printf("(%i) - IP %s\n", i, ipbuf);
        }
    }

    if(old_ptr){
        free(old_ptr);
        atomic_store(&ps->old_ptr, NULL);
    }
}

void p_ip_addresses(struct packet_storage* ps){
    ip_addresses_op(ps, -1);
}

/*
 * void p_packet_storage_exp(struct packet_storage* ps){
 *     _Atomic struct 
 * }
*/

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
    atomic load ap_print
    return 0 !ap_print
then at the end, we can
    CAS(ap_print, ap_print->next)!

this way, if it's been NULL-ified by an idx of -1 being set
we won't set it to a weird position in the middle of a bucket
when we shouldn't be printing anything

*/
_Bool p_stream(struct packet_storage* ps){
    /*atomic-l*/
    struct address_packets* ap = atomic_load(&ps->ap_print);
    if(!ap)return 0;
    p_packet(ap, 1);
    atomic_compare_exchange_strong(&ps->ap_print, &ap, ap->next);
    return 1;
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
 * need:
 *  a thread to populate packet_storage
 *      what's currently done in main()
 *  a thread to read print index from stdin
 *      this will update print pointer upon receiving an integer
 *      otherwise, will reset idx to -1, printing only the summary
 *  a thread to print to stdout from a saved `last_addr` pointer
 *      thread will wait until ptr->next is available using pthread_cond_wait
 *
 *  could also just have a `print_from` ptr!
 *  this is maintained when:
 *      new print index is read (set ptr = bucktes[idx][ip][0])
 *      we print a packet (increment ptr)
 *
 * TODO: print the number of packets next to IP when outputted from ip_addresses
*/
void* p_stream_th(void* arg){
    struct packet_storage* ps = arg;

    while(run){
        /*
         * this logic is bad because even if we haven't had a packet in a while
         * we need to stay waiting to stream
         * we can do this by checking the ip of ps?
        */
        // TODO:
        // maybe we can only print once there's a new IP and we won't need to clear screen
        // this won't corrupt user input either
        // can also probably use this logic to not print guide again after we're out of packets from a given IP
        // HERE:
        //  if our last actual print was a real packet, then WAIT!
        //  keep printing nothing at all
        //  make sure that 
        //  the issue is that streaming won't work with this setup because new packets within
        //  a bucket won't be added to ps->ap_print->next
        //  we can only print packets after they've been processed
        //
        //  we could potentially also keep track of ip integer and check when we get a new packet
        //  if ip int is valid
        //  if(ip_int == current_ip)
        //      CAS(ap_print, NULL, new_ap);
        //  but this could cause problems if we:
        //      select idx
        //      print all packets
        //      user sets idx to -1, ap_print is set to NULL
        //      we get a new packet
        //      ap_print is overwritten with new packet
        //
        //  this could be countered by having a flag that's set when the user sets it to NULL
        //
        //  THIS IS WHAT THE NEXT STEP IS
        //  maybe we could store prev_ap each time we print!
        //  if NULL, print prev_ap->next, repeat
        if(!p_stream(ps)){
            printf("%s%s", ANSI_CLR, ANSI_HOM);
            p_ip_addresses(ps);
        }
        usleep(1000000);
    }
    return NULL;
}

void* select_ip_th(void* arg){
    struct packet_storage* ps = arg;
    int idx;

    while(run){
        /* TODO: don't use fscanf */
        if(!fscanf(stdin, "%i", &idx))continue;
        ip_addresses_op(ps, idx);
        /*printf("SET IDX TO %i\n", idx);*/
    }
    return NULL;
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
    struct packet_storage ps;
    struct address_packets* ap;
    pthread_t p_stream_pth, select_ip_pth;

    signal(SIGINT, exit_loop);

    init_packet_storage(&ps, 10000);
    
    pthread_create(&p_stream_pth, NULL, p_stream_th, &ps);
    pthread_create(&select_ip_pth, NULL, select_ip_th, &ps);

    /*printf("sock %i\n", sock);*/
    /*br = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr*)&sa_i, &slen_i);*/
    while(run){
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
        /* if we've inserted a packet, p_stream()
         * there's a chance the summary has changed
         * TODO: only p_stream() if we have a new address or ap->p->ihdr.saddr == 
         */
        /*p_stream()*/
        /*
         * puts("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
         * printf("read %li bytes\n", br);
        */
        /*printf("%s%s", ANSI_CLR, ANSI_HOM);*/
        /*p_ip_addresses(&ps);*/

        /*
        if(!p_stream(&ps)){
            printf("%s%s", ANSI_CLR, ANSI_HOM);
            p_ip_addresses(&ps);
        }
        */

        /*p_packet_storage(&ps, 1, NULL);*/

        (void)ap;
        /*p_packet(ap, 1);*/
        /*free(buf);*/
    }
    pthread_join(p_stream_pth, NULL);
    kill(getpid(), SIGUSR1);
    pthread_join(select_ip_pth, NULL);
}
