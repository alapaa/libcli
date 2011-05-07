#ifndef IPUTILS_H
#define IPUTILS_H

#include <netdb.h>

#define FOREACH_EXTDATA(item, ip_addrs, ip_addrs_size)  \
    for ((item).data=(ip_addrs).data,(item).size=(ip_addrs_size);((char*)(item).data+(ip_addr_size))<=((char*)(ip_addrs).data+(ip_addrs).size);(*((char**)&(item).data))+=(ip_addrs_size))

#ifndef likely
#define likely(x)       __builtin_expect((x),1)
#endif

#ifndef unlikely
#define unlikely(x)     __builtin_expect((x),0)
#endif

#ifdef LIKELY_IPV6
#define ADR_IPV4(x)         unlikely((x))
#define ADR_IPV6(x)         likely((x))
#else
/* We are more likely to handle ipv4 addresses */
#define ADR_IPV4(x)         likely((x))
#define ADR_IPV6(x)         unlikely((x))
#endif

static inline __uint32_t set_u32mask(int bits)
{
    return bits <= 0 ? 0 : htonl(0xffffffff << (32-bits));
}

/*
 * Set a 128 bit mask
 */
static inline void set_u128mask( struct in6_addr *mask, __uint8_t bits)
{
        mask->s6_addr32[0] = (bits > 31 ? 0xffffffff : set_u32mask(bits));
        mask->s6_addr32[1] = (bits > 63 ? 0xffffffff : set_u32mask(bits-32));
        mask->s6_addr32[2] = (bits > 95 ? 0xffffffff : set_u32mask(bits-64));
        mask->s6_addr32[3] = (bits > 127 ? 0xffffffff : set_u32mask(bits-96));
}

/**
 *  Compare IPv6 addresses only mask a2
 *  @return bool
 */
static inline int ipv6_addr_equal_mask(struct in6_addr *a1,
									   struct in6_addr *a2,
									   struct in6_addr *mask)
{
	return ((a1->s6_addr32[3] == (a2->s6_addr32[3] & mask->s6_addr32[3])) &&
            (a1->s6_addr32[2] == (a2->s6_addr32[2] & mask->s6_addr32[2])) &&
            (a1->s6_addr32[1] == (a2->s6_addr32[1] & mask->s6_addr32[1])) &&
            (a1->s6_addr32[0] == (a2->s6_addr32[0] & mask->s6_addr32[0])));
}
/**
 *  Compare IPv6 addresses mask both
 *  @return bool
 */
static inline int ipv6_addr_cmp_mask2(struct in6_addr *a1,
                                       struct in6_addr *a2,
                                       struct in6_addr *mask)
{
    return (((a1->s6_addr32[3] ^ a2->s6_addr32[3]) & mask->s6_addr32[3]) ||
            ((a1->s6_addr32[2] ^ a2->s6_addr32[2]) & mask->s6_addr32[2]) ||
            ((a1->s6_addr32[1] ^ a2->s6_addr32[1]) & mask->s6_addr32[1]) ||
            ((a1->s6_addr32[0] ^ a2->s6_addr32[0]) & mask->s6_addr32[0]));
}
/**
 *  Compare IPv4 addresses only mask a2
 *  @return bool
 */
static inline int ipv4_addr_equal_mask(struct in_addr *a1,
									   struct in_addr *a2,
									   struct in_addr *mask)
{
	return (a1->s_addr == (a2->s_addr & mask->s_addr));
}
/**
 *  Compare IPv6 addresses mask both
 *  @return bool
 */
static inline int ipv4_addr_cmp_mask2(struct in_addr *a1,
                                       struct in_addr *a2,
                                       struct in_addr *mask)
{
    return ((a1->s_addr ^ a2->s_addr) & mask->s_addr);
}

/* Check if m1 has smaller mask than m2 */
static inline int ipv6_min_mask(struct in6_addr *m1, struct in6_addr *m2)
{
    int i;
    for(i=0;i<4;i++) {
        if (m1->s6_addr32[i] < m2->s6_addr32[i]) {
            return -1;
        } else if (m1->s6_addr32[i] > m2->s6_addr32[i]) {
            return 1;
        }
    }
    return 0;
}

static inline int ipv4_min_mask(struct in_addr *m1, struct in_addr *m2)
{
    return (m1->s_addr == m2->s_addr ? 0 : (m1->s_addr < m2->s_addr ? -1 : 1 ));
}

const char *ipaddr_to_numeric(char *buf, int nbuf, const struct in_addr *addrp);
const char *ipmask_to_numeric(char *buf, int nbuf, const struct in_addr *mask);
const char *ip6mask_to_numeric(char *buf, int nbuf, const struct in6_addr *addrp);
const char *ip6addr_to_numeric(char *buf, int nbuf, const struct in6_addr *addrp);

short str_to_family(char *);
char *family_to_str(struct sockaddr_storage *);
char *get_family(struct sockaddr_storage *);
char *ipproto_to_str(unsigned short ipproto_nr);

char* ip_to_str(char *str,int maxlen,const struct sockaddr_storage* address);
size_t str_to_rawip(void *dest, const char *str);
size_t str_to_rawip_dns(void *dest, const char *str);
int raw_ip_to_str(char *str,int maxlen,void* ip,int ip_size);
int str_to_ip(struct sockaddr_storage* address,const char *str,int dns_lookup);
int compare_address(void *addr_data,int addr_size,
                   const struct sockaddr_storage *addr2);
int compare_address_storage(const struct sockaddr_storage* addr1,
                            const struct sockaddr_storage* addr2);
int compare_address_and_port(const struct sockaddr_storage* addr1,
                             const struct sockaddr_storage* addr2);
int compare_addr_mask(struct sockaddr_storage *a,struct sockaddr_storage *b,int mask);
int get_route_dev(char* rmt_addr,char* dev,int size);
int get_route(char* rmt_addr,char* lcl_addr, int lcl_size);
int raw_ip_to_ip(struct sockaddr_storage* address,void* ip,int ip_size);
int ip_to_raw_ip(void* ip,int ip_size,const struct sockaddr_storage *const address);
int inet_getport(struct sockaddr_storage *sa);
int inet_setport(struct sockaddr_storage *sa, int port);
int generate_ipv6_from_node_id(char* address, int size, char* node_id);
int parse_linklocal_ipv6(char* dev, struct sockaddr_storage* address);
int parse_dev_ipv6(char *dev,const char *full_addr, int max_dev);
int convert_fe80_to_mac(char* macaddress, int size, char* fe80);
int strip_device_from_fe80(char *fe80_str, int fe80_size);
int compare_addr_mask(struct sockaddr_storage *a,struct sockaddr_storage *b,int mask);
int is_addr_zero(struct sockaddr_storage *addr);

#endif
