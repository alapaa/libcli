#include <net/if.h>
#include <sys/ioctl.h>
#include "iputils.h"
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include "elog.h"
#include "sysutils.h"
#include <stdio.h>
#include <arpa/inet.h>

#include "sysutils.h"


const char *ipaddr_to_numeric(char *buf, int nbuf, const struct in_addr *addrp)
{
    const unsigned char *bytep = (const void *)&addrp->s_addr;

    safe_snprintf(buf, nbuf, "%u.%u.%u.%u", bytep[0], bytep[1], bytep[2], bytep[3]);
    return buf;
}

const char *ipmask_to_numeric(char *buf, int nbuf, const struct in_addr *mask)
{
    uint32_t maskaddr, bits;
    int i;

    maskaddr = ntohl(mask->s_addr);

    if (maskaddr == 0xFFFFFFFFL)
        /* we don't want to see "/32" */
        return "";

    i = 32;
    bits = 0xFFFFFFFEL;
    while (--i >= 0 && maskaddr != bits)
        bits <<= 1;
    if (i >= 0)
        safe_snprintf(buf, nbuf, "/%d", i);
    else {
        char t[20];
        /* mask was not a decent combination of 1's and 0's */
        safe_snprintf(buf, nbuf, "/%s", ipaddr_to_numeric(t,sizeof(t),mask));
    }

    return buf;
}

static int ip6addr_prefix_length(const struct in6_addr *k)
{
    unsigned int bits = 0;
    uint32_t a, b, c, d;

    a = ntohl(k->s6_addr32[0]);
    b = ntohl(k->s6_addr32[1]);
    c = ntohl(k->s6_addr32[2]);
    d = ntohl(k->s6_addr32[3]);
    while (a & 0x80000000U) {
        ++bits;
        a <<= 1;
        a  |= (b >> 31) & 1;
        b <<= 1;
        b  |= (c >> 31) & 1;
        c <<= 1;
        c  |= (d >> 31) & 1;
        d <<= 1;
    }
    if (a != 0 || b != 0 || c != 0 || d != 0)
        return -1;
    return bits;
}

const char *ip6mask_to_numeric(char *buf, int nbuf, const struct in6_addr *addrp)
{
    int l = ip6addr_prefix_length(addrp);

    if (l == -1) {
        /* TODO: check boundaries */
        strcpy(buf, "/");
        strncat(buf, inet_ntop(AF_INET6, addrp, buf, 50), nbuf);
        return buf;
    }
    safe_snprintf(buf, nbuf, "/%d", l);
    return buf;
}

const char *ip6addr_to_numeric(char *buf, int nbuf, const struct in6_addr *addrp)
{
    return inet_ntop(AF_INET6, addrp, buf, nbuf);
}

static const char *mask_to_slash_num(char *buf, int nbuf, uint8_t bits, uint8_t max)
{
    if (bits >= max)
        return "";
    safe_snprintf(buf, nbuf, "/%d", bits);
    return buf;
}


char *ipt_addr_tostr(char *buff, char *pre, int bufsize,
                            struct sockaddr_storage *vip,
                            uint8_t mask)
{
    char b[64], b2[16];

    if (mask == 0)
        return "";
    if (vip->ss_family == AF_INET6) {
        safe_snprintf(buff, bufsize, "%s %s%s", pre,
                      ip6addr_to_numeric(b,sizeof(b),&((struct sockaddr_in6*)vip)->sin6_addr),
                      mask_to_slash_num(b2,sizeof(b2),mask, 128));
    } else {
        safe_snprintf(buff, bufsize, "%s %s%s", pre,
                      ipaddr_to_numeric(b,sizeof(b),&((struct sockaddr_in*)vip)->sin_addr),
                      mask_to_slash_num(b2,sizeof(b2), mask, 32));
    }
    return buff;
}

short str_to_family(char *name)
{
    short family = 0;
    char *tmp = 0;
    int len = 0;
    int i = 0;

    tmp = strdup(name);
    len = strlen(tmp);

    for(i = 0; i < len; i++) {
        tmp[i] = tolower(tmp[i]);
    }

    if (ADR_IPV4(strcmp(tmp,"ipv4") == 0)) {
        family = AF_INET;
    } else if (ADR_IPV6(strcmp(tmp,"ipv6") == 0)) {
        family = AF_INET6;
    }
    free(tmp);

    return family;
}

char *family_to_str(struct sockaddr_storage *sa)
{
    if (ADR_IPV4(AF_INET  == sa->ss_family)) {
        return "ipv4";
    } else if (ADR_IPV6(AF_INET6 == sa->ss_family)) {
        return "ipv6";
    } else {
        return 0;
    }
}

char *ipproto_to_str(unsigned short ipproto_nr)
{
    switch (ipproto_nr) {
    case IPPROTO_TCP:
        return "tcp";
    case IPPROTO_UDP:
        return "udp";
    case IPPROTO_SCTP:
        return "sctp";
    default:
        return 0;
    }
}

char* ip_to_str(char *str,int maxlen,const struct sockaddr_storage* address)
{
    if (address->ss_family==AF_UNSPEC) {
        snprintf(str,maxlen,"(unspec)");
    } else if (getnameinfo((struct sockaddr*)address, sizeof(*address), str, maxlen,0,0,NI_NUMERICHOST) != 0) {
        str[0]=0;
    }
    return str;
}

int raw_ip_to_str(char *str,int maxlen,void* ip,int ip_size)
{
    if (ADR_IPV4(4 == ip_size)) {
        if (inet_ntop(AF_INET,ip,str,maxlen)==0) {
            return -1;
        }
    } else if (ADR_IPV6(16 == ip_size)) {
        if (inet_ntop(AF_INET6,ip,str,maxlen)==0) {
            return -1;
        }
    } else {
        if (maxlen>0) {
            str[0]=0;
            return -1;
        }
    }
    return 0;
}

int raw_ip_to_ip(struct sockaddr_storage* address,void* ip,int ip_size)
{
    if (ADR_IPV4(4 == ip_size)) {
        address->ss_family=AF_INET;
        memcpy(&((struct sockaddr_in*)address)->sin_addr,ip,ip_size);
    } else if (ADR_IPV6(16 == ip_size)) {
        /*Ugly needs to be redone*/
        char str[48];
        raw_ip_to_str(str,sizeof(str),ip,ip_size);
        str_to_ip(address,str,1);
    } else {
        return -1;
    }

    return 0;
}

int ip_to_raw_ip(void* ip,int ip_size,const struct sockaddr_storage *const address)
{
    bzero(ip, ip_size);

    if (ADR_IPV4(AF_INET == address->ss_family && ip_size >= 4)) {
        memcpy(ip,&((struct sockaddr_in*)address)->sin_addr,4);
    } else if (ADR_IPV6(AF_INET6 == address->ss_family && ip_size>=16)) {
        memcpy(ip,&((struct sockaddr_in6*)address)->sin6_addr,16);
    } else {
        return -1;
    }
    return 0;
}

int parse_linklocal_ipv6(char* dev, struct sockaddr_storage* address) {
    char* start,*stop;
    char ip[48];
    ip_to_str(ip,sizeof(ip),address);
    if ((start = strstr(ip,"fe80")) != NULL) {
        if((stop = strchr(ip,'%')) != NULL) {
            *stop = 0;
            str_to_ip(address,start,1);
            strcpy(dev,stop+1);
            return 0;
        }
    }
    return -1;
}

int parse_dev_ipv6(char *dev,const char *full_addr, int max_dev)
{
    char *start,*stop;
    if ((start = strstr(full_addr,"fe80")) != NULL) {
        if((stop = strchr(full_addr,'%')) != NULL) {
            strncpy(dev,stop+1,max_dev);
            return 0;
        }
    }
    return -1;
}

int convert_fe80_to_mac(char *mac_str, int mac_size, char *fe80_str_in)
{
    char fe80_str[64];
    char fe80[16] = {0};
    char mac[6] = {0};
    char *dev_i;

    /* Strip %device from fe80 ipv6 addresses. */
    if ((dev_i = strchr(fe80_str_in, '%')) == 0) {
        dev_i = fe80_str_in + strnlen(fe80_str_in, 46);
    }
    strncpy(fe80_str, fe80_str_in, sizeof(fe80_str));
    fe80_str[dev_i - fe80_str_in] = 0;

    if (str_to_rawip(fe80, fe80_str) == 0) {
        ERR("Invalid ipv6 address.\n");
        return -1;
    }

    mac[0] = fe80[8] ^ 0x02;
    mac[1] = fe80[9];
    mac[2] = fe80[10];
    mac[3] = fe80[13];
    mac[4] = fe80[14];
    mac[5] = fe80[15];

    snprintf(mac_str, mac_size, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0] & 0xff, mac[1] & 0xff, mac[2] & 0xff,
             mac[3] & 0xff, mac[4] & 0xff, mac[5] & 0xff);

    return 0;
}

int convert_mac_to_fe80(char* fe80_str, int size, char* macaddress)
{
    char fe80[16], mac[6], mac_copy[20];
    int i;
    char *saveptr, *result;

    if (size < 46) {
        return -1;
    }

    strncpy(mac_copy,macaddress,sizeof(mac_copy));

    result =  strtok_r(mac_copy,":",&saveptr);
    for(i = 0; i < 6; i++) {
        mac[i] = strtol(result, NULL, 16);
        result =  strtok_r(NULL,":",&saveptr);
    }

    fe80[0] = 0xfe;
    fe80[1] = 0x80;
    fe80[2] = 0x00;
    fe80[3] = 0x00;
    fe80[4] = 0x00;
    fe80[5] = 0x00;
    fe80[6] = 0x00;
    fe80[7] = 0x00;

    fe80[8] = mac[0] ^ 0x02;
    fe80[9] = mac[1];
    fe80[10] = mac[2];
    fe80[11] = 0xff;
    fe80[12] = 0xfe;
    fe80[13] = mac[3];
    fe80[14] = mac[4];
    fe80[15] = mac[5];

    if (raw_ip_to_str(fe80_str, size, fe80, 16) != 0) {
        return -1;
    }

    return 0;
}

/* Returns 0 success */
int str_to_ip(struct sockaddr_storage* address,const char *str,int dns_lookup)
{
    bzero(address, sizeof(struct sockaddr_storage)); // To please valgrind.

    int rval = 0;
    if (dns_lookup) {
        struct addrinfo hints,*res;
        memset(&hints,0,sizeof(hints));
        hints.ai_family=AF_UNSPEC;
        rval = getaddrinfo(str,0,&hints,&res);
        if (rval == 0) {
            memcpy(address,res->ai_addr,res->ai_addrlen);
            freeaddrinfo(res);
        }
    } else {
        if (ADR_IPV4(strchr(str,':') == 0)) {
            address->ss_family=AF_INET;
            return inet_pton(AF_INET,str,
                             &((struct sockaddr_in*)address)->sin_addr)-1;
        } else {
            address->ss_family=AF_INET6;
            return inet_pton(AF_INET6,str,
                             &((struct sockaddr_in6*)address)->sin6_addr)-1;
        }
    }

    return rval;
}

size_t str_to_rawip(void *dest, const char *str)
{
    struct sockaddr_storage ip;
    size_t size;
    int check;

    if (ADR_IPV4(strchr(str,':') == 0)) {
        ip.ss_family = AF_INET;
        check = inet_pton(AF_INET, str, &((struct sockaddr_in*)&ip)->sin_addr);
        if ( check > 0 ) {
            memcpy(dest, &((struct sockaddr_in*) &ip)->sin_addr, size = sizeof(struct in_addr));
        } else {
            return 0;
        }
    } else {
        ip.ss_family = AF_INET6;
        check = inet_pton(AF_INET6, str, &((struct sockaddr_in6*)&ip)->sin6_addr);
        if ( check > 0 ) {
            memcpy(dest, &((struct sockaddr_in6*) &ip)->sin6_addr, size = sizeof(struct in6_addr));
        } else {
            return 0;
        }
    }
    return size;
}

size_t str_to_rawip_dns(void *dest, const char *str)
{
    struct sockaddr_storage ip;

    if (str_to_ip(&ip,str,1)!=0) {
        return 0;
    }
    if (ip_to_raw_ip(dest,16,&ip)==-1) {
        return 0;
    }
    if (ip.ss_family==AF_INET) {
        return sizeof(struct in_addr);
    } else {
        return sizeof(struct in6_addr);
    }
}

int compare_address(void *addr_data,int addr_size,
                   const struct sockaddr_storage* addr2)
{
    if (ADR_IPV4(AF_INET == addr2->ss_family)) {
        if (addr_size!=4) {
            return -1;
        }
        return memcmp(addr_data,&((struct sockaddr_in*)addr2)->sin_addr,4);
    } else if (ADR_IPV6(AF_INET6 == addr2->ss_family)) {
        if (addr_size!=16) {
            return -1;
        }
        return memcmp(addr_data,&((struct sockaddr_in6*)addr2)->sin6_addr,16);
    } else {
        return -1;
    }
}

static int compare_address_storage_and_port(const struct sockaddr_storage* addr1,
                                            const struct sockaddr_storage* addr2, int compare_port)
{
    if (addr1->ss_family!=addr2->ss_family)
        return -1;

    if (ADR_IPV4(AF_INET == addr1->ss_family)) {
        struct sockaddr_in *a1 = (struct sockaddr_in*) addr1;
        struct sockaddr_in *a2 = (struct sockaddr_in*) addr2;
        int32_t i1=ntohl(a1->sin_addr.s_addr);
        int32_t i2=ntohl(a2->sin_addr.s_addr);

        if (compare_port && a1->sin_port != a2->sin_port)
            return -1;

        return  i1 - i2;

    } else if (ADR_IPV6(AF_INET6 == addr1->ss_family)) {
        struct sockaddr_in6 *a1 = (struct sockaddr_in6*) addr1;
        struct sockaddr_in6 *a2 = (struct sockaddr_in6*) addr2;

        if (compare_port && a1->sin6_port != a2->sin6_port)
            return -1;

        if (a1->sin6_addr.s6_addr32[0] != a2->sin6_addr.s6_addr32[0])
            return a1->sin6_addr.s6_addr32[0] - a2->sin6_addr.s6_addr32[0];
        if (a1->sin6_addr.s6_addr32[1] != a2->sin6_addr.s6_addr32[1])
            return a1->sin6_addr.s6_addr32[1] - a2->sin6_addr.s6_addr32[1];
        if (a1->sin6_addr.s6_addr32[2] != a2->sin6_addr.s6_addr32[2])
            return a1->sin6_addr.s6_addr32[2] - a2->sin6_addr.s6_addr32[2];
        if (a1->sin6_addr.s6_addr32[3] != a2->sin6_addr.s6_addr32[3])
            return a1->sin6_addr.s6_addr32[3] - a2->sin6_addr.s6_addr32[3];
        return 0;

    } else {
        return -1;
    }
}

int compare_address_storage(const struct sockaddr_storage* addr1,
                            const struct sockaddr_storage* addr2)
{
    return compare_address_storage_and_port(addr1, addr2, 0);
}

int compare_address_and_port(const struct sockaddr_storage* addr1,
                             const struct sockaddr_storage* addr2)
{
    return compare_address_storage_and_port(addr1, addr2, 1);
}

/**
 * Comapres addresses a and b with a netmask
 *
 */
int compare_addr_mask(struct sockaddr_storage *a, struct sockaddr_storage *b,
                      int mask)
{
    if (a->ss_family!=b->ss_family) {
        return -1;
    }
    if (a->ss_family == AF_INET) {
        struct in_addr addrmask = { .s_addr = set_u32mask(mask), };

        if (mask > 32)
            return -1;

        return ipv4_addr_cmp_mask2(&((struct sockaddr_in*)a)->sin_addr,
                                   &((struct sockaddr_in*)b)->sin_addr,
                                   &addrmask);
    }
    if (a->ss_family == AF_INET6) {
        struct in6_addr addrmask;

        if (mask > 128)
            return -1;

        set_u128mask(&addrmask, mask);
        return ipv6_addr_cmp_mask2(&((struct sockaddr_in6*)a)->sin6_addr,
                                   &((struct sockaddr_in6*)b)->sin6_addr,
                                   &addrmask);
    }
    return -1;
}

int get_route_dev(char* rmt_addr,char* dev,int size)
{
    char **getdev_output;
    unsigned int nlines=0;
    char* result,*firstspace,*lastspace;
    char ip_route[64];

    snprintf(ip_route, sizeof(ip_route), "ip route get %s",rmt_addr);
    run_cmd(ip_route,&getdev_output,&nlines);

    if (nlines>=1) {
        result=strstr(getdev_output[0],"dev");
        if (result) {
            firstspace=strchr(result+3,' ');
            if (firstspace) {
                lastspace=strchr(firstspace+1,' ');
                if (lastspace) {
                    if ((lastspace-firstspace)<size) {
                        memcpy(dev,firstspace+1,lastspace-firstspace-1);
                        dev[lastspace-firstspace-1]=0;
                        run_cmd_release_buf(getdev_output,nlines);
                        return 0;
                    }
                }
            }
        }
    }
    run_cmd_release_buf(getdev_output,nlines);
    return -1;
}

int get_route(char* rmt_addr,char* lcl_addr,int lcl_size)
{
    char route_cmd[128];
    char **route_buf;
    unsigned int route_lines;
    char *dev_pos=strchr(rmt_addr,'%');
    char rmt_addr2[128];
    if (dev_pos) {
        memcpy(rmt_addr2,rmt_addr,dev_pos-rmt_addr);
        rmt_addr2[dev_pos-rmt_addr]=0;
        snprintf(route_cmd, sizeof(route_cmd), "ip route get %s | sed '1!d;s/.*src //;s/ .*//'",
                 rmt_addr2);
    } else {
        snprintf(route_cmd, sizeof(route_cmd), "ip route get %s | sed '1!d;s/.*src //;s/ .*//'",
                 rmt_addr);
    }
    run_cmd(route_cmd,&route_buf,&route_lines);
    if (route_lines>0) {
        int len=strlen(route_buf[0]);
        while (route_buf[0][len-1]==' ') {
            route_buf[0][len-1]=0;
            len--;
        }
        safe_strncpy(lcl_addr,route_buf[0],lcl_size);
    } else {
        if (lcl_size>=1) {
            lcl_addr[0]=0;
        }
    }
    run_cmd_release_buf(route_buf,route_lines);
    return 0;
}

int inet_getport(struct sockaddr_storage *sa)
{
    if(ADR_IPV4(AF_INET == sa->ss_family)) {
        struct sockaddr_in *sin;
        sin = (struct sockaddr_in *)sa;
        return ntohs(sin->sin_port);
    } else if (ADR_IPV6(AF_INET6 == sa->ss_family)) {
        struct sockaddr_in6 *sin6;
        sin6 = (struct sockaddr_in6 *)sa;
        return ntohs(sin6->sin6_port);
    } else {
        return 0;
    }
}

int inet_setport(struct sockaddr_storage *sa, int port)
{
    if(ADR_IPV4(AF_INET == sa->ss_family)) {
        struct sockaddr_in *sin;
        sin = (struct sockaddr_in *)sa;
        sin->sin_port = htons(port);
        return 1;
    } else if (ADR_IPV6(AF_INET6 == sa->ss_family)) {
        struct sockaddr_in6 *sin6;
        sin6 = (struct sockaddr_in6 *)sa;
        sin6->sin6_port = htons(port);
        return 1;
    } else {
        return 0;
    }
}

int strip_device_from_fe80(char *fe80_str, int fe80_size)
{
    char *dev_i;

    if ((dev_i = strchr(fe80_str, '%')) == 0) {
        dev_i = fe80_str + strnlen(fe80_str, fe80_size);
    }
    fe80_str[dev_i - fe80_str] = 0;

    return 0;
}

int is_addr_zero(struct sockaddr_storage *addr)
{
    int i;
    if (!addr) {
        return 1;
    }
    if (addr->ss_family==AF_INET) {
        return (*(uint32_t*)&((struct sockaddr_in*)addr)->sin_addr)==0;
    } else if (addr->ss_family==AF_INET6) {
        for (i=0;i<4;i++) {
            if (((struct sockaddr_in6*)addr)->sin6_addr.s6_addr[i]) {
                return 0;
            }
        }
        return 1;
    } else {
        return 0;
    }
}
