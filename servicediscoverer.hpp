#ifdef _SERVICE_DISCOVERER_H
#define _SERVICE_DISCOVERER_H 1

#define mDNS_ADDR "224.0.0.251"
#define mDNS_PORT 5353
#define mDNS_MAX_PACKET_SIZE 9000 /* includes ip hdr, udp hdr and dns hdr: RFC 6762 */

#define clear_struct(s) memset((s), 0, sizeof((*s)))
#define calc_offset(from, at) (off_t)((char *)(at) - (char *)(from))
#define error(msg) std::cerr << __func__ << ": " << (msg) << " (" << strerror(errno) << ")" << std::endl

struct mdns_hdr
{
	uint16_t txid;
	uint16_t flags;
#if __BYTE_ORDER == __LITTLE_ENDIAN
# define MDNS_RESPONSE 0x8000
#else
# define MDNS_RESPONSE 0x0001
#endif
	uint16_t nr_qs;
	uint16_t nr_as;
	uint16_t nr_aa;
	uint16_t nr_ad;
} __attribute__((__packed__));

struct mdns_srv_data
{
	uint16_t priority;
	uint16_t weight;
	uint16_t port;
	std::string target;
};

struct mdns_record
{
	uint16_t type;
	uint16_t klass;
	uint32_t ttl;
	uint16_t data_len;
	time_t cached;
	std::map<std::string,std::string> *text_data;
	struct mdns_srv_data srv_data;
	struct in_addr inet4;
	struct in6_addr inet6;
	std::string domain_name;
};

struct Query
{
	std::string name;
	uint16_t type;
	uint16_t klass;
};

#endif /* !defined _SERVICE_DISCOVERER_H
