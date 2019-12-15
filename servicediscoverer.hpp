#ifndef _SERVICE_DISCOVERER_H
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

class serviceDiscoverer
{
	public:

	serviceDiscoverer();

	~serviceDiscoverer();

	int mdns_query_service(std::string);
	int mdns_query_all_services(void);
	int mdns_listen(void);

	private:

	int startup(void);
	int mdns_handle_packet(void *, size_t);
	//int mdns_handle_response_packet(void *, size_t);
	int mdns_parse_queries(void *, size_t, void *, uint16_t);
	int mdns_parse_answers(void *, size_t, void *, uint16_t);
	int mdns_parse_authoritative(void *, size_t, void *, uint16_t);
	int mdns_parse_additional(void *, size_t, void *, uint16_t);
	void mdns_print_record(std::string, struct mdns_record&);
	std::map<std::string,std::string> *mdns_parse_text_record(void *, size_t);
	std::list<std::string> tokenize_name(std::string, char);

	bool should_replace_file(void);
	bool should_do_query(void);

	std::string timestamp_to_str(time_t);
	void mdns_save_cached_records(void);

	void default_iphdr(struct iphdr *);
	void default_udphdr(struct udphdr *);

	off_t label_get_offset(char *);
	std::string decode_name(void *, char *, int *);
	std::string encode_data(std::vector<struct Query>);

	bool cached_record_is_stale(struct mdns_record&);
	void check_cached_records(void);
	uint16_t get_16bit_val(char *); /* parses from pointer into native byte order */
	uint32_t get_32bit_val(char *); /* ' ' ' ' */
	const char * klass_str(uint16_t);
	const char * type_str(uint16_t);

	bool is_udp_pkt(char *);
	bool is_mdns_pkt(char *);
	bool is_query(uint16_t);
	bool is_response(uint16_t);
	bool should_flush_cache(uint16_t); /* checks for the CACHE FLUSH bit in class field */

	uint16_t new_txid(void); /* generate random 16-bit number */

	std::map<const char *,uint16_t> mdns_types =
	{
		{ "A", 1 }, /* ipv4 record */
		{ "PTR", 12 }, /* pointer record */
		{ "TXT", 16 }, /* text record */
		{ "AAAA", 28 }, /* ipv6 record */
		{ "SRV", 33 }, /* services record */
		{ "NSEC", 47 },
		{ "ANY", 255 }
	};

	std::map<const char *,uint16_t> mdns_classes =
	{
		{ "IN", 1 }
	};

	std::string special_query_all = "_services._dns-sd._udp.local";

	std::vector<struct Query> services =
	{
		{ "_http._tcp.local",  255, 1 },
		{ "_p2pchat._tcp.local",  255, 1 },
		{ "_ftp._tcp.local",  255, 1 },
		{ "_webdav._tcp.local",  255, 1 },
		{ "_imap._tcp.local",  255, 1 },
		{ "_pop3._tcp.local",  255, 1 },
		{ "_domain._udp.local",  255, 1 },
		{ "_ntp._udp.local",  255, 1 },
		{ "_printer._tcp.local",  255, 1 },
		{ "_ipp._tcp.local",  255, 1 },
		{ "_ipps._tcp.local",  255, 1 },
		{ "_daap._tcp.local",  255, 1 },
		{ "_pulse-server._tcp.local",  255, 1 }
	};
#if 0
	std::list<std::string> services =
	{
		"_http._tcp.local",
		"_p2pchat._tcp.local",
		"_ftp._tcp.local",
		"_webdav._tcp.local",
		"_imap._tcp.local",
		"_pop3._tcp.local",
		"_domain._udp.local",
		"_ntp._udp.local",
		"_printer._tcp.local",
		"_ipp._tcp.local",
		"_ipps._tcp.local",
		"_daap._tcp.local",
		"_pulse-server._tcp.local"
	};
#endif

	int sock;
	in_port_t port;
	struct sockaddr_in mdns_addr;
	struct sockaddr_in local_ifaddr;

	time_t time_last_service_query;
	time_t time_next_disk_push;
	int query_interval = 120; /* seconds */
	int disk_push_interval = 600; /* seconds */

	std::map<std::string,short> label_cache;
	std::map<std::string,std::list<struct mdns_record> > record_cache;
};

#endif /* !defined _SERVICE_DISCOVERER_H */
