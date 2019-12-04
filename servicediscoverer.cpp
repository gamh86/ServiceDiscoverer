#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <iostream>
#include <list>
#include <map>

#define mDNS_MULTICAST "224.0.0.251"
#define mDNS_PORT 5353
#define mDNS_MAX_PACKET_SIZE 9000 /* includes ip hdr, udp hdr and dns hdr: RFC 6762 */
#define MDNS_LISTEN_INTERVAL 5

#define clear_struct(s) memset((s), 0, sizeof((*s)))

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
};

struct mdns_record
{
	uint16_t type;
	uint16_t klass;
	uint32_t ttl;
	uint16_t data_len;
	time_t cached;
	void *data;
};

struct mdns_srv_data
{
	uint16_t priority;
	uint16_t weight;
	uint16_t port;
	void *target;
};

class serviceDiscoverer
{
	public:

	serviceDiscoverer();

	~serviceDiscoverer();

	int mdns_query_service(const char *service_name);
	int mdns_listen(void);

	private:

	int startup(void);
	int mdns_handle_packet(void *, size_t);
	int mdns_handle_response_packet(void *, size_t);

	off_t label_get_offset(char *);
	int decode_name(void *, char *, char *);
	char *encode_name(char *);

	bool cached_record_is_stale(struct mdns_record&);
	void check_cached_records(void);
	uint16_t get_16bit_val(char *); /* parses from pointer into native byte order */
	uint32_t get_32bit_val(char *); /* ' ' ' ' */
	const char * klass_str(uint16_t);
	const char * type_str(uint16_t);

	bool is_query(uint16_t);
	bool is_response(uint16_t);
	bool should_flush_cache(uint16_t); /* checks for the CACHE FLUSH bit in class field */

	uint16_t new_txid(void); /* generate random 16-bit number */

	std::map<const char *,uint16_t> mdns_types =
	{
		{ "A", 1 }, /* host address */
		{ "PTR", 12 }, /* pointer record */
		{ "TXT", 16 }, /* text record */
		{ "SRV", 33 }, /* services record */
		{ "NSEC", 47 }
	};

	std::map<const char *,uint16_t> mdns_classes =
	{
		{ "IN", 1 }
	};

	std::list<std::string> services =
	{
		"_ipp._tcp.local",
		"_printer._sub._tcp.local",
		"_ntp._tcp.local"
	};

	int sock;
	in_port_t port;
	struct sockaddr_in mdns_addr;

	int query_interval = 60; /* seconds */
	time_t time_last_service_query;

	std::map<std::string,std::list<struct mdns_record> > cached_records;
};

serviceDiscoverer::serviceDiscoverer()
{
	srand(time(NULL));
	if (this->startup() < 0)
		abort();
}

serviceDiscoverer::~serviceDiscoverer()
{
	for (std::map<std::string,std::list<struct mdns_record> >::iterator map_iter = this->cached_records.begin();
			map_iter != this->cached_records.end();
			++map_iter)
	{
		std::list<struct mdns_record> &__list = map_iter->second;
		for (std::list<struct mdns_record>::iterator list_iter = __list.begin();
				list_iter != __list.end();
				++list_iter)
		{
			free(list_iter->data);
		}
	}
}

uint16_t serviceDiscoverer::new_txid(void)
{
	return (uint16_t)((rand() >> 16) & 0xffff);
}

#define DNS_LABEL_OFFSET_BIAS (0x100 * 0xc0)
off_t serviceDiscoverer::label_get_offset(char *p)
{
	return (((*p * 0x100) + *(p+1)) - DNS_LABEL_OFFSET_BIAS);
}

char *serviceDiscoverer::encode_name(char *name)
{
	size_t len = strlen(name);
	char *encoded_name = (char *)calloc(len * 2, 1);
	char *tmp = (char *)calloc(len + 2, 1);
	int i;
	char *dot;
	char *p;
	char *e;

	strcpy(tmp, name);
	strcat(tmp, ".");

	e = (tmp + strlen(tmp));

	p = tmp;
	while (true)
	{
		dot = memchr((void *)p, '.', (size_t)(e - p));

/*
 * We should always find a dot at the end
 * of each label after the strcat() above.
 */
		if (!dot)
		{
			std::cerr << __func__ << ": failed to find '.' char in name" << std::endl;
			return NULL;
		}

		encoded_name[i++] = (unsigned char)(dot - p);
		memcpy((void *)&encoded_name[i], (void *)p, (dot - p));
		i += (dot - p);

		p = ++dot;

		if (dot >= e)
			break;
	}

	free(tmp);
	tmp = NULL;

#ifdef DEBUG
	std::cerr << "Encoded name: " << encoded_name << std::endl;
#endif
	return encoded_name;
}

#define LABEL_JUMP_INDICATOR 0xc0
int serviceDiscoverer::decode_name(void *data, char *dest, char *name)
{
	bool jumped = false;
	off_t off;
	char *ptr;
	int didx = 0;
	int delta = 0;

	while (true)
	{
		if (*ptr == 0)
			break;

		if (*ptr >= LABEL_JUMP_INDICATOR)
		{
			off = this->label_get_offset(ptr);
			ptr = ((char *)data + off);
			jumped = true;
		}

		if (!isascii(*ptr) && !isdigit(*ptr) && *ptr < LABEL_JUMP_INDICATOR)
			dest[didx++] = '.';
		else
			dest[didx++] = *ptr;

		++ptr;

		if (!jumped)
			++delta;
	}

	dest[didx] = 0;

/*
 * Either NAME + DELTA == \x00 or NAME + DELTA == 0xCx (start of jump offset)
 */
	if (jumped)
		delta += 2;
	else
		++delta;

	return delta;
}

void serviceDiscoverer::check_cached_records(void)
{
	for (std::map<std::string,std::list<struct mdns_record> >::iterator map_iter = this->cached_records.begin();
				map_iter != this->cached_records.end();
				++map_iter)
	{
		std::list<struct mdns_record> &__list = map_iter->second;
		for (std::list<struct mdns_record>::iterator list_iter = __list.begin();
					list_iter != __list.end();
				)
		{
			if (this->cached_record_is_stale(*list_iter))
			{
				list_iter = __list.erase(list_iter);
				continue;
			}
			else
			{
				++list_iter;
			}
		}
	}
}

bool serviceDiscoverer::is_query(uint16_t flags)
{
	return !(flags & MDNS_RESPONSE);
}

bool serviceDiscoverer::is_response(uint16_t flags)
{
	return (flags & MDNS_RESPONSE);
}

uint32_t serviceDiscoverer::get_32bit_val(char *p)
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
	return ntohl(*((uint32_t *)p));
#else
	return *((uint32_t *)p);
#endif
}

uint16_t serviceDiscoverer::get_16bit_val(char *p)
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
	return ntohs(*((uint16_t *)p));
#else
	return *((uint16_t *)p);
#endif
}

bool serviceDiscoverer::should_flush_cache(uint16_t k)
{
	if (k & (1 << 15))
		return true;
	else
		return false;
}

bool serviceDiscoverer::cached_record_is_stale(struct mdns_record& record)
{
	if ((time(NULL) - record.cached) >= record.ttl)
		return true;
	else
		return false;
}

const char * serviceDiscoverer::klass_str(uint16_t klass)
{
	for (std::map<const char *,uint16_t>::iterator map_iter = this->mdns_classes.begin();
			map_iter != this->mdns_classes.end();
			++map_iter)
	{
		if (klass == map_iter->second)
			return map_iter->first;
	}

	return (const char *)"Unknown class";
}

const char *serviceDiscoverer::type_str(uint16_t type)
{
	for (std::map<const char *,uint16_t>::iterator map_iter = this->mdns_types.begin();
			map_iter != this->mdns_types.end();
			++map_iter)
	{
		if (type == map_iter->second)
			return map_iter->first;
	}

	return (const char *)"Unknown type";
}

int serviceDiscoverer::mdns_handle_response_packet(void *packet, size_t size)
{
	struct mdns_hdr *hdr = (struct mdns_hdr *)packet;
	struct mdns_record record;
	char *ptr = (char *)packet + sizeof(struct mdns_hdr);
	char *e = (char *)packet + size;
	char *decoded_name = (char *)calloc(512, 1);
	int delta;
	uint16_t type;
	uint16_t klass;
	uint32_t ttl;
	uint16_t data_len;
	uint16_t priority;
	uint16_t weight;
	void *data = NULL;
	uint16_t total_answers = 0;

	total_answers += htons(hdr->nr_as) + htons(hdr->nr_aa) + htons(hdr->nr_ad);

	while (true)
	{
		delta = this->decode_name(packet, decoded_name, ptr);

		if (delta < 0)
		{
			std::cerr << __func__ << ": failed to decode name" << std::endl;
			free(decoded_name);
			return -1;
		}

		ptr += delta;
		type = this->get_16bit_val(ptr);
		ptr += 2;
		klass = this->get_16bit_val(ptr);
		ptr += 2;
		ttl = this->get_32bit_val(ptr);
		ptr += 4;
		data_len = this->get_16bit_val(ptr);
		ptr += 2;

		data = calloc((data_len+1), 1);
		memcpy(data, ptr, data_len);
		ptr += data_len;
		clear_struct(&record);

		record.type = type;
		record.klass = klass;
		record.ttl = ttl;
		record.data_len = data_len;
		record.cached = time(NULL);
		record.data = data;

		std::map<std::string,std::list<struct mdns_record> >::iterator map_iter = this->cached_records.find(decoded_name);

		if (map_iter == this->cached_records.end())
		{
			map_iter->second.push_back(record);
			std::cout << "Cached record for \"" << decoded_name << "\"" << std::endl;
		}
		else
		{
			std::list<struct mdns_record> &__list = map_iter->second;
			std::list<struct mdns_record>::iterator list_iter;
			bool no_cache = false;

			list_iter = __list.begin();
			while (list_iter != __list.end())
			{
				if (list_iter->type == record.type && list_iter->klass == record.klass)
				{
					if (this->cached_record_is_stale(*list_iter) == true || this->should_flush_cache(klass) == true)
					{
						free(list_iter->data);
						__list.erase(list_iter);
						__list.push_back(record);
						std::cout << "Record for \"" << decoded_name << "\" is stale: removing from cache" << std::endl;
						std::cout << "Cached fresh record for \"" << decoded_name << "\" exists" << std::endl;
					}

					no_cache = true;
				}
			}

			if (!no_cache)
			{
				__list.push_back(record);
				std::cout << "Cached record for \"" << decoded_name << "\" exists" << std::endl;
			}
			else
			{
				free(data);
				data = NULL;
			}
		}

		--total_answers;
		if (!total_answers)
			break;
	}
}

int serviceDiscoverer::mdns_handle_packet(void *packet, size_t size)
{
	struct mdns_hdr *hdr = (struct mdns_hdr *)packet;
	char *ptr = (char *)packet + sizeof(hdr);
	uint16_t type;
	uint16_t klass;

	if (this->is_response(hdr->flags) == true)
	{
		return (this->mdns_handle_response_packet(packet, size));
	}

	char *e = ((char *)packet + size);
	char *decoded_name = (char *)calloc(512, 1);
	int delta = 0;

	while (true)
	{
		delta = this->decode_name(packet, decoded_name, ptr);

		if (delta < 0)
		{
			free(decoded_name);
			return -1;
		}

		ptr += delta;
		type = this->get_16bit_val(ptr);
		ptr += 2;
		klass = this->get_16bit_val(ptr);
		ptr += 2;

		std::cout << " Query [" << this->type_str(type) << " : " << this->klass_str(klass) << "] " << decoded_name << std::endl;

		if (ptr >= e)
			break;
	}

	return 0;

	fail_free_mem__hmdns:
	free(decoded_name);
	return -1;
}

int serviceDiscoverer::startup(void)
{
	struct ip_mreq mreq;
	struct sockaddr_in sin;
	int opt;

	clear_struct(&mreq);
	inet_aton(mDNS_MULTICAST, &mreq.imr_multiaddr);
	inet_aton("0.0.0.0", &mreq.imr_interface);

/* Get a random high port */
	this->port = ((rand() % (65535 - (IPPORT_RESERVED * 10))) + (IPPORT_RESERVED * 10));
	this->sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);

	clear_struct(&sin);
	sin.sin_addr.s_addr = INADDR_ANY;
	sin.sin_port = htons(this->port);
	bind(this->sock, (struct sockaddr *)&sin, (socklen_t)sizeof(sin));
	opt = 1;
	setsockopt(this->sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
	opt = 0;
	setsockopt(this->sock, IPPROTO_IP, IP_MULTICAST_LOOP, &opt, sizeof(opt));
	setsockopt(this->sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq));

	clear_struct(&this->mdns_addr);
	inet_aton(mDNS_MULTICAST, &this->mdns_addr.sin_addr);
	this->mdns_addr.sin_port = htons(5353);

	return 0;
}

int serviceDiscoverer::mdns_listen(void)
{
	fd_set rset;
	struct timeval tv = {0};
	int nr_ready;
	char *buffer = NULL;
	char *mdns_start;
	size_t buffer_size = USHRT_MAX+1;
	ssize_t bytes;

	buffer = (char *)calloc(buffer_size, 1);
	memset(buffer, 0, buffer_size);

	while (true)
	{
		FD_ZERO(&rset);
		FD_SET(this->sock, &rset);
		tv.tv_sec = MDNS_LISTEN_INTERVAL;

		nr_ready = select(this->sock + 1, &rset, NULL, NULL, &tv);

		if (nr_ready)
		{
			if (FD_ISSET(this->sock, &rset))
			{
				bytes = recv(this->sock, buffer, buffer_size, 0); 
				buffer[bytes] = 0;
				mdns_start = (buffer + sizeof(struct udphdr));
				this->mdns_handle_packet((void *)mdns_start, (size_t)bytes);
			}
		}

		this->check_cached_records();
	}
}

int serviceDiscoverer::mdns_query_service(const char *hostname)
{
	char *encoded = this->encode_name((char *)hostname);
	uint16_t klass;
	uint16_t type;
	struct udphdr udphdr;

	if (!encoded)
		return -1;

	struct mdns_hdr hdr;
	size_t enc_len = strlen(encoded);

	clear_struct(&udphdr);

	udphdr.source = htons(this->port);
	udphdr.dest = htons(mDNS_PORT);
	udphdr.len = htons(8 + sizeof(hdr) + strlen(encoded) + 1 + 4);

	clear_struct(&hdr);
	hdr.txid = this->new_txid();
	hdr.nr_qs = htons(1);

	char *t;
	char *tmp = (char *)calloc(1024, 1);

	if (!tmp)
		goto fail_free_mem__mdnsq;

	memset(tmp, 0, 1024);
	t = tmp;

	memcpy((void *)t, &udphdr, sizeof(udphdr));
	t += sizeof(udphdr);
	memcpy((void *)t, &hdr, sizeof(hdr));
	t += sizeof(hdr);

/*
 * We want to keep the NULL byte at the end.
 */
	memcpy((void *)t, (void *)encoded, enc_len+1);
	t += enc_len+1;

	type = htons(this->mdns_types["SRV"]);
	klass = htons(this->mdns_classes["IN"]);

	memcpy((void *)t, &type, 2);
	t += 2;
	memcpy((void *)t, &klass, 2);
	t += 2;

	ssize_t bytes;
	bytes = sendto(this->sock, tmp, (t - tmp), 0, (struct sockaddr *)&this->mdns_addr, (socklen_t)sizeof(this->mdns_addr));
	if (bytes <= 0)
	{
		std::cerr << __func__ << ": failed to send mDNS packet (" << strerror(errno) << ")" << std::endl;
		goto fail_free_mem__mdnsq;
	}

#ifdef DEBUG
	std::cout << "Sent mDNS query for service " << hostname << std::endl;
#endif

	this->time_last_service_query = time(NULL);
	free(encoded);
	encoded = NULL;

	free(tmp);
	tmp = NULL;

	return 0;

	fail_free_mem__mdnsq:

	if (tmp)
		free(tmp);

	if (encoded)
		free(encoded);

	return -1;
}

int
main(void)
{
	serviceDiscoverer *sd = new serviceDiscoverer();
	sd->mdns_query_service((const char *)"_ipp._tcp.local");
	sd->mdns_listen();

	delete sd;

	exit(EXIT_SUCCESS);

	fail:
	exit(EXIT_FAILURE);
}