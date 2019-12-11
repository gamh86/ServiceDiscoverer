#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <iostream>
#include <list>
#include <map>
#include <vector>

#define mDNS_MULTICAST "224.0.0.251"
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

	std::map<std::string,std::list<struct mdns_record> > cached_records;
};

serviceDiscoverer::serviceDiscoverer()
{
	srand(time(NULL));
	if (this->startup() < 0)
	{
		std::cerr << "aborting" << std::endl;
		abort();
	}
}

serviceDiscoverer::~serviceDiscoverer()
{
	for (std::map<std::string,std::list<struct mdns_record> >::iterator map_iter = this->cached_records.begin();
			map_iter != this->cached_records.end();
			++map_iter)
	{
		for (std::list<struct mdns_record>::iterator list_iter = map_iter->second.begin();
				list_iter != map_iter->second.end();
				++list_iter)
		{
			if (list_iter->text_data != NULL)
				delete list_iter->text_data;
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
/*
 * ALWAYS remember it MUST be unsigned char, or you'll
 * get a NEGATIVE result for *p * 0x100 !
 */
	return ((((unsigned char)*p * 0x100) + (unsigned char)*(p+1)) - DNS_LABEL_OFFSET_BIAS);
}

std::string serviceDiscoverer::encode_data(std::vector<struct Query> queries)
{
	char *encoded = NULL;
	char *tmp = NULL;
	size_t len;
	std::map<std::string,uint16_t> label_cache;
	std::map<std::string,uint16_t>::iterator map_iter;
	std::list<std::string> tokens;
	std::string data;
	bool need_null = true;
	int pos = 0;
	int nr_qs = 0;

	encoded = (char *)calloc(8192, 1);

	if (!encoded)
	{
		error("failed to allocate memory for output data");
		return data;
	}

	tmp = (char *)calloc(2048, 1);

	if (!tmp)
	{
		error("failed to allocate temporary memory");
		return data;
	}

	nr_qs = queries.size();
#ifdef DEBUG
	std::cerr << "Number of queries to encode: " << nr_qs << std::endl;
#endif
	for (int j = 0; j < nr_qs; ++j)
	{
		tokens.clear();
		tokens = this->tokenize_name(queries[j].name, '.');

		for (std::list<std::string>::iterator list_iter = tokens.begin();
				list_iter != tokens.end();
				++list_iter)
		{
#ifdef DEBUG
			std::cerr << "Token: " << *list_iter << std::endl;
			std::cerr << "Length: " << list_iter->length() << std::endl;
#endif
			if ((map_iter = label_cache.find(*list_iter)) != label_cache.end())
			{
#ifdef DEBUG
				std::cerr << "Token \"" << *list_iter << "\" already in cache" << std::endl;
#endif
				uint16_t off = map_iter->second;
				off |= (0xc0 << 8);
				off = htons(off);
				memcpy((void *)&encoded[pos], (void *)&off, 2);
				pos += 2;
				need_null = false;
				break;
#ifdef DEBUG
				std::cerr << "Current position: " << pos << std::endl;
#endif
			}
			else
			{
#ifdef DEBUG
				std::cerr << "Encoding token \"" << *list_iter << "\"" << std::endl;
#endif
				uint16_t off;
				off = (12 + pos);
				label_cache.insert(std::pair<std::string,uint16_t>(*list_iter, off));
				encoded[pos++] = list_iter->length();
				list_iter->copy((char *)&encoded[pos], list_iter->length(), 0);
				pos += list_iter->length();
#ifdef DEBUG
				std::cerr << "Current position: " << pos << std::endl;
#endif
			}
		}

		if (need_null == true)
			encoded[pos++] = 0;
		else
			need_null = true;

		uint16_t type = htons(queries[j].type);
		uint16_t klass = htons(queries[j].klass);
		memcpy((void *)&encoded[pos], (void *)&type, 2);
		pos += 2;
		memcpy((void *)&encoded[pos], (void *)&klass, 2);
		pos += 2;
	}

	encoded[pos] = 0;

	data.append(encoded, pos);

	free(tmp);
	free(encoded);

	return data;
}

#define LABEL_JUMP_INDICATOR 0xc0
std::string serviceDiscoverer::decode_name(void *data, char *name, int *_delta)
{
	bool jumped = false;
	off_t off;
	char *ptr;
	int didx = 0;
	int delta = 0;
	unsigned char len;
	std::string decoded;

#ifdef DEBUG
	std::cerr << "Entered decode_name(): sitting at:\n" << std::endl;
	for (int i = 0; i < 10; ++i)
		fprintf(stderr, "\\x%02hhx", name[i]);
	fprintf(stderr, "\n");
	std::cerr << "(this is " << (name - (char *)data) << " bytes from start of data)" << std::endl;
#endif
	ptr = name;

	decoded.clear();
	while (true)
	{
		len = (unsigned char)*ptr;

		if (!len)
			break;
		else
		if (len >= LABEL_JUMP_INDICATOR)
		{
#ifdef DEBUG
			std::cerr << "Jumping! Currently at:\n" << std::endl;
			for (int i = 0; i < 10; ++i)
				fprintf(stderr, "\\x%02hhx", ptr[i]);
			fprintf(stderr, "\n");
			std::cerr << "Name thus far: " << decoded << std::endl;
#endif
			off = this->label_get_offset(ptr);
#ifdef DEBUG
			std::cerr << "Jump to start of mDNS packet + " << off << " bytes" << std::endl;
#endif
			ptr = ((char *)data + off);
#ifdef DEBUG
			std::cerr << "Now at:\n" << std::endl;
			for (int i = 0; i < 10; ++i)
				fprintf(stderr, "\\x%02hhx", ptr[i]);
			fprintf(stderr, "\n");
#endif
			jumped = true;
			continue;
		}
		else
		{
			if (decoded.length() > 0)
				decoded.push_back('.');

			++ptr;
			decoded.append(ptr, len);
			ptr += len;

			if (jumped == false)
				delta += len + 1;
		}
	}

	//dest[didx] = 0;

/*
 * Either NAME + DELTA == \x00 or NAME + DELTA == 0xCx (start of jump offset)
 */
	if (jumped == true)
		delta += 2;
	else
		++delta;

	*_delta = delta;

	return decoded;
}

void serviceDiscoverer::check_cached_records(void)
{
#ifdef DEBUG
	std::cerr << "Checking cache for stale records" << std::endl;
#endif
	for (std::map<std::string,std::list<struct mdns_record> >::iterator map_iter = this->cached_records.begin();
				map_iter != this->cached_records.end();
				++map_iter)
	{
		for (std::list<struct mdns_record>::iterator list_iter = map_iter->second.begin();
					list_iter != map_iter->second.end();
				)
		{
			if (this->cached_record_is_stale(*list_iter))
			{
#ifdef DEBUG
				std::cerr << "Removing stale record from cache for \"" << map_iter->first << "\"" << std::endl;
#endif
				list_iter = map_iter->second.erase(list_iter);
				continue;
			}
			else
			{
				++list_iter;
			}
		}
	}
}

bool serviceDiscoverer::is_udp_pkt(char *data)
{
	struct iphdr *ip = (struct iphdr *)data;

	return ip->protocol == IPPROTO_UDP;
}

bool serviceDiscoverer::is_mdns_pkt(char *data)
{
	struct udphdr *udp = (struct udphdr *)((char *)data + sizeof(struct iphdr));

	if (ntohs(udp->dest) != mDNS_PORT && ntohs(udp->source) != mDNS_PORT)
		return false;
	else
		return true;
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
	return ntohl(*((uint32_t *)p));
}

uint16_t serviceDiscoverer::get_16bit_val(char *p)
{
	return ntohs(*((uint16_t *)p));
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

std::string serviceDiscoverer::timestamp_to_str(time_t tstamp)
{
	static char tmp[128];
	struct tm tm;

	if (!gmtime_r((const time_t *)&tstamp, &tm))
	{
		std::cerr << __func__ << ": gmtime_r error (" << strerror(errno) << ")" << std::endl;
		return NULL;
	}

	strftime(tmp, 128, "%a %d %b %Y %H:%M:%S", &tm);
	std::string __ret = tmp;

	return __ret;
}

void serviceDiscoverer::mdns_save_cached_records(void)
{
	time_t timestamp = time(NULL);
	std::string filename;
	FILE *fp = NULL;
	char timestamp_str[64];

	sprintf(timestamp_str, "%ld", timestamp);

	filename.append("mdns_local_services_");
	filename.append(timestamp_str);
	filename.append(".txt");

	fp = fdopen(open(filename.data(), O_RDWR|O_TRUNC|O_CREAT, S_IRUSR|S_IWUSR), "r+");

	if (!fp)
	{
		std::cerr << " *** Failed to save cached records in file ***" << std::endl;
		return;
	}

	for (std::map<std::string,std::list<struct mdns_record> >::iterator map_iter = this->cached_records.begin();
			map_iter != this->cached_records.end();
			++map_iter)
	{
		if (map_iter->second.empty() || map_iter->first.length() < 3)
			continue;

		fprintf(fp, " Records for \"%s\"\n\n", map_iter->first.data());

		for (std::list<struct mdns_record>::iterator list_iter = map_iter->second.begin();
				list_iter != map_iter->second.end();
				++list_iter)
		{
			fprintf(fp,
					"\n"
					" Type          %s\n"
					" Class         %s\n"
					" Cached        %s\n",
					this->type_str(list_iter->type),
					this->type_str(list_iter->klass),
					this->timestamp_to_str(list_iter->cached).data());

			if (list_iter->type == this->mdns_types["A"])
			{
				fprintf(fp,
						" Address       %s\n\n",
						inet_ntoa(list_iter->inet4));
			}
			else
			if (list_iter->type == this->mdns_types["SRV"])
			{
				fprintf(fp,
						" Priority      %hu\n"
						" Weight        %hu\n"
						" Port          %hu\n"
						" Target        %s\n\n",
						list_iter->srv_data.priority,
						list_iter->srv_data.weight,
						list_iter->srv_data.port,
						list_iter->srv_data.target.data());
			}
			else
			if (list_iter->type == this->mdns_types["TXT"])
			{
				fprintf(fp, "\n");
				for (std::map<std::string,std::string>::iterator _list_iter = list_iter->text_data->begin();
						_list_iter != list_iter->text_data->end();
						++_list_iter)
				{
					fprintf(fp, "    %s=%s\n", _list_iter->first.data(), _list_iter->second.data());
				}

				fprintf(fp, "\n");
			}
			else
			if (list_iter->type == this->mdns_types["AAAA"])
			{
				static char ipv6_str[INET6_ADDRSTRLEN];

				inet_ntop(AF_INET6, (void *)&record.inet6, ipv6_str, INET6_ADDRSTRLEN);
				fprintf(fp,
					" IPv6 Address  %s\n\n",
					ipv6_str);
			}
			else
			if (list_iter->type == this->mdns_types["PTR"])
			{
				fprintf(fp,
					" Domain Name   %s\n\n",
					list_iter->domain_name.data());
			}
		}
	}

	fflush(fp);
	fclose(fp);
	fp = NULL;

	return;
}

void serviceDiscoverer::mdns_print_record(std::string host, struct mdns_record& record)
{
	std::cout << " Host          " << host << std::endl;
	uint32_t age = (time(NULL) - record.cached);
	fprintf(stdout,
			" Type          %s (%hu)\n"
			" Class         %s (%hu)\n"
			" Time-to-Live  %u second%s\n"
			" Age           %u second%s\n",
			this->type_str(record.type), record.type, this->klass_str(record.klass), record.klass,
			record.ttl,
			record.ttl == 1 ? "" : "s",
			age,
			age == 1 ? "" : "s");
			
	if (record.type == this->mdns_types["A"])
	{
		fprintf(stdout,
			" IPv4 Address  %s\n\n",
			inet_ntoa(record.inet4));
	}
	else
	if (record.type == this->mdns_types["SRV"])
	{
		fprintf(stdout,
			" Priority      %hu\n"
			" Weight        %hu\n"
			" Port          %hu\n",
			record.srv_data.priority,
			record.srv_data.weight,
			record.srv_data.port);
		std::cout << " Target        " << record.srv_data.target << "\n" << std::endl;
	}
	else
	if (record.type == this->mdns_types["TXT"] && record.text_data != NULL)
	{
		fprintf(stdout, "\n");
		for (std::map<std::string,std::string>::iterator map_iter = record.text_data->begin();
				map_iter != record.text_data->end();
				++map_iter)
		{
			fprintf(stdout, "    %s=%s\n", map_iter->first.data(), map_iter->second.data());
		}

		fprintf(stdout, "\n");
	}
	else
	if (record.type == this->mdns_types["AAAA"])
	{
		static char ipv6_str[INET6_ADDRSTRLEN];
		inet_ntop(AF_INET6, (void *)&record.inet6, ipv6_str, INET6_ADDRSTRLEN);
		fprintf(stdout,
			" IPv6 Address  %s\n\n",
			ipv6_str);
	}
	else
	if (record.type == this->mdns_types["PTR"])
	{
		fprintf(stdout,
			" Domain Name   %s\n\n",
			record.domain_name.data());
	}

	std::cout << std::endl;
}

std::map<std::string,std::string> *serviceDiscoverer::mdns_parse_text_record(void *data, size_t len)
{
	char *p = (char *)data;
	const char *end = (char *)data + len;
	char *e;
	char *eq;
	int kvlen;

	if (len == 1 && *p == 0)
		return NULL;
/*
 * RFC 6763: MUST ignore a text record
 * that begins with a missing key.
 */
	if (((char *)data)[0] == '=')
		return NULL;

	std::map<std::string,std::string> *__ret = new std::map<std::string,std::string>();
	std::string key;
	std::string value;

	while (p < end)
	{
/*
 * Length encoded in byte before key/value pair begins.
 */
		kvlen = (int)*p;
		++p;
		assert(kvlen > 0);
		e = (p + kvlen);

		if (e > end)
		{
			errno = EPROTO;
			error("key start + length of key/value pair is beyond end of data");
			fprintf(stderr, "(%.*s)\n", (int)kvlen, p);
			delete __ret;
			return NULL;
		}

		eq = (char *)memchr(p, '=', (e - p));

#if 0
/*
 * Data in the text record doesn't always have to be
 * key/value pair. A token on its own simply acts like
 * a boolean, to mean that it exists.
 */
		if (!eq)
		{
			std::cerr << __func__ << ": failed to find '=' separator!" << std::endl;
			delete __ret;
			return NULL;
		}
#endif
		key.clear();
		value.clear();

		if (!eq)
		{
			key.append(p, (e - p));
			value.append("true");
		}
		else
		{
			key.append(p, (eq - p));
			p = ++eq;
			value.append(p, (e - p));
		}

		p = e;
/*
 * Ignore repeated occurences of keys.
 */
		if (__ret->find(key) == __ret->end())
			__ret->insert(std::pair<std::string,std::string>(key, value));
	}

#ifdef DEBUG
	std::cerr << "Got the following key/value pairs from the text record:\n" << std::endl;
	for (std::map<std::string,std::string>::iterator map_iter = __ret->begin();
				map_iter != __ret->end();
				++map_iter)
	{
		std::cerr << map_iter->first << "=" << map_iter->second << std::endl;
	}
#endif

	return __ret;
}

int serviceDiscoverer::mdns_parse_queries(void *packet, size_t size, void *data_start, uint16_t nr)
{
	if (!nr)
		return 0;

	struct mdns_hdr *hdr = NULL;
	std::string decoded;
	uint16_t type;
	uint16_t klass;
	int delta = 0;
	char *ptr = (char *)data_start;

	while (true)
	{
#ifdef DEBUG
		for (int i = 0; i < 8; ++i)
			fprintf(stderr, "\\x%02hhx", ptr[i]);
		fprintf(stderr, "\n");
#endif
		decoded = this->decode_name(packet, ptr, &delta);

		ptr += delta;

		type = this->get_16bit_val(ptr);
		ptr += 2;
		klass = this->get_16bit_val(ptr);
		ptr += 2;

		std::cerr << "\nQuery  \"" << decoded << "\" [" << this->type_str(type) << " : " << this->klass_str(klass) << "]\n" << std::endl;

		--nr;
		if (!nr)
			break;
	}

	return (int)((char *)ptr - (char *)data_start);
}

int serviceDiscoverer::mdns_parse_answers(void *packet, size_t size, void *data_start, uint16_t nr)
{
	if (!nr)
		return 0;

	std::string decoded;
	struct mdns_record record;
	char *ptr = (char *)data_start;
	int delta;

	clear_struct(&record);
	record.text_data = NULL;

	while (true)
	{
		decoded = this->decode_name(packet, ptr, &delta);
		ptr += delta;

		record.type = this->get_16bit_val(ptr);
		ptr += 2;
		record.klass = this->get_16bit_val(ptr);
		ptr += 2;
		record.ttl = this->get_32bit_val(ptr);
		ptr += 4;
		record.data_len = this->get_16bit_val(ptr);
		ptr += 2;
		record.cached = time(NULL);

		if (record.type == this->mdns_types["NSEC"])
		{
			ptr += record.data_len;
			break;
		}

		if (record.type == this->mdns_types["A"])
		{
			memcpy(&record.inet4, ptr, 4);
			ptr += 4;
		}
		else
		if (record.type == this->mdns_types["TXT"])
		{
			record.text_data = this->mdns_parse_text_record((void *)ptr, record.data_len);
			ptr += record.data_len;
		}
		else
		if (record.type == this->mdns_types["AAAA"])
		{
			memcpy((void *)&record.inet6, (void *)ptr, 16);
			ptr += 16;
		}
		else
		if (record.type == this->mdns_types["SRV"])
		{
			record.srv_data.priority = this->get_16bit_val(ptr);
			ptr += 2;
			record.srv_data.weight = this->get_16bit_val(ptr);
			ptr += 2;
			record.srv_data.port = this->get_16bit_val(ptr);
			ptr += 2;

			record.srv_data.target = this->decode_name(packet, ptr, &delta);
			ptr += delta;
		}
		else
		if (record.type == this->mdns_types["PTR"])
		{
			record.domain_name = this->decode_name(packet, ptr, &delta);
			ptr += delta;
		}
		else
		{
			ptr += record.data_len;
		}

		this->mdns_print_record(decoded, record);

		std::map<std::string,std::list<struct mdns_record> >::iterator map_iter = this->cached_records.find(decoded);
		if (map_iter == this->cached_records.end())
		{
#ifdef DEBUG
			std::cerr << "No record in cache for " << decoded << ": caching record" << std::endl;
#endif
			std::list<struct mdns_record> __list;
			__list.push_back(record);
			this->cached_records.insert( std::pair<std::string,std::list<struct mdns_record> >(decoded, __list) );
#ifdef DEBUG
			std::cerr << "Record for " << decoded << " added to cache" << std::endl;
#endif
		}
		else
		{
			for (std::list<struct mdns_record>::iterator list_iter = map_iter->second.begin();
					list_iter != map_iter->second.end();
					++list_iter)
			{
				if (list_iter->type == record.type && list_iter->klass == record.klass)
				{
#ifdef DEBUG
					std::cerr << "Found previous record in cache for " << decoded << std::endl;
					std::cerr << "Age = " << (time(NULL) - list_iter->cached) << " seconds" << std::endl;
					std::cerr << "(ttl = " << list_iter->ttl << " seconds)" << std::endl;
#endif
					map_iter->second.erase(list_iter);
					map_iter->second.push_back(record);
					break;
				}
			}
		}

		--nr;

		if (!nr)
			break;
	}

	return (int)((char *)ptr - (char *)data_start);
}

int serviceDiscoverer::mdns_handle_packet(void *packet, size_t size)
{
	struct mdns_hdr *hdr = (struct mdns_hdr *)packet;
	char *ptr = (char *)packet + sizeof(struct mdns_hdr);
	int delta;

	delta = this->mdns_parse_queries(packet, size, (void *)ptr, ntohs(hdr->nr_qs));
	ptr += delta;
	delta = this->mdns_parse_answers(packet, size, (void *)ptr, ntohs(hdr->nr_as));
	ptr += delta;
	delta = this->mdns_parse_answers(packet, size, (void *)ptr, ntohs(hdr->nr_aa));
	ptr += delta;
	delta = this->mdns_parse_answers(packet, size, (void *)ptr, ntohs(hdr->nr_ad));
	ptr += delta;

	return 0;
}

int serviceDiscoverer::startup(void)
{
	struct ip_mreq mreq;
	struct sockaddr_in sin;
	struct ifreq ifr;
	struct if_nameindex *ifnames = NULL;
	int opt;
	int idx;

	clear_struct(&ifr);
	if (!(ifnames = if_nameindex()))
	{
		std::cerr << __func__ << ": if_nameindex error (" << strerror(errno) << ")" << std::endl;
		return -1;
	}

	idx = 0;
	while (ifnames[idx].if_name[0] != 'w')
	{
		++idx;
	}

	if (ifnames[idx].if_name[0] != 'w')
	{
		std::cerr << __func__ << ": failed to get wireless interface" << std::endl;
		if (ifnames)
			if_freenameindex(ifnames);
		return -1;
	}

	strcpy(ifr.ifr_name, ifnames[idx].if_name);
	if_freenameindex(ifnames);

	if ((this->sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP)) < 0)
	{
		std::cerr << __func__ << ": failed to open socket (" << strerror(errno) << ")" << std::endl;
		return -1;
	}

	if (ioctl(this->sock, SIOCGIFADDR, &ifr) < 0)
	{
		std::cerr << __func__ << ": ioctl SIOCGIFADDR error (" << strerror(errno) << ")" << std::endl;
		return -1;
	}

	memcpy(&this->local_ifaddr, &ifr.ifr_addr, sizeof(struct sockaddr_in));

	clear_struct(&mreq);
	inet_aton(mDNS_MULTICAST, &mreq.imr_multiaddr);
	inet_aton("0.0.0.0", &mreq.imr_interface);

/* Get a random high port */
	this->port = ((rand() % (65535 - (IPPORT_RESERVED * 10))) + (IPPORT_RESERVED * 10));

	clear_struct(&sin);
	sin.sin_addr.s_addr = INADDR_ANY;
	sin.sin_port = htons(this->port);

	if (bind(this->sock, (struct sockaddr *)&sin, (socklen_t)sizeof(sin)) != 0)
	{
		std::cerr << __func__ << ": failed to bind socket (" << strerror(errno) << ")" << std::endl;
		return -1;
	}

	opt = 1;
	if (setsockopt(this->sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
	{
		std::cerr << __func__ << ": failed to set option SO_REUSEADDR (" << strerror(errno) << ")" << std::endl;
		return -1;
	}

	if (setsockopt(this->sock, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt)) < 0)
	{
		std::cerr << __func__ << ": failed to set option IP_HDRINCL (" << strerror(errno) << ")" << std::endl;
		return -1;
	}

	opt = 0;
	if (setsockopt(this->sock, IPPROTO_IP, IP_MULTICAST_LOOP, &opt, sizeof(opt)) < 0)
	{
		std::cerr << __func__ << ": failed to set option IP_MULTICAST_LOOP (" << strerror(errno) << ")" << std::endl;
		return -1;
	}

	if (setsockopt(this->sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0)
	{
		std::cerr << __func__ << ": failed to set option IP_ADD_MEMBERSHIP (" << strerror(errno) << ")" << std::endl;
		return -1;
	}

	clear_struct(&this->mdns_addr);
	inet_aton(mDNS_MULTICAST, &this->mdns_addr.sin_addr);
	this->mdns_addr.sin_port = htons(5353);

	this->time_next_disk_push = (time(NULL) + this->disk_push_interval);
	this->time_last_service_query = 0;

	return 0;
}

bool serviceDiscoverer::should_replace_file(void)
{
	if ((time(NULL) - this->time_next_disk_push) >= this->disk_push_interval)
	{
		this->time_next_disk_push = (time(NULL) + this->disk_push_interval);
		return true;
	}
	else
	{
		return false;
	}
}

bool serviceDiscoverer::should_do_query(void)
{
	if ((time(NULL) - this->time_last_service_query) >= this->query_interval)
		return true;
	else
		return false;
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
		tv.tv_sec = 100;

		nr_ready = select(this->sock + 1, &rset, NULL, NULL, &tv);

		if (nr_ready)
		{
			if (FD_ISSET(this->sock, &rset))
			{
				bytes = recv(this->sock, buffer, buffer_size, 0);

				if (this->is_udp_pkt(buffer) == false)
				{
					continue;
				}

				if (this->is_mdns_pkt(buffer) == false)
				{
					continue;
				}
#ifdef DEBUG
				fprintf(stderr, "Dumping hex of received mDNS packet (%ld bytes)\n", bytes);
				for (int i = 0; i < (int)bytes; ++i)
				{
					fprintf(stderr, "\\x%02hhx", buffer[i]);
				}
				fprintf(stderr, "\n");
#endif
				buffer[bytes] = 0;
				mdns_start = ((char *)buffer + sizeof(struct iphdr) + sizeof(struct udphdr));
				this->mdns_handle_packet((void *)mdns_start, (size_t)bytes);
			}
		}
		else
		{
			/* do other stuff in the meantime */
		}

		this->check_cached_records();

		if (this->should_replace_file() == true)
			this->mdns_save_cached_records();

		if (this->should_do_query() == true)
			this->mdns_query_all_services();
	}
}

void serviceDiscoverer::default_iphdr(struct iphdr *ip)
{
	ip->version = 4;
	ip->ihl = 5;
	ip->tos = 0;
	ip->id = htons(this->new_txid());
	ip->frag_off = 0;
	ip->ttl = 255;
	ip->protocol = IPPROTO_UDP;
	ip->check = 0;
	ip->saddr = this->local_ifaddr.sin_addr.s_addr;
	ip->daddr = this->mdns_addr.sin_addr.s_addr;

	return;
}

void serviceDiscoverer::default_udphdr(struct udphdr *udp)
{
	udp->source = htons(this->port);
	udp->dest = htons(mDNS_PORT);
	udp->check = 0;
}

std::list<std::string> serviceDiscoverer::tokenize_name(std::string name, char c)
{
	char *p = NULL;
	char *e = NULL;
	char *sep = NULL;

	std::list<std::string> list;
	std::string tmp = name;
	std::string token;
	tmp.push_back(c);

	p = (char *)tmp.data();
	e = (p + tmp.length());

	while (true)
	{
		sep = (char *)memchr(p, c, (e - p));
		if (!sep)
		{
			errno = EPROTO;
			error("failed to find separator in name");
			list.clear();
			return list;
		}

		token.clear();
		token.append(p, (sep - p));
		list.push_back(token);

		p = ++sep;

		if (p >= e)
			break;
	}

	return list;
}

int serviceDiscoverer::mdns_query_all_services(void)
{
	struct iphdr *ip;
	struct udphdr *udp;
	struct mdns_hdr *mdns;
	char *buffer = (char *)calloc(32768, 1);
	char *b = buffer;
	char *ptr = NULL;
	std::string data;
	size_t len;

	if (!buffer)
	{
		error("failed to allocate memory for buffer");
		return -1;
	}

	memset(buffer, 0, 32768);
	ip = (struct iphdr *)buffer;
	udp = (struct udphdr *)((char *)buffer + sizeof(*ip));
	mdns = (struct mdns_hdr *)((char *)buffer + sizeof(*ip) + sizeof(*udp));

	this->default_iphdr(ip);
	this->default_udphdr(udp);
	mdns->txid = htons(this->new_txid());
	b = (char *)buffer + sizeof(*ip) + sizeof(*udp) + sizeof(*mdns);

	data = this->encode_data(this->services);
	ptr = (char *)data.data();
	memcpy((void *)b, ptr, data.length());
	b += data.length();
	*b = 0;

	len = calc_offset(buffer, b);
	ip->tot_len = (uint16_t)htons(len);
	udp->len = (uint16_t)htons(len - 20);
	mdns->nr_qs = htons(this->services.size());

#ifdef DEBUG
	std::cerr << "Total length: " << ntohs(ip->tot_len) << std::endl;
	std::cerr << "UDP length: " << ntohs(udp->len) << std::endl;
	std::cerr << "MDNS Data length: " << data.length() << std::endl;
#endif

#if 0
	for (std::list<std::string>::iterator list_iter = this->services.begin();
			list_iter != this->services.end();
			++list_iter)
	{
		tmp_string.clear();
		tmp_string.append(list_iter->data(), list_iter->length());
		tmp_string.push_back('.');

		std::list<std::string> tokens = this->tokenize_name(tmp_string, '.');

		if (tokens.empty())
		{
			std::cerr << __func__ << ": failed to tokenize \"" << *list_iter << "\"" << std::endl;
			continue;
		}

		for (std::list<std::string>::iterator iter = tokens.begin();
				iter != tokens.end();
				++iter)
		{
			std::map<std::string,uint16_t>::iterator lc_iter = label_cache.find(*iter);
			if (lc_iter != label_cache.end())
			{
				uint16_t _off = htons(lc_iter->second);
				unsigned char *__uc = (unsigned char *)&_off;
				*__uc |= (unsigned char)LABEL_JUMP_INDICATOR;
				memcpy(b, &_off, 2);
				b += 2;

				break;
			}
			else
			{
				uint16_t _off = (uint16_t)calc_offset(mdns, b);
				label_cache.insert(std::pair<std::string,uint16_t>(*iter, _off));
				*b++ = (char)iter->length();
				iter->copy(b, iter->length());
				b += iter->length();
			}
		}

		memcpy(b, &type, 2);
		b += 2;
		memcpy(b, &klass, 2);
		b += 2;

		++nr_qs;
	}
#endif

	ssize_t bytes;

#ifdef DEBUG
	len = ntohs(ip->tot_len);
	std::cerr << "Sending packet of size " << len << " bytes:\n" << std::endl;
	for (int i = 0; (size_t)i < len; ++i)
		fprintf(stderr, "\\x%02hhx", buffer[i]);
	fprintf(stderr, "\n");
#endif

	bytes = sendto(this->sock, buffer, len, 0, (struct sockaddr *)&this->mdns_addr, (socklen_t)sizeof(this->mdns_addr));
	free(buffer);
	buffer = NULL;

	this->time_last_service_query = time(NULL);
	return 0;
}

int serviceDiscoverer::mdns_query_service(std::string hostname)
{
	std::string encoded;
	struct iphdr *ip;
	struct udphdr *udp;
	struct mdns_hdr *mdns;
	size_t len;
	std::vector<struct Query> args;
	struct Query query;
	char *buffer = NULL;
	char *b = NULL;

	buffer = (char *)calloc(8192, 1);
	if (!buffer)
	{
		error("failed to allocate memory for packet buffer");
		return -1;
	}

	query.name = hostname;
	query.type = this->mdns_types["ANY"];
	query.klass = this->mdns_classes["IN"];

	args.push_back(query);

	encoded = this->encode_data(args);

	ip = (struct iphdr *)buffer;
	udp = (struct udphdr *)((char *)buffer + sizeof(*ip));
	mdns = (struct mdns_hdr *)((char *)buffer + sizeof(*ip) + sizeof(*udp));

	this->default_iphdr(ip);
	this->default_udphdr(udp);

	len = encoded.length();
	ip->tot_len = htons(20 + 8 + 12 + len);
	udp->len = htons(8 + 12 + len);

	mdns->txid = this->new_txid();
	mdns->nr_qs = htons(1);

	b = (char *)buffer + sizeof(*ip) + sizeof(*udp) + sizeof(*mdns);
	memcpy((void *)b, (void *)encoded.data(), len);
	b += len;
	*b = 0;

	len = (size_t)calc_offset(buffer, b);

	ssize_t bytes;
	bytes = sendto(this->sock, buffer, len, 0, (struct sockaddr *)&this->mdns_addr, (socklen_t)sizeof(this->mdns_addr));
	if (bytes <= 0)
	{
		error("failed to send mDNS packet");
		free(buffer);
		return -1;
	}

#ifdef DEBUG
	std::cout << "Sent mDNS query for service " << hostname << std::endl;
#endif

	this->time_last_service_query = time(NULL);

	free(buffer);
	buffer = NULL;

	return 0;
}

static serviceDiscoverer *sd = NULL;

static void
clean_up(int signo)
{
	if (signo != SIGINT && signo != SIGQUIT)
		return;

	if (sd != NULL)
		delete sd;

	std::cerr << "Caught signal (" << signo << ")" << std::endl;
	exit(signo);
}

int
main(void)
{
	signal(SIGINT, clean_up);
	signal(SIGQUIT, clean_up);

	sd = new serviceDiscoverer();
	sd->mdns_query_all_services();
	sd->mdns_listen();

	delete sd;

	exit(EXIT_SUCCESS);

	fail:
	exit(EXIT_FAILURE);
}
