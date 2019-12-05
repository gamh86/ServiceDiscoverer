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
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <iostream>
#include <list>
#include <map>

#define mDNS_MULTICAST "224.0.0.251"
#define mDNS_PORT 5353
#define mDNS_MAX_PACKET_SIZE 9000 /* includes ip hdr, udp hdr and dns hdr: RFC 6762 */

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
	std::string domain_name;
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

	bool should_replace_file(void);
	bool should_do_query(void);

	std::string timestamp_to_str(time_t);
	void mdns_save_cached_records(void);

	void default_iphdr(struct iphdr *);
	void default_udphdr(struct udphdr *);

	off_t label_get_offset(char *);
	std::string decode_name(void *, char *, int *);
	std::string encode_name(std::string);

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
		{ "A", 1 }, /* host address */
		{ "PTR", 12 }, /* pointer record */
		{ "TXT", 16 }, /* text record */
		{ "SRV", 33 }, /* services record */
		{ "NSEC", 47 },
		{ "ANY", 255 }
	};

	std::map<const char *,uint16_t> mdns_classes =
	{
		{ "IN", 1 }
	};

	std::list<std::string> services =
	{
		"_ipp._tcp.local",
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

	int sock;
	in_port_t port;
	struct sockaddr_in mdns_addr;
	struct sockaddr_in local_ifaddr;

	time_t time_last_service_query;
	time_t time_pushed_to_disk;
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
	return ((((unsigned char)*p * 0x100) + *(p+1)) - DNS_LABEL_OFFSET_BIAS);
}

std::string serviceDiscoverer::encode_name(std::string name)
{
	char *encoded = (char *)calloc(1024, 1);
	char *tmp = (char *)calloc(1024, 1);
	char *dot;
	char *p;
	char *e;
	int i;
	size_t len;

	if (!tmp || !encoded)
	{
		std::cerr << __func__ << ": failed to allocate memory for encoded and or tmp" << std::endl;
		return NULL;
	}

	strcpy(tmp, name.data());
	strcat(tmp, ".");

	len = strlen(tmp);
	e = tmp + len;
	p = tmp;

	i = 0;

	while (true)
	{
		dot = memchr(p, '.', (e - p));

/*
 * We should always find a dot at the end
 * of each label after the strcat() above.
 */
		if (!dot)
		{
			std::cerr << __func__ << ": failed to find '.' char in name string" << std::endl;
			return NULL;
		}

		encoded[i++] = (unsigned char)(dot - p);
		memcpy((void *)&encoded[i], (void *)p, (dot - p));
		i += (dot - p);

		p = ++dot;

		if (dot >= e)
			break;
	}

	encoded[i] = 0;

	std::string _encoded = encoded;

	free(tmp);
	free(encoded);

	return _encoded;
}

#define LABEL_JUMP_INDICATOR 0xc0
std::string serviceDiscoverer::decode_name(void *data, char *name, int *_delta)
{
	bool jumped = false;
	off_t off;
	char *ptr;
	int didx = 0;
	int delta = 0;
	std::string decoded;

#ifdef DEBUG
	std::cerr << "Entered decode_name(): sitting at:\n" << std::endl;
	for (int i = 0; i < 10; ++i)
		fprintf(stderr, "\\x%02hhx", name[i]);
	fprintf(stderr, "\n");
	std::cerr << "(this is " << (name - (char *)data) << " bytes from start of data" << std::endl;
#endif
	ptr = name;
	if ((unsigned char)*ptr < 0x20 && (unsigned char)*ptr < 0xc0)
	{
		++ptr;
		++delta;
	}

	while (true)
	{
		if (*ptr == 0)
			break;

		if ((unsigned char)*ptr >= LABEL_JUMP_INDICATOR)
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
		}

		if ((unsigned char)*ptr < 0x20)
			decoded.push_back('.');
		else
			decoded.push_back(*ptr);

		++ptr;

		if (jumped == false)
			++delta;
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
		if (!map_iter->first.length())
			continue;

		fprintf(fp, " Records for host  %s\n\n", map_iter->first.data());

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
						" Address       %s\n",
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
				for (std::map<std::string,std::string>::iterator _list_iter = list_iter->text_data->begin();
						_list_iter != list_iter->text_data->end();
						++_list_iter)
				{
					fprintf(fp, "%s=%s\n", _list_iter->first.data(), _list_iter->second.data());
				}

				fprintf(fp, "\n");
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
			" Type          %s\n"
			" Class         %s\n"
			" Time-to-Live  %u second%s\n"
			" Age           %u second%s\n",
			this->type_str(record.type), this->klass_str(record.klass),
			record.ttl,
			record.ttl == 1 ? "" : "s",
			age,
			age == 1 ? "" : "s");
			
	if (record.type == this->mdns_types["A"])
	{
		fprintf(stdout,
			" Address       %s\n",
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
		std::cout << " Target        " << record.srv_data.target << std::endl;
	}
	else
	if (record.type == this->mdns_types["TXT"] && record.text_data != NULL)
	{
		for (std::map<std::string,std::string>::iterator map_iter = record.text_data->begin();
				map_iter != record.text_data->end();
				++map_iter)
		{
			fprintf(stdout, "%s=%s\n", map_iter->first.data(), map_iter->second.data());
		}
	}
	else
	if (record.type == this->mdns_types["PTR"])
	{
		fprintf(stdout,
			" Domain Name   %s\n",
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

#ifdef DEBUG
	std::cerr << "Parsing text record: len == " << len << " and first byte == " << *p << std::endl;
#endif
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

#ifdef DEBUG
	std::cerr << "Currently at data:\n" << std::endl;
	for (int i = 0; i < 20; ++i)
		fprintf(stderr, "\\x%02hhx", p[i]);
	fprintf(stderr, "\n");
#endif

	while (p < end)
	{
/*
 * Length encoded in byte before key/value pair begins.
 */
		kvlen = (int)*p;
		++p;
		assert(kvlen > 0);
		e = (p + kvlen);
#ifdef DEBUG
		fprintf(stderr, "Working on key/value pair: \"%.*s\"\n", kvlen, p);
#endif

		if (e > end)
		{
			std::cerr << __func__ << ": key start + length of key/value pair is beyond end of data!" << std::endl;
			fprintf(stderr, "(%.*s)\n", (int)kvlen, p);
			delete __ret;
			return NULL;
		}

		eq = memchr(p, '=', (e - p));

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

		fprintf(stderr, "Got key \"%s\" and value \"%s\"\n", key.data(), value.data());

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

#if 0
int serviceDiscoverer::mdns_handle_response_packet(void *packet, size_t size)
{
	struct mdns_hdr *hdr = (struct mdns_hdr *)packet;
	struct mdns_record record;
	char *ptr = (char *)packet + sizeof(struct mdns_hdr);
	uint16_t data_len;
	std::string decoded_name;
	int delta;

	while (true)
	{
		decoded_name = this->decode_name(packet, ptr, &delta);

		if (delta < 0)
		{
			std::cerr << __func__ << ": failed to decode name" << std::endl;
			//free(decoded_name);
			return -1;
		}

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
		record.text_data = NULL;

		if (record.type == this->mdns_types["TXT"])
		{
			record.text_data = this->mdns_parse_text_record((void *)ptr, (size_t)record.data_len);
			ptr += record.data_len;
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

#if 0
#ifdef DEBUG
			std::cerr << "Got the following SRV data:\n" << std::endl;
			std::cerr << "priority=" << record.srv_data.priority << std::endl;
			std::cerr << "weight=" << record.srv_data.weight << std::endl;
			std::cerr << "port=" << record.srv_data.port << std::endl;
			std::cerr << "target=" << record.srv_data.target << std::endl;
#endif
#endif
		}
		else
		{
/*
 * For the timebeing, just ignore other types.
 */
			ptr += record.data_len;
		}

		std::cout << "Service: " << decoded_name << std::endl;

		std::map<std::string,std::list<struct mdns_record> >::iterator map_iter = this->cached_records.find(decoded_name);

		if (map_iter == this->cached_records.end())
		{
			map_iter->second.push_back(record);
			std::cout << "Cached record for \"" << decoded_name << "\"" << std::endl;
		}
		else
		{
			//std::list<struct mdns_record> &__list = map_iter->second;
			//std::list<struct mdns_record>::iterator list_iter;
			bool no_cache = false;

			for (std::list<struct mdns_record>::iterator list_iter = map_iter->second.begin();
					list_iter != map_iter->second.end();
					++list_iter)
			//list_iter = __list.begin();
			//while (list_iter != __list.end())
			{
				if (list_iter->type == record.type && list_iter->klass == record.klass)
				{
					if (this->cached_record_is_stale(*list_iter) == true || this->should_flush_cache(record.klass) == true)
					{
						if (list_iter->text_data != NULL)
							delete list_iter->text_data;

						map_iter->second.erase(list_iter);
						map_iter->second.push_back(record);

						std::cout << "Record for \"" << decoded_name << "\" is stale: removing from cache" << std::endl;
						std::cout << "Cached fresh record for \"" << decoded_name << "\" exists" << std::endl;
					}

					no_cache = true;
				}
			}

			if (!no_cache)
			{
				map_iter->second.push_back(record);
				std::cout << "Cached record for \"" << decoded_name << "\" exists" << std::endl;
			}
			else
			{
				if (record.text_data != NULL)
					delete record.text_data;

				record.text_data = NULL;
			}
		}
	}
}
#endif

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
#if 0
		std::cerr << "Record for " << decoded << std::endl;

		fprintf(stderr,
				"Type = %s : Class = %s\n"
				"TTL = %u seconds\n",
				this->type_str(record.type), this->klass_str(record.klass),
				record.ttl);

		if (record.type == this->mdns_types["SRV"])
		{
			fprintf(stderr,
				"Priority = %hu\n"
				"Weight = %hu\n"
				"Port = %hu\n",
				record.srv_data.priority,
				record.srv_data.weight,
				record.srv_data.port);
			std::cerr << "Target = " << record.srv_data.target << std::endl;
		}
		else
		if (record.type == this->mdns_types["TXT"])
		{
			for (std::map<std::string,std::string>::iterator map_iter = record.text_data->begin();
					map_iter != record.text_data->end();
					++map_iter)
			{
				std::cerr << map_iter->first << "=" << map_iter->second << std::endl;
			}
		}
#endif

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

	this->time_pushed_to_disk = (time(NULL) + this->disk_push_interval);
	this->time_last_service_query = 0;

	return 0;
}

bool serviceDiscoverer::should_replace_file(void)
{
	if ((time(NULL) - this->time_pushed_to_disk) >= this->disk_push_interval)
		return true;
	else
		return false;
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

int serviceDiscoverer::mdns_query_all_services(void)
{
	struct iphdr *ip;
	struct udphdr *udp;
	struct mdns_hdr *mdns;
	//char *encoded_name = NULL;
	std::string encoded_name;
	size_t mdns_size = 0;
	int nr_qs = 0;
	char *buffer = (char *)calloc(32768, 1);
	char *b = buffer;
	uint16_t type = htons(this->mdns_types["ANY"]);
	uint16_t klass = htons(this->mdns_classes["IN"]);
	size_t len;

	if (!buffer)
	{
		std::cerr << __func__ << ": failed to allocate memory for buffer (" << strerror(errno) << ")" << std::endl;
		return -1;
	}

	memset(buffer, 0, 32768);
	ip = (struct iphdr *)buffer;
	udp = (struct udphdr *)((char *)buffer + sizeof(*ip));
	mdns = (struct mdns_hdr *)((char *)udp + sizeof(*udp));

	this->default_iphdr(ip);
	this->default_udphdr(udp);

	mdns->txid = htons(this->new_txid());

	b = buffer + sizeof(*ip) + sizeof(*udp) + sizeof(*mdns);

	for (std::list<std::string>::iterator list_iter = this->services.begin();
			list_iter != this->services.end();
			++list_iter)
	{
		encoded_name = this->encode_name(*list_iter);

		len = encoded_name.length();
		memcpy(b, encoded_name.data(), len);

		b += len;
		*b++ = 0;
		memcpy(b, &type, 2);
		b += 2;
		memcpy(b, &klass, 2);
		b += 2;

		++nr_qs;
	}

	*b = 0;
	len = (size_t)((char *)b - (char *)buffer);
	ip->tot_len = htons(len);
	udp->len = htons(len - sizeof(iphdr));
	mdns->nr_qs = htons(nr_qs);

	ssize_t bytes;

#ifdef DEBUG
	std::cerr << "Sending packet of size " << len << " bytes:\n" << std::endl;
	for (int i = 0; i < len; ++i)
		fprintf(stderr, "\\x%02hhx", buffer[i]);
	fprintf(stderr, "\n");
#endif

	bytes = sendto(this->sock, buffer, len, 0, (struct sockaddr *)&this->mdns_addr, (socklen_t)sizeof(this->mdns_addr));

	this->time_last_service_query = time(NULL);
	return 0;
}

int serviceDiscoverer::mdns_query_service(std::string hostname)
{
	std::string encoded;
	struct iphdr iphdr;
	struct udphdr udphdr;
	struct mdns_hdr hdr;
	size_t len;
	size_t enc_len;
	uint16_t klass;
	uint16_t type;

	encoded = this->encode_name(hostname);
	enc_len = encoded.length();

	clear_struct(&iphdr);

	iphdr.version = 4;
	iphdr.ihl = 5;
	iphdr.tos = 0;

	iphdr.id = this->new_txid();
	iphdr.frag_off = 0;
	iphdr.ttl = 255;
	iphdr.protocol = IPPROTO_UDP;
	iphdr.check = 0;
	iphdr.saddr = this->local_ifaddr.sin_addr.s_addr;

	struct in_addr mcast_in;
	inet_aton(mDNS_MULTICAST, &mcast_in);
	iphdr.daddr = mcast_in.s_addr;

	clear_struct(&udphdr);

	udphdr.source = htons(this->port);
	udphdr.dest = htons(mDNS_PORT);

	len = 8 + sizeof(hdr) + enc_len + 1 + 4;
	udphdr.len = htons(len);

	len += sizeof(iphdr);
	iphdr.tot_len = htons(len);

	clear_struct(&hdr);
	hdr.txid = this->new_txid();
	hdr.nr_qs = htons(1);

	char *t;
	char *tmp = (char *)calloc(1024, 1);

	if (!tmp)
		goto fail_free_mem__mdnsq;

	memset(tmp, 0, 1024);
	t = tmp;

	memcpy((void *)t, &iphdr, sizeof(iphdr));
	t += sizeof(iphdr);
	memcpy((void *)t, &udphdr, sizeof(udphdr));
	t += sizeof(udphdr);
	memcpy((void *)t, &hdr, sizeof(hdr));
	t += sizeof(hdr);

/*
 * We want to keep the NULL byte at the end.
 */
	memcpy((void *)t, (void *)encoded.data(), enc_len+1);
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

	free(tmp);
	tmp = NULL;

	return 0;

	fail_free_mem__mdnsq:

	if (tmp)
		free(tmp);

	return -1;
}

int
main(void)
{
	serviceDiscoverer *sd = new serviceDiscoverer();
	sd->mdns_query_all_services();
	sd->mdns_listen();

	delete sd;

	exit(EXIT_SUCCESS);

	fail:
	exit(EXIT_FAILURE);
}
