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
#include "servicediscoverer.hpp"

/*
 * TODO
 *
 * Allow user to register a service and respond
 * to any mDNS queries for the service.
 *
 */

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
	for (std::map<std::string,std::list<struct mdns_record> >::iterator map_iter = this->record_cache.begin();
			map_iter != this->record_cache.end();
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
	//std::map<std::string,uint16_t> label_cache;
	std::map<std::string,uint16_t>::iterator map_iter;
	std::list<std::string> tokens;
	std::string data;
	bool need_null = true;
	int pos = 0;
	int nr_qs = 0;

	this->label_cache.clear();
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
			if ((map_iter = this->label_cache.find(*list_iter)) != this->label_cache.end())
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
				this->label_cache.insert(std::pair<std::string,uint16_t>(*list_iter, off));
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

#define LABEL_JUMP_INDICATOR (unsigned char)0xc0
std::string serviceDiscoverer::decode_name(void *data, char *name, int *deltaPtr)
{
	assert(data);
	assert(name);
	assert(deltaPtr);

	bool jumped = false;
	off_t off;
	char *ptr;
	int didx = 0;
	int delta = 0;
	unsigned char len;
	std::string decoded;
	//std::vector<char *> jumpPoints;

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
		/*
		 * No need to save pointer locations just before
		 * each jump because we are just incrementing
		 * DELTA based on whether we jumped or not.
		 *
		 * Only in cases where we need to be able to
		 * return the pointer to the very first pre-jump
		 * location do we need to save these pointers.
		 */
			//jumpPoints.push_back(ptr);
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
#ifdef DEBUG
			std::cerr << "Length of next token: " << (size_t)len << std::endl;
#endif
			if (decoded.length() > 0)
				decoded.push_back('.');

			++ptr; // skip the byte for token length
			decoded.append(ptr, len);
			ptr += len;

			if (false == jumped)
				delta += len + 1;

#ifdef DEBUG
			std::cerr << decoded << std::endl;
#endif
		}
	}

	//dest[didx] = 0;

/*
 * Either NAME + DELTA == \x00 or NAME + DELTA == 0xCx (start of jump offset)
 */
	if (true == jumped)
		delta += 2;
	else
		++delta;

	*deltaPtr = delta;

#ifdef DEBUG
	std::cerr << "Returning std::string (\"" << decoded << "\")" << std::endl;
#endif
	return decoded;
}

void serviceDiscoverer::check_cached_records(void)
{
#ifdef DEBUG
	std::cerr << "Checking cache for stale records" << std::endl;
#endif
	for (std::map<std::string,std::list<struct mdns_record> >::iterator map_iter = this->record_cache.begin();
		map_iter != this->record_cache.end();
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
	char tmp[128];
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

	for (std::map<std::string,std::list<struct mdns_record> >::iterator map_iter = this->record_cache.begin();
			map_iter != this->record_cache.end();
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

				inet_ntop(AF_INET6, (void *)&list_iter->inet6, ipv6_str, INET6_ADDRSTRLEN);
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

	std::map<std::string,std::string> *text_KeyValueMap = new std::map<std::string,std::string>();
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
			delete text_KeyValueMap;
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
		if (text_KeyValueMap->find(key) == text_KeyValueMap->end())
			text_KeyValueMap->insert(std::pair<std::string,std::string>(key, value));
	}

#ifdef DEBUG
	std::cerr << "Got the following key/value pairs from the text record:\n" << std::endl;
	for (std::map<std::string,std::string>::iterator map_iter = text_KeyValueMap->begin();
				map_iter != text_KeyValueMap->end();
				++map_iter)
	{
		std::cerr << map_iter->first << "=" << map_iter->second << std::endl;
	}
#endif

	return text_KeyValueMap;
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

/* XXX
 *	NEVER do this!!
 *	Thanks to doing this, we were getting SIGSEGV
 *	when the string implementation was copying
 *	the result from decode_name to any string
 *	objects in the record structure (because
 *	%rdi would obviously be 0x0000000000000000).
 */
	//clear_struct(&record);

#ifdef DEBUG
	std::cerr << "Entered mDNS_Parse_Answers(): " << nr << " to parse" << std::endl;
#endif

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
		else
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
#ifdef DEBUG
			std::cerr << "Decoding TARGET for server record" << std::endl;
#endif
			record.srv_data.target = this->decode_name(packet, ptr, &delta);
			ptr += delta;
		}
		else
		if (record.type == this->mdns_types["PTR"])
		{
#ifdef DEBUG
			std::cerr << "Decoding DOMAIN NAME for pointer record" << std::endl;
#endif
			record.domain_name = this->decode_name(packet, ptr, &delta);
			ptr += delta;
#ifdef DEBUG
			std::cerr << "Domain Name: " << record.domain_name << std::endl;
#endif
		}
		else
		{
			ptr += record.data_len;
		}

#ifdef DEBUG
		std::cerr << "Printing decoded record for \"" << decoded << "\"" << std::endl;
#endif
		this->mdns_print_record(decoded, record);

#ifdef DEBUG
		std::cerr << "Adding record to record cache" << std::endl;
#endif
		std::map<std::string,std::list<struct mdns_record> >::iterator map_iter = this->record_cache.find(decoded);
		if (map_iter == this->record_cache.end())
		{
#ifdef DEBUG
			std::cerr << "Creating new cache record map entry" << std::endl;
#endif
			std::list<struct mdns_record> __list;
			__list.push_back(record);
			this->record_cache.insert( std::pair<std::string,std::list<struct mdns_record> >(decoded, __list) );
		}
		else
		{
#ifdef DEBUG
			std::cerr << "Searching list for previous entry" << std::endl;
#endif
			bool replacedOld = false;

			for (std::list<struct mdns_record>::iterator list_iter = map_iter->second.begin();
				list_iter != map_iter->second.end();
				++list_iter)
			{
				if (list_iter->type == record.type && list_iter->klass == record.klass)
				{
					map_iter->second.erase(list_iter);
					map_iter->second.push_back(record);
					replacedOld = true;
					break;
				}
			}
#ifdef DEBUG
			std::cerr << "No previous record; adding record to list" << std::endl;
#endif
			if (false == replacedOld)
			{
				map_iter->second.push_back(record);
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
	inet_aton(mDNS_ADDR, &mreq.imr_multiaddr);
	inet_aton("0.0.0.0", &mreq.imr_interface);

/* Get a random high port */
	this->port = ((rand() % (USHRT_MAX - (IPPORT_RESERVED * 10))) + (IPPORT_RESERVED * 10));

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
	inet_aton(mDNS_ADDR, &this->mdns_addr.sin_addr);
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
			error("failed to find separator in name");
			list.clear();
			errno = EPROTO;
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

#define BUFFER_SIZE 32768
int serviceDiscoverer::mdns_query_all_services(void)
{
	struct iphdr *ip;
	struct udphdr *udp;
	struct mdns_hdr *mdns;
	char *buffer = (char *)calloc(BUFFER_SIZE, 1);
	char *b = buffer;
	char *ptr = NULL;
	std::string data;
	size_t len;

	if (!buffer)
	{
		error("failed to allocate memory for buffer");
		return -1;
	}

	memset(buffer, 0, BUFFER_SIZE);
	ip = (struct iphdr *)buffer;
	udp = (struct udphdr *)((char *)buffer + sizeof(*ip));
	mdns = (struct mdns_hdr *)((char *)udp + sizeof(*udp));

	this->default_iphdr(ip);
	this->default_udphdr(udp);

	mdns->txid = htons(this->new_txid());
	b = (char *)mdns + sizeof(*mdns);
	//b = (char *)buffer + sizeof(*ip) + sizeof(*udp) + sizeof(*mdns);

	struct Query query;

	query.name = this->special_query_all;
	query.type = this->mdns_types["PTR"];
	query.klass = this->mdns_classes["IN"];

	std::vector<struct Query> vquery;

	vquery.push_back(query);

	data = this->encode_data(vquery);
	ptr = (char *)data.data();
	memcpy((void *)b, (void *)ptr, data.length());
	b += data.length();
	*b = 0;

	len = calc_offset(buffer, b);
	ip->tot_len = (uint16_t)htons(len);
	udp->len = (uint16_t)htons(len - sizeof(*ip));
	//mdns->nr_qs = htons(this->services.size());
	mdns->nr_qs = (uint16_t)1; // Just one special query for local intranet services

#ifdef DEBUG
	std::cerr << "Total length: " << ntohs(ip->tot_len) << std::endl;
	std::cerr << "UDP length: " << ntohs(udp->len) << std::endl;
	std::cerr << "MDNS Data length: " << data.length() << std::endl;
#endif

	ssize_t bytes;

#ifdef DEBUG
	len = ntohs(ip->tot_len);
	std::cerr << "Sending packet of size " << len << " bytes:\n" << std::endl;
	for (int i = 0; (size_t)i < len; ++i)
		fprintf(stderr, "\\x%02hhx", buffer[i]);
	fprintf(stderr, "\n");
#endif

	std::cout << "Querying local services...");
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

	buffer = (char *)calloc(BUFFER_SIZE, 1);
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
	mdns = (struct mdns_hdr *)((char *)udp + sizeof(*udp));

	this->default_iphdr(ip);
	this->default_udphdr(udp);

	len = encoded.length();
	ip->tot_len = htons(20 + 8 + 12 + len);
	udp->len = htons(8 + 12 + len);

	mdns->txid = this->new_txid();
	mdns->nr_qs = htons(1);

	b = (char *)mdns + sizeof(*mdns);
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

/*
 * XXX	Causing SIGSEGV when doing ctrl+c
 */
static void
clean_up(int signo)
{
	if (SIGINT != signo && SIGQUIT != signo)
		return;

	if (NULL != sd)
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
