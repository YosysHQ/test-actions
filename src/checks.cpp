#include <algorithm>
#include <stdexcept>
#include <string.h>
#include <string>
#include <sstream>
#include <iomanip>
#include <vector>
#include <curl/curl.h>
#include "checks.h"

#ifdef __linux__

#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if_arp.h>
#include <sys/socket.h>
#include <unistd.h>

#define IFLIST_REPLY_BUFFER 8192

static std::vector<std::string> get_current_mac()
{
	std::vector<std::string> retVal;
	int done = 0;

	int nl = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (nl == -1)
	{
		return retVal;
	}

	struct sockaddr_nl local;
	memset(&local, 0, sizeof(local));
	local.nl_family = AF_NETLINK;
	local.nl_pid = getpid();
	local.nl_groups = 0;

	struct sockaddr_nl kernel;
	memset(&kernel, 0, sizeof(kernel));
	kernel.nl_family = AF_NETLINK;

	if (bind(nl, (struct sockaddr *) &local, sizeof(local)) < 0)
	{
		goto fail;
	}

	struct {
		struct nlmsghdr hdr;
		struct rtgenmsg gen;
	} req;
	memset(&req, 0, sizeof(req));

	req.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtgenmsg));
	req.hdr.nlmsg_type = RTM_GETLINK;
	req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	req.hdr.nlmsg_seq = 1;
	req.hdr.nlmsg_pid = getpid();
	req.gen.rtgen_family = AF_PACKET;

	struct iovec io;
	memset(&io, 0, sizeof(io));
	io.iov_base = &req;
	io.iov_len = req.hdr.nlmsg_len;

	struct msghdr rtnl_msg;
	memset(&rtnl_msg, 0, sizeof(rtnl_msg));
	rtnl_msg.msg_iov = &io;
	rtnl_msg.msg_iovlen = 1;
	rtnl_msg.msg_name = &kernel;
	rtnl_msg.msg_namelen = sizeof(kernel);

	if (sendmsg(nl, (struct msghdr *) &rtnl_msg, 0) < 0)
	{
		goto fail;
	}

	uint8_t reply[IFLIST_REPLY_BUFFER];
	while (!done)
	{
		struct nlmsghdr *msg_ptr;

		struct iovec io_reply;
		memset(&io_reply, 0, sizeof(io_reply));
		io.iov_base = reply;
		io.iov_len = IFLIST_REPLY_BUFFER;

		struct msghdr rtnl_reply;
		memset(&rtnl_reply, 0, sizeof(rtnl_reply));
		rtnl_reply.msg_iov = &io;
		rtnl_reply.msg_iovlen = 1;
		rtnl_reply.msg_name = &kernel;
		rtnl_reply.msg_namelen = sizeof(kernel);

		int len = recvmsg(nl, &rtnl_reply, 0);
		if (len == -1)
		{
			goto fail;
		}
		if (len)
		{
			for (msg_ptr = (struct nlmsghdr *) reply; NLMSG_OK(msg_ptr, len); msg_ptr = NLMSG_NEXT(msg_ptr, len))
			{
				switch(msg_ptr->nlmsg_type)
				{
					case NLMSG_DONE:
						done = 1;
						break;
					case RTM_NEWLINK:
						{
							struct ifinfomsg *iface = (struct ifinfomsg *)NLMSG_DATA(msg_ptr);
							int len = msg_ptr->nlmsg_len - NLMSG_LENGTH(sizeof(*iface));
							for (struct rtattr *attribute = IFLA_RTA(iface); RTA_OK(attribute, len); attribute = RTA_NEXT(attribute, len))
							{
								if (iface->ifi_type != ARPHRD_ETHER)
									continue;

								switch (attribute->rta_type)
								{
									case IFLA_ADDRESS:
										uint8_t *iface_mac = (uint8_t *)RTA_DATA(attribute);
										std::ostringstream oss;
										for (int i=0;i<6;i++) {
											if (i!=0) oss << ":";
											oss << std::hex << std::setw(2) << std::setfill('0');
											oss << (int)iface_mac[i];
										}
										retVal.push_back(std::string(oss.str()));
										break;
								}
							}
						}
						break;
				}
			}
		}
	}
fail:
	close(nl);
	return retVal;
}
#elif __APPLE__
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/sysctl.h>
#include <net/if.h>
#include <net/if_dl.h>

static std::vector<std::string> get_current_mac()
{
	std::vector<std::string> retVal;
	struct if_nameindex *if_ni, *i;
	int mib[6];
	size_t len;
	char *buf;
	uint8_t *ptr;
	struct if_msghdr *ifm;
	struct sockaddr_dl *sdl;

	if_ni = if_nameindex();
	if (if_ni == NULL) goto fail;

	for (i = if_ni; ! (i->if_index == 0 && i->if_name == NULL); i++) {
		mib[0] = CTL_NET;
		mib[1] = AF_ROUTE;
		mib[2] = 0;
		mib[3] = AF_LINK;
		mib[4] = NET_RT_IFLIST;
		mib[5] = i->if_index;

		if (sysctl(mib, 6, NULL, &len, NULL, 0) < 0) goto fail;
		if ((buf = (char*)malloc(len)) == NULL)  goto fail;
		if (sysctl(mib, 6, buf, &len, NULL, 0) < 0) goto fail;

		ifm = (struct if_msghdr *)buf;
		sdl = (struct sockaddr_dl *)(ifm + 1);
		ptr = (uint8_t*)LLADDR(sdl);
		std::ostringstream oss;
		for (int i=0;i<6;i++) {
			if (i!=0) oss << ":";
			oss << std::hex << std::setw(2) << std::setfill('0');
			oss << (int)ptr[i];
		}
		retVal.push_back(std::string(oss.str()));
	}
fail:
	if_freenameindex(if_ni);   
	return retVal;
}
#elif __MINGW32__

#include <sstream>
#include <iphlpapi.h>

long gethostid()
{
	DWORD dwVolumeSerialNumber;
	LPCTSTR lpRootPathName = "C:\\";

	GetVolumeInformation( lpRootPathName, 0, 0, &dwVolumeSerialNumber, 0, 0, 0, 0 );
	return dwVolumeSerialNumber;
}

static std::vector<std::string> get_current_mac()
{
	std::vector<std::string> retVal;
	PIP_ADAPTER_INFO AdapterInfo;
	DWORD dwBufLen = sizeof(IP_ADAPTER_INFO);
	AdapterInfo = (IP_ADAPTER_INFO *) malloc(sizeof(IP_ADAPTER_INFO));
	if (AdapterInfo == NULL) {
		return retVal;
	}

	if (GetAdaptersInfo(AdapterInfo, &dwBufLen) == ERROR_BUFFER_OVERFLOW) {
		free(AdapterInfo);
		AdapterInfo = (IP_ADAPTER_INFO *) malloc(dwBufLen);
		if (AdapterInfo == NULL) {
			return retVal;
		}
	}

	if (GetAdaptersInfo(AdapterInfo, &dwBufLen) == NO_ERROR) {
		PIP_ADAPTER_INFO pAdapterInfo = AdapterInfo;
		do {
			std::ostringstream oss;
			for (int i=0;i<6;i++) {
				if (i!=0) oss << ":";
				oss << std::hex << std::setw(2) << std::setfill('0');
				oss << (int)pAdapterInfo->Address[i];
			}
			retVal.push_back(std::string(oss.str()));
			pAdapterInfo = pAdapterInfo->Next;
		} while(pAdapterInfo);
	}
	free(AdapterInfo);
	return retVal;
}
#else
#error "mac_check unimplemented for target system"
#endif

static std::string str_tolower(std::string s)
{
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c){ return std::tolower(c); } );
    return s;
}

static int curl_string_writer(char *data, size_t size, size_t nmemb, std::string *writerData)
{
	if (writerData == nullptr)
		return 0;

	writerData->append(data, size*nmemb);

	return size*nmemb;
}

static std::string get_current_scaleway_instance()
{
	static bool got_scaleway_id = false;
	static std::string scaleway_id;

	if (!got_scaleway_id)
	{
		CURL *curl = curl_easy_init();
		std::string buffer;
		size_t cursor = 0;

		if (curl == nullptr)
			return "";

		if (curl_easy_setopt(curl, CURLOPT_URL, "http://169.254.42.42/conf") != CURLE_OK)
			goto curl_error;

		if (curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_string_writer) != CURLE_OK)
			goto curl_error;

		if (curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buffer) != CURLE_OK)
			goto curl_error;

		if (curl_easy_setopt(curl, CURLOPT_TIMEOUT, 2L) != CURLE_OK)
			goto curl_error;

		if (curl_easy_perform(curl) != CURLE_OK)
			goto curl_error;

		while (1) {
			size_t eol = buffer.find('\n', cursor);
			if (eol == std::string::npos) break;
			std::string line = buffer.substr(cursor, eol-cursor);
			if (line.substr(0, 3) == "ID=")
				scaleway_id = line.substr(3);
			cursor = eol + 1;
		}

curl_error:
		curl_easy_cleanup(curl);
		got_scaleway_id = true;
	}

	return scaleway_id;
}

static int scaleway_instance_check(std::string id)
{
	return str_tolower(get_current_scaleway_instance()) == id;
}

static std::string get_current_aws_instance()
{
	static bool got_aws_id = false;
	static std::string aws_id;

	if (!got_aws_id)
	{
		CURL *curl = curl_easy_init();
		std::string buffer;

		if (curl == nullptr)
			return "";

		if (curl_easy_setopt(curl, CURLOPT_URL, "http://169.254.169.254/2018-09-24/meta-data/instance-id") != CURLE_OK)
			goto curl_error;

		if (curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_string_writer) != CURLE_OK)
			goto curl_error;

		if (curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buffer) != CURLE_OK)
			goto curl_error;

		if (curl_easy_setopt(curl, CURLOPT_TIMEOUT, 2L) != CURLE_OK)
			goto curl_error;

		if (curl_easy_perform(curl) != CURLE_OK)
			goto curl_error;

		aws_id = buffer;

curl_error:
		curl_easy_cleanup(curl);
		got_aws_id = true;
	}

	return aws_id;
}

static int aws_instance_check(std::string id)
{
	return str_tolower(get_current_aws_instance()) == id;
}

static std::string get_github_action()
{
	static bool got_ga_id = false;
	static std::string ga_id;

	if (!got_ga_id)
	{
		CURL *curl = curl_easy_init();
		std::string buffer;

		if (curl == nullptr)
			return "";

		struct curl_slist *header_list = nullptr;
		char *token = getenv("GITHUB_TOKEN");
		if (token == nullptr)
			return "";
		char *owner = getenv("GITHUB_REPOSITORY_OWNER");
		if (owner == nullptr)
			return "";
		char *repo = getenv("GITHUB_REPOSITORY");
		if (repo == nullptr)
			return "";
		std::string user_agent = "User-Agent: YosysHQ LicenseCheker";
		std::string auth_header = std::string("authorization: Bearer ") + token;
		std::string content_header = "content-type: application/json";
		header_list = curl_slist_append(header_list, user_agent.c_str());
		header_list = curl_slist_append(header_list, auth_header.c_str());
		header_list = curl_slist_append(header_list, content_header.c_str());
		std::string url = "https://api.github.com/orgs/" + std::string(owner) + "/actions/secrets/public-key";
		if (curl_easy_setopt(curl, CURLOPT_URL, url.c_str()) != CURLE_OK)
			goto curl_error;

		if (curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_string_writer) != CURLE_OK)
			goto curl_error;

		if (curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buffer) != CURLE_OK)
			goto curl_error;

		if (curl_easy_setopt(curl, CURLOPT_TIMEOUT, 2L) != CURLE_OK)
			goto curl_error;

		if (curl_easy_setopt(curl, CURLOPT_HTTPHEADER, header_list) != CURLE_OK)
			goto curl_error;

		if (curl_easy_perform(curl) != CURLE_OK)
			goto curl_error;

		if (buffer.find("integration") != std::string::npos) {
			ga_id = std::string(repo);	
		}
curl_error:
		curl_easy_cleanup(curl);
		got_ga_id = true;
	}

	return ga_id;
}

static int github_action_check(std::string id)
{
	return str_tolower(get_github_action()) == id;
}

static std::string get_current_hostid()
{
	static bool got_host_id = false;
	static std::string host_id;

	if (!got_host_id)
	{
		char hostbuffer[256];
		snprintf(hostbuffer, 256, "%08x", (uint32_t)gethostid());
		host_id = hostbuffer;
		got_host_id = true;
	}
	return host_id;
}

static int hostid_check(std::string id)
{
	return get_current_hostid() == id;
}

static std::string get_current_machine_id()
{
	static bool got_machine_id = false;
	static std::string machine_id;

	if (!got_machine_id)
	{
		char hostbuffer[256];
		FILE *fp = fopen("/etc/machine-id", "r");
		if (fp) {
			fgets(hostbuffer, 256, fp);
			char *tok = strtok(hostbuffer, " \t\r\n");
			machine_id = tok;
			got_machine_id = true;
		}
		fclose(fp);
	}
	return machine_id;
}

static int machine_id_check(std::string id)
{
	return str_tolower(get_current_machine_id()) == id;
}

static std::string get_current_hostname()
{
	static bool got_hostname_id = false;
	static std::string hostname_id;

	if (!got_hostname_id)
	{
		char hostbuffer[256];
		if (gethostname(hostbuffer, sizeof(hostbuffer))==0) {
			hostname_id = hostbuffer;
			got_hostname_id = true;
		}		
	}
	return hostname_id;
}

static int hostname_check(std::string id)
{
	return str_tolower(get_current_hostname()) == id;
}

static int mac_address_check(std::string id)
{
	std::vector<std::string> mac = get_current_mac();
	for(size_t i=0;i<mac.size();i++) {
		if (mac.at(i) == id) return 1;
	}
	return 0;
}

void display_dev_identifiers(CheckType ct)
{
	printf("Device identifiers\n");
	printf("================================================================\n");
	if ((ct==CHECK_ALL) || (ct==CHECK_LOCAL) || (ct==CHECK_MAC_ADDRESS)) {
		std::vector<std::string> mac = get_current_mac();
		printf("MAC               : %d found\n",(int)mac.size());
		for(size_t i=0;i<mac.size();i++) {
			printf("                    %s\n", mac.at(i).c_str());
		}

	}
	if ((ct==CHECK_ALL) || (ct==CHECK_LOCAL) || (ct==CHECK_HOSTID))      printf("Host ID           : %s\n", get_current_hostid().c_str());
	if ((ct==CHECK_ALL) || (ct==CHECK_LOCAL) || (ct==CHECK_MACHINEID))   printf("Machine ID        : %s\n", get_current_machine_id().c_str());
	if ((ct==CHECK_ALL) || (ct==CHECK_LOCAL) || (ct==CHECK_HOSTNAME))    printf("Hostname          : %s\n", get_current_hostname().c_str());
	if ((ct==CHECK_ALL) || (ct==CHECK_AWS_INSTANCE))                     printf("AWS Instance      : %s\n", get_current_aws_instance().c_str());
	if ((ct==CHECK_ALL) || (ct==CHECK_SCALEWAY_INSTANCE))                printf("Scaleway instance : %s\n", get_current_scaleway_instance().c_str());
	if ((ct==CHECK_ALL) || (ct==CHECK_GITHUB_ACTION))                    printf("GitHub action     : %s\n", get_github_action().c_str());
}

int execute_check(CheckType ct, const char *val)
{
	std::string id = str_tolower(val);
	switch(ct)
	{
		case CHECK_MAC_ADDRESS: return mac_address_check(id);
		case CHECK_HOSTID: return hostid_check(id);
		case CHECK_MACHINEID: return machine_id_check(id);
		case CHECK_HOSTNAME: return hostname_check(id);
		case CHECK_AWS_INSTANCE: return aws_instance_check(id);
		case CHECK_SCALEWAY_INSTANCE: return scaleway_instance_check(id);
		case CHECK_GITHUB_ACTION: return github_action_check(id);
		default:
			throw std::runtime_error("Unhandled check");
	}
}
