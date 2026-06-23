#ifndef KB_LISTENER_H
#define KB_LISTENER_H

#include <stdio.h>

// Forward declarations (simplified)
void kb_listener(int fd);
void kb_run(const char* device_path);

#define SHORT_PACKET_MAX 1024

#endif // KB_LISTENER_H
