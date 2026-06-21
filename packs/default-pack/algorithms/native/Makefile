CC ?= gcc
CFLAGS ?= -O2 -fPIC -Wall -Wextra -Werror
LDFLAGS ?= -shared

SOURCES := $(wildcard *.hash.c)
TARGETS := $(SOURCES:.hash.c=.hash.so)

.PHONY: all clean

all: $(TARGETS)

%.hash.so: %.hash.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

clean:
	rm -f $(TARGETS)
