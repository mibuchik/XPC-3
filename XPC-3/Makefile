CC ?= gcc
CFLAGS += -O3 -Wall -Wextra -std=c11 -fPIC -DOPENSSL_SUPPRESS_DEPRECATED
LDFLAGS ?= -lcrypto -lz

TARGET = xpc3
SRCS = xkdf.c xbe.c xcm.c xpc3.c main.c
OBJS = $(SRCS:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET) test_*

.PHONY: all clean
