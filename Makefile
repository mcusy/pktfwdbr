PKGCONFIG ?= pkg-config
CFLAGS = --std=gnu99 -ggdb
GLIB = `$(PKGCONFIG) --cflags --libs glib-2.0 gio-2.0`
JSON = `$(PKGCONFIG) --cflags --libs json-glib-1.0`
MOSQUITTO = -lmosquitto

all: pktfwdbr

pktfwdbr: pktfwdbr.c pkt.h
	$(CC) $(GLIB) $(JSON) $(MOSQUITTO) $(CFLAGS) -o $@ $<

.PHONY: clean

clean:
	- rm pktfwdbr
