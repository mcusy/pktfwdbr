CFLAGS = --std=gnu99
GLIB = `pkg-config --cflags --libs glib-2.0 gio-2.0`

all: pktfwdbr

pktfwdbr: pktfwdbr.c
	$(CC) $(GLIB) $(CLAGS) -o $@ $^

.PHONY: clean

clean:
	- rm pktfwdbr
