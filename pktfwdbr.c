#include <gio/gio.h>

#include "pkt.h"

#define ERR_RXSOCK 1
#define ERR_RXADDR 2
#define ERR_RXBIND 3

static gboolean handlerx(GIOChannel *source, GIOCondition condition,
		gpointer data) {

	gsize pktbuffsz = 8 * 1024;

	void* pktbuff = g_malloc(8 * 1024);
	if (pktbuff == NULL)
		goto error;

	gssize pktsz = g_socket_receive((GSocket*) data, pktbuff, pktbuffsz, NULL,
	NULL);
	if (pktsz == 0 || pktsz < sizeof(struct pkt_hdr))
		goto error;

	union pkt* p = ((union pkt*) pktbuff);
	if (!PKT_VALIDHEADER(p))
		goto error;

	switch (p->hdr.type) {
	default:
		goto error;
	}

	return TRUE;

	error: if (pktbuff != NULL)
		g_free(pktbuff);
	return FALSE;
}

int main(int argc, char** argv) {

	int ret = 0;

	GSocket* rxsock = g_socket_new(G_SOCKET_FAMILY_IPV6, G_SOCKET_TYPE_DATAGRAM,
			G_SOCKET_PROTOCOL_DEFAULT, NULL);
	if (rxsock == NULL) {
		ret = ERR_RXSOCK;
		goto out;
	}

	GSocketAddress* rxaddr = g_inet_socket_address_new_from_string("::1", 1985);
	if (rxaddr == NULL) {
		ret = ERR_RXADDR;
		goto out;
	}

	if (!g_socket_bind(rxsock, rxaddr, FALSE, NULL)) {
		ret = ERR_RXBIND;
		goto out;
	}

	int rxfd = g_socket_get_fd(rxsock);
	GIOChannel* rxchan = g_io_channel_unix_new(rxfd);
	g_io_add_watch(rxchan, G_IO_IN, handlerx, rxsock);

	GMainLoop* mainloop = g_main_loop_new(NULL, FALSE);
	g_main_loop_run(mainloop);

	out: return ret;
}
