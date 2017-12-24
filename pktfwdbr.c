#define GETTEXT_PACKAGE "gtk20"
#include <glib.h>
#include <json-glib/json-glib.h>
#include <gio/gio.h>
#include <mosquitto.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include "pkt.h"

#define ERR_MQTTCONNECT 0
#define ERR_MQTTSUB 1
#define ERR_SOCK 2
#define ERR_RXADDR 3
#define ERR_TXADDR 4
#define ERR_RXBIND 5
#define ERR_TXCONNECT 6

#define TOPIC_ROOT	"pktfwdbr"
#define TOPIC_RX	"rx"
#define TOPIC_RX_JOIN "join"
#define TOPIC_RX_UNCONF "unconfirmed"
#define TOPIC_RX_CONF "confirmed"
#define TOPIC_RX_OTHER "other"
#define TOPIC_TX	"tx"
#define TOPIC_STAT	"stat"

#define JSON_RXPK				"rxpk"
#define JSON_STAT				"stat"
#define JSON_GATEWAY_CONF		"gateway_conf"
#define JSON_GATEWAY_ID			"gateway_ID"
#define JSON_SERV_PORT_UP		"serv_port_up"
#define JSON_SERV_PORT_DOWN		"serv_port_down"

#define MTYPE_SHIFT 5
#define MTYPE_MASK 0b111
#define MTYPE_JOINREQ 0b000
#define MTYPE_UNCONFUP 0b010
#define MTYPE_CONFUP 0b100

struct context {
	GSocket* sock;
	GHashTable* txaddrs;
	struct mosquitto* mosq;
	const gchar* mqtthost;
	gint mqttport;
	GIOChannel* mosqchan;
	guint mosqsource;
};

struct publishcontext {
	gchar* id;
	struct mosquitto* mosq;
};

static gchar* createtopic(const gchar* id, ...) {
	GString* topicstr = g_string_new(TOPIC_ROOT"/");
	g_string_append(topicstr, id);

	va_list args;
	va_start(args, id);

	const gchar* part = va_arg(args, const gchar*);
	for (; part != NULL; part = va_arg(args, const gchar*)) {
		g_string_append(topicstr, "/");
		g_string_append(topicstr, part);
	}

	va_end(args);
	gchar* topic = g_string_free(topicstr, FALSE);
	return topic;
}

static gchar* extracteui(guchar* buffer) {
	GString* tmp = g_string_new(NULL);
	for (int i = 7; i >= 0; i--) {
		unsigned b = buffer[i];
		g_string_append_printf(tmp, "%02x", b);
		buffer[i];
	}
	return g_string_free(tmp, FALSE);
}

static void handlerx_processrx(JsonArray *array, guint index,
		JsonNode *element_node, gpointer data) {

	// Do a tiny bit of processing on the payload
	// so we can split joins etc onto a different
	// topic
	JsonObject* obj = json_node_get_object(element_node);
	const gchar* b64payload = json_object_get_string_member(obj, "data");
	gsize payloadlen;
	guchar* payload = g_base64_decode(b64payload, &payloadlen);
	uint8_t mtype = (*payload >> MTYPE_SHIFT) & MTYPE_MASK;

	gchar* subtopic;
	gchar* subsubtopic = NULL;
	gchar* subsubsubtopic = NULL;

	switch (mtype) {
	case MTYPE_JOINREQ: {
		subtopic = TOPIC_RX_JOIN;
		guchar* joinpayload = payload + 1;
		guchar* appeui = joinpayload;
		guchar* deveui = appeui + 8;
		subsubtopic = extracteui(appeui);
		subsubsubtopic = extracteui(deveui);
	}
		break;
	case MTYPE_UNCONFUP:
		subtopic = TOPIC_RX_UNCONF;
		break;
	case MTYPE_CONFUP:
		subtopic = TOPIC_RX_CONF;
		break;
	default:
		subtopic = TOPIC_RX_OTHER;
		break;
	}

	g_free(payload);

	struct publishcontext* cntx = (struct publishcontext*) data;
	gchar* topic = createtopic(cntx->id, TOPIC_RX, subtopic, subsubtopic,
			subsubsubtopic, NULL);

	if (subsubtopic != NULL)
		g_free(subsubtopic);
	if (subsubsubtopic != NULL)
		g_free(subsubsubtopic);

	JsonGenerator* jsongenerator = json_generator_new();
	json_generator_set_root(jsongenerator, element_node);
	gsize publishpayloadsz;
	gchar* publishpayload = json_generator_to_data(jsongenerator,
			&publishpayloadsz);
	g_object_unref(jsongenerator);

	mosquitto_publish(cntx->mosq, NULL, topic, publishpayloadsz, publishpayload,
			0, false);

	g_free(topic);
	g_free(publishpayload);
}

static gchar* extractid(uint8_t* pktbuff) {
	GString* str = g_string_new(NULL);
	uint8_t* id = PKT_GATEWAYID(pktbuff);
	for (int i = 0; i < PKT_IDLEN; i++)
		g_string_append_printf(str, "%02"PRIx8, id[i]);
	return g_string_free(str, FALSE);
}

static GSocketAddress* findport(struct context* cntx, const gchar* id) {
	GSocketAddress* txaddr = g_hash_table_lookup(cntx->txaddrs, id);
	if (txaddr == NULL)
		g_message("don't have a port for %s", id);
	return txaddr;
}

static gboolean handlerx(GIOChannel *source, GIOCondition condition,
		gpointer data) {

	struct context* cntx = (struct context*) data;

	gchar* idstr = NULL;
	JsonParser* jsonparser = NULL;

	g_message("UDP incoming");

	gsize pktbuffsz = 8 * 1024;

	uint8_t* pktbuff = g_malloc(8 * 1024);
	if (pktbuff == NULL)
		goto out;

	gssize pktsz = g_socket_receive(cntx->sock, pktbuff, pktbuffsz, NULL, NULL);
	if (pktsz == 0 || pktsz < sizeof(struct pkt_hdr)) {
		g_message("invalid packet size; %d", (int) pktsz);
		goto out;
	}

	struct pkt_hdr* p = ((struct pkt_hdr*) pktbuff);
	if (!PKT_VALIDHEADER(p)) {
		g_message("invalid packet header");
		goto out;
	}

	switch (p->type) {
	case PKT_TYPE_PUSH_DATA: {
		idstr = extractid(pktbuff);
		GSocketAddress* txaddr = findport(cntx, idstr);
		if (txaddr == NULL)
			goto out;

		struct pkt_hdr ack = { .version = PKT_VERSION, .token = p->token,
				.type =
				PKT_TYPE_PUSH_ACK };

		if (g_socket_send_to(cntx->sock, txaddr, (const gchar*) &ack,
				sizeof(ack), NULL, NULL) < 0)
			g_message("failed to ack push data");

		gssize jsonsz = PKT_JSONSZ(pktsz);

		if (jsonsz < 2) {
			g_message("json payload is too short");
			goto out;
		}

		g_message("Processing RX packets from %s", idstr);

		uint8_t* json = PKT_JSON(pktbuff);
		jsonparser = json_parser_new_immutable();
		if (!json_parser_load_from_data(jsonparser, json, jsonsz, NULL)) {
			g_message("failed to parse json");
			goto out;
		}
		JsonNode* root = json_parser_get_root(jsonparser);
		if (!JSON_NODE_HOLDS_OBJECT(root))
			g_message("json root should have been an object");

		JsonObject* rootobj = json_node_get_object(root);

		if (json_object_has_member(rootobj, JSON_RXPK)) {
			JsonArray* rxpkts = json_object_get_array_member(rootobj,
			JSON_RXPK);
			struct publishcontext pcntx = { idstr, cntx->mosq };
			json_array_foreach_element(rxpkts, handlerx_processrx, &pcntx);
		} else
			g_message("no rx packets");

		if (json_object_has_member(rootobj, JSON_STAT)) {
			JsonObject* stat = json_object_get_object_member(rootobj,
			JSON_STAT);
		} else
			g_message("no stat");
	}
		break;
	case PKT_TYPE_PULL_DATA: {
		idstr = extractid(pktbuff);
		GSocketAddress* txaddr = findport(cntx, idstr);
		if (txaddr == NULL)
			goto out;

		struct pkt_hdr ack = { .version = PKT_VERSION, .token = p->token,
				.type =
				PKT_TYPE_PULL_ACK };
		if (g_socket_send_to(cntx->sock, txaddr, (const gchar*) &ack,
				sizeof(ack), NULL, NULL) < 0)
			g_message("failed to ack pull data");
	}
		break;
	case PKT_TYPE_TX_ACK: {
		idstr = extractid(pktbuff);
		GSocketAddress* txaddr = findport(cntx, idstr);
		if (txaddr == NULL)
			goto out;
		uint8_t* json = PKT_JSON(pktbuff);

		g_message("got tx ack");
	}
		break;
	default:
		g_message("Unhandled type: %d", (int) p->type);
		goto out;
	}

	out: if (pktbuff != NULL)
		g_free(pktbuff);
	if (idstr != NULL)
		g_free(idstr);
	if (jsonparser != NULL)
		g_object_unref(jsonparser);
	return TRUE;
}

static gboolean handlemosq(GIOChannel *source, GIOCondition condition,
		gpointer data) {
	struct mosquitto* mosq = (struct mosquitto*) data;
	mosquitto_loop_read(mosq, 1);
	return TRUE;
}

static void subforgw(gpointer key, gpointer value, gpointer user_data) {
	struct context* cntx = (struct context*) user_data;
	gchar* topic = createtopic(key, TOPIC_TX, NULL);
	if (mosquitto_subscribe(cntx->mosq, NULL, topic, 0) != MOSQ_ERR_SUCCESS) {
		g_message("Failed to subscribe to topic");
	}
	g_free(topic);
}

static gboolean mosq_idle(gpointer data) {
	struct context* cntx = (struct context*) data;

	bool connected = false;

// This seems like the only way to work out if
// we ever connected or got disconnected at
// some point
	if (mosquitto_loop_misc(cntx->mosq) == MOSQ_ERR_NO_CONN) {
		if (cntx->mosqchan != NULL) {
			g_source_remove(cntx->mosqsource);
			// g_io_channel_shutdown doesn't work :/
			close(mosquitto_socket(cntx->mosq));
			cntx->mosqchan = NULL;
		}

		if (mosquitto_connect(cntx->mosq, cntx->mqtthost, cntx->mqttport, 60)
				== MOSQ_ERR_SUCCESS) {
			int mosqfd = mosquitto_socket(cntx->mosq);
			cntx->mosqchan = g_io_channel_unix_new(mosqfd);
			cntx->mosqsource = g_io_add_watch(cntx->mosqchan, G_IO_IN,
					handlemosq, cntx->mosq);
			g_io_channel_unref(cntx->mosqchan);

			g_hash_table_foreach(cntx->txaddrs, subforgw, cntx);
			connected = true;
		}
	} else
		connected = true;

	if (connected) {
		mosquitto_loop_read(cntx->mosq, 1);
		mosquitto_loop_write(cntx->mosq, 1);
	}
	return TRUE;
}

static void mosq_log(struct mosquitto* mosq, void* userdata, int level,
		const char* str) {
	g_message(str);
}

static int parseconfig(JsonParser* jsonparser, GInetAddress* loinetaddr,
		struct context* cntx, const gchar* c) {

	int ret = 0;

	if (!json_parser_load_from_file(jsonparser, c, NULL)) {
		g_message("failed to parse json from %s", c);
		goto out;
	}

	JsonNode* root = json_parser_get_root(jsonparser);
	if (JSON_NODE_HOLDS_OBJECT(root)) {
		JsonObject* rootobj = json_node_get_object(root);
		if (json_object_has_member(rootobj, JSON_GATEWAY_CONF)) {
			JsonObject* gatewayconf = json_object_get_object_member(rootobj,
			JSON_GATEWAY_CONF);
			if (json_object_has_member(gatewayconf, JSON_GATEWAY_ID)
					&& json_object_has_member(gatewayconf,
					JSON_SERV_PORT_DOWN)) {
				const gchar* id = json_object_get_string_member(gatewayconf,
				JSON_GATEWAY_ID);
				gint64 port = json_object_get_int_member(gatewayconf,
				JSON_SERV_PORT_DOWN);

				g_message("downstream port for %s is %d", id, (int) port);

				// we need our own copy of the id string,
				// the packet forward also lower cases the
				// id string from the config.
				GString* gwid = g_string_new(id);
				g_string_ascii_down(gwid);
				id = g_string_free(gwid, false);

				GSocketAddress* txaddr = g_inet_socket_address_new(loinetaddr,
						port);
				if (txaddr == NULL) {
					ret = ERR_RXADDR;
					goto out;
				}
				g_hash_table_insert(cntx->txaddrs, (gpointer) id, txaddr);
				g_message("registered gateway %s", id);
			} else
				g_message("%s doesn't contain all the required keys", c);
		}
	}

	out: return ret;
}

static void mosq_msg(struct mosquitto *mosq, void *obj,
		const struct mosquitto_message *message) {

	struct context* cntx = obj;

	char** splittopic;
	int topicparts;
	mosquitto_sub_topic_tokenise(message->topic, &splittopic, &topicparts);

	char* root = splittopic[0];
	char* gatewayid = splittopic[1];
	char* direction = splittopic[2];

	if (strcmp(root, TOPIC_ROOT) != 0) {
		g_message("bad topic root");
		return;
	}

	if (strcmp(direction, TOPIC_TX) != 0) {
		g_message("unexpected direction");
		return;
	}

	g_message("have tx packet");

	GSocketAddress* txaddr = findport(cntx, gatewayid);
	if (txaddr == NULL)
		return;

	uint16_t token = 0;

	gsize pktsz = sizeof(struct pkt_hdr) + message->payloadlen;
	uint8_t* pkt = g_malloc(pktsz);

	struct pkt_hdr hdr = { .version = PKT_VERSION, .token = token, .type =
	PKT_TYPE_PULL_RESP };

	memcpy(pkt, &hdr, sizeof(hdr));
	memcpy(pkt + sizeof(hdr), message->payload, message->payloadlen);

	if (g_socket_send_to(cntx->sock, txaddr, (const gchar*) pkt, pktsz,
	NULL, NULL) < 0)
		g_message("failed to send pull resp");

}

int main(int argc, char** argv) {

	int ret = 0;

	struct context cntx = { 0 };
	cntx.txaddrs = g_hash_table_new(g_str_hash, g_str_equal);

	gchar* mqtthost = "localhost";
	gint mqttport = 1883;
	gint listenport = 1912;
	gchar** configs = NULL;
	GOptionEntry entries[] = { //
			{ "mqtthost", 'h', 0, G_OPTION_ARG_STRING, &mqtthost, "", "" }, //
					{ "mqttport", 'p', 0, G_OPTION_ARG_INT, &mqttport, "", "" }, //
					{ "listenport", 'l', 0, G_OPTION_ARG_INT, &listenport, "",
							"" }, //
					{ "config", 'c', 0, G_OPTION_ARG_FILENAME_ARRAY, &configs,
							"", "" }, //
					{ NULL } };

	GOptionContext* context = g_option_context_new("");
	GError* error = NULL;
	g_option_context_add_main_entries(context, entries, GETTEXT_PACKAGE);
	if (!g_option_context_parse(context, &argc, &argv, &error)) {
		g_print("option parsing failed: %s\n", error->message);
		goto out;
	}

	mosquitto_lib_init();
	g_message("using mqtt broker at %s on port %d", mqtthost, mqttport);
	cntx.mqtthost = mqtthost;
	cntx.mqttport = mqttport;
	cntx.mosq = mosquitto_new(NULL, true, &cntx);
	mosquitto_message_callback_set(cntx.mosq, mosq_msg);
	mosquitto_log_callback_set(cntx.mosq, mosq_log);

	GInetAddress* loinetaddr = g_inet_address_new_loopback(
			G_SOCKET_FAMILY_IPV4);

	if (configs != NULL) {
		JsonParser* jsonparser = json_parser_new_immutable();
		for (gchar** c = configs; *c != NULL; c++)
			parseconfig(jsonparser, loinetaddr, &cntx, *c);
		g_object_unref(jsonparser);
	}

	cntx.sock = g_socket_new(G_SOCKET_FAMILY_IPV4, G_SOCKET_TYPE_DATAGRAM,
			G_SOCKET_PROTOCOL_DEFAULT, NULL);
	if (cntx.sock == NULL) {
		ret = ERR_SOCK;
		goto out;
	}

	g_message("listening for packet forwarder packets on port %d", listenport);
	GSocketAddress* rxaddr = g_inet_socket_address_new(loinetaddr, listenport);
	if (rxaddr == NULL) {
		ret = ERR_RXADDR;
		goto out;
	}

	if (!g_socket_bind(cntx.sock, rxaddr, FALSE, NULL)) {
		ret = ERR_RXBIND;
		goto out;
	}

	g_timeout_add(500, mosq_idle, &cntx);

	int rxfd = g_socket_get_fd(cntx.sock);
	GIOChannel* rxchan = g_io_channel_unix_new(rxfd);
	g_io_add_watch(rxchan, G_IO_IN, handlerx, &cntx);

	GMainLoop* mainloop = g_main_loop_new(NULL, FALSE);
	g_main_loop_run(mainloop);

	mosquitto_disconnect(cntx.mosq);

	out: mosquitto_lib_cleanup();
	return ret;
}
