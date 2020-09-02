#define PERL_NO_GET_CONTEXT

#define ALLOC_PAGE_SIZE sysconf(_SC_PAGESIZE)
#define BUFFER_PAGES 1024
#define BUFFER_SIZE ALLOC_PAGE_SIZE * BUFFER_PAGES
#define PACKET_HEAD_BUFFER_SIZE ALLOC_PAGE_SIZE
#define PACKET_READ_BUFFER_SIZE ALLOC_PAGE_SIZE

#define EV_MULTIPLICITY 1

#define CONSTANT(A_VAR, A_VAL) static const char * const A_VAR = A_VAL; static const unsigned int A_VAR ## _size = sizeof(A_VAL) - 1

#define AST_PKT_SEPARATOR_CR "\r"
#define AST_PKT_SEPARATOR_NL "\n"
#define AST_PKT_SEPARATOR_FIELD_VALUE ": "
#define AST_PKT_SEPARATOR_FIELD AST_PKT_SEPARATOR_CR AST_PKT_SEPARATOR_NL
#define AST_PKT_SEPARATOR_END AST_PKT_SEPARATOR_FIELD AST_PKT_SEPARATOR_FIELD
#define AST_PKT_SEPARATOR_FIELD_MULTI_LINE_END AST_PKT_SEPARATOR_NL "--END COMMAND--" AST_PKT_SEPARATOR_END
#define AST_PKT_SEPARATOR_FIELD_END AST_PKT_SEPARATOR_CR

#define AST_PKT_BANNER "Asterisk" //"Asterisk Call Manager/\d+.\d+.\d+\r\n"
#define AST_PKT_HEAD_EVENT "Event"

#define AST_PKT_HEAD_EVENT_WELL_KNOWN "WellKnown"

CONSTANT(ast_pkt_separator_cr, AST_PKT_SEPARATOR_CR);
CONSTANT(ast_pkt_separator_nl, AST_PKT_SEPARATOR_NL);
CONSTANT(ast_pkt_separator_field_value, AST_PKT_SEPARATOR_FIELD_VALUE);

CONSTANT(ast_pkt_separator_field, AST_PKT_SEPARATOR_FIELD);
CONSTANT(ast_pkt_separator_end, AST_PKT_SEPARATOR_END);
CONSTANT(ast_pkt_separator_field_multi_line_end, AST_PKT_SEPARATOR_FIELD_MULTI_LINE_END);
CONSTANT(ast_pkt_separator_field_end, AST_PKT_SEPARATOR_FIELD_END);

CONSTANT(ast_pkt_banner, AST_PKT_BANNER);
CONSTANT(ast_pkt_head_event, AST_PKT_HEAD_EVENT);
CONSTANT(ast_pkt_head_event_well_known, AST_PKT_HEAD_EVENT_WELL_KNOWN);

#include "EVAPI.h"

#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include <stdlib.h>
#include <string.h>

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <stdint.h>
#include <unistd.h>

#include <pthread.h>

#ifdef __GNUC__
#ifndef LIKELY
# define LIKELY(A_COND)   __builtin_expect(!!(A_COND), 1)
#endif
#ifndef UNLIKELY
# define UNLIKELY(A_COND) __builtin_expect(!!(A_COND), 0)
#endif
#else
#ifndef LIKELY
# define LIKELY(x)   (x)
#endif
#ifndef UNLIKELY
# define UNLIKELY(x) (x)
#endif
#endif

#define ATOMIC_MEMORDER __ATOMIC_SEQ_CST
#define ATOMIC_COMPARE_EXCHANGE(ptr, expected, desired) __atomic_compare_exchange_n(ptr, expected, desired, 0, ATOMIC_MEMORDER, ATOMIC_MEMORDER)
#define ATOMIC_LOAD(ptr) __atomic_load_n(ptr, ATOMIC_MEMORDER)

#define DEFINED(A_PTR) A_PTR != NULL
#define UNDEF(A_PTR) A_PTR = NULL
#define FREE_AND_UNDEF_CHECKED(A_PTR) if (LIKELY(DEFINED(A_PTR))) { free(A_PTR); UNDEF(A_PTR); }
#define FREE_AND_UNDEF(A_PTR) do { free(A_PTR); UNDEF(A_PTR); } while(0)

#define max(a, b) ({ __typeof__ (a) _a = (a); __typeof__ (b) _b = (b); _a > _b ? _a : _b; })
#define min(a, b) ({ __typeof__ (a) _a = (a); __typeof__ (b) _b = (b); _a > _b ? _b : _a; })

#ifdef DEBUG
#define trace(f_, ...) printf("%s:%-4d [%d] " f_, __FILE__, __LINE__, (int)getpid(), ##__VA_ARGS__)

int hexdump(void const *data, size_t length, int linelen, int split) {
	char buffer[BUFFER_SIZE];
	char *ptr;
	const void *inptr;
	int pos;
	int remaining = length;
	inptr = data;
	assert(sizeof(buffer) >= (3 + (4 * (linelen / split)) + (linelen * 4)));
	while (remaining > 0) {
		int lrem;
		int splitcount;
		ptr = buffer;
		lrem = remaining;
		splitcount = 0;
		for (pos = 0; pos < linelen; pos++) {
			if (split == splitcount++) {
				sprintf(ptr, "  ");
				ptr += 2;
				splitcount = 1;
			}
			if (lrem) {
				sprintf(ptr, "%0.2x ", *((unsigned char *) inptr + pos));
				lrem--;
			} else {
				sprintf(ptr, "   ");
			}
			ptr += 3;
		}
		*ptr++ = ' ';
		*ptr++ = ' ';
		lrem = remaining;
		splitcount = 0;
		for (pos = 0; pos < linelen; pos++) {
			unsigned char c;
			if (split == splitcount++) {
				sprintf(ptr, "  ");
				ptr += 2;
				splitcount = 1;
			}
			if (lrem) {
				c = *((unsigned char *) inptr + pos);
				if (c > 31 && c < 127) {
					sprintf(ptr, "%c", c);
				} else {
					sprintf(ptr, ".");
				}
				lrem--;
			}
			ptr++;
		}
		*ptr = '\0';
		trace("%s\n", buffer);
		inptr += linelen;
		remaining -= linelen;
	}
	return 0;
}

#define trace_buff(A_BUFF, A_LEN) hexdump(A_BUFF, A_LEN, 24, 24)
#else
#define trace(...)
#define trace_buff(...)
#endif

typedef enum AMIerr_e { EAMI_NONE = 0, EAMI_FATAL, EAMI_UNKNOWN, EAMI_DESTROY } AMIerr_t;

typedef enum AMIstate_e { SAMI_NONE = 0, SAMI_DESTROY } AMIstate_t;

typedef struct AMIbuff_s {
	uint64_t read_ptr;
	uint64_t write_ptr;
	int64_t len;
	void *ring[];
} AMIbuff_t;

typedef struct AMIpktbuff_s {
	uint64_t len;
	char *buffer;
} AMIpktbuff_t;

typedef struct AMIvalue_s {
	size_t len;
	char *content;
} AMIvalue_t;

typedef struct AMIfield_s {
	AMIvalue_t * name;
	AMIvalue_t * value;
	struct AMIfield_s * next;
} AMIfield_t;

typedef struct AMIpkt_s {
	size_t len;
	AMIfield_t * head;
	AMIfield_t * tail;
} AMIpkt_t;

typedef struct AMIctx_s {
	pthread_t * tid;
	pthread_mutex_t * lock;
	pthread_cond_t * invoke_cv;

	struct ev_async * async_ev_w;

	struct ev_io * read_ev_io;

	struct ev_loop * loop;

	char * buffer;
	char * buffer_head;
	char * buffer_cursor;

	char * last_packet_head_type;
	unsigned long last_packet_head_type_len;

	char * last_event;
	unsigned long last_event_len;

	SV * event_callback;

	HV * hv;
	SV * packet;

	uint64_t buffer_len;
	uint64_t buffer_pos;
	uint64_t buffer_free;

	unsigned int portno;

	struct sockaddr_in serv_addr;
	struct hostent *server;

	int sockfd;
	bool error;
	AMIerr_t error_code;
	AMIbuff_t * parse_buffer;
	AMIbuff_t * parsed_buffer;

	unsigned long long stat_packets;
} AMIctx_t;

AMIbuff_t *ami_ctx_ring_buffer_init(int64_t len)
{
	AMIbuff_t *ring_buffer = (AMIbuff_t *)malloc(sizeof(AMIbuff_t) + len * sizeof(void*));
	ring_buffer->read_ptr = 0;
	ring_buffer->write_ptr = 0;
	ring_buffer->len = len;
	memset(ring_buffer->ring, 1, len * sizeof(void*));
	return ring_buffer;
}

int ami_ctx_ring_buffer_push(AMIbuff_t *ring_buffer, void *value)
{
	uint64_t read_ptr;
	uint64_t write_ptr;
	uint64_t real_ptr;
	void *old_value;
	while (1) {
		read_ptr = ATOMIC_LOAD(&ring_buffer->read_ptr);
		write_ptr = ATOMIC_LOAD(&ring_buffer->write_ptr);
		if (UNLIKELY(write_ptr - read_ptr >= ring_buffer->len)) {
			return 0;
		}
		real_ptr = write_ptr % ring_buffer->len;
		old_value = ring_buffer->ring[real_ptr];
		if (!old_value || !ATOMIC_COMPARE_EXCHANGE(&ring_buffer->ring[real_ptr], &old_value, 0)) {
			continue;
		}
		if (ATOMIC_COMPARE_EXCHANGE(&ring_buffer->write_ptr, &write_ptr, write_ptr + 1)) {
			break;
		}
		void *null_value = NULL;
		ATOMIC_COMPARE_EXCHANGE(&ring_buffer->ring[real_ptr], &null_value, old_value);
	}
	ring_buffer->ring[real_ptr] = value;
	return 1;
}

void *ami_ctx_ring_buffer_pop(AMIbuff_t *ring_buffer)
{
	uint64_t read_ptr;
	uint64_t write_ptr;
	uint64_t real_ptr;
	void *value;
	while (1) {
		write_ptr = ATOMIC_LOAD(&ring_buffer->write_ptr);
		read_ptr = ATOMIC_LOAD(&ring_buffer->read_ptr);
		if (UNLIKELY(read_ptr >= write_ptr)) {
			return NULL;
		}
		real_ptr = read_ptr % ring_buffer->len;
		value = ring_buffer->ring[real_ptr];
		if (UNLIKELY(!value)) {
			return NULL;
		}
		if (ATOMIC_COMPARE_EXCHANGE(&ring_buffer->read_ptr, &read_ptr, read_ptr + 1)) {
			break;
		}
	}
	return value;
}

void ami_ctx_ring_buffer_destroy(AMIbuff_t *ring_buffer)
{
	FREE_AND_UNDEF(ring_buffer);
}

AMIpktbuff_t * ami_ctx_assign_packet_buffer(AMIctx_t * ami_ctx, size_t len)
{
	if (LIKELY(DEFINED(ami_ctx))) {
		AMIpktbuff_t * packet_buffer = (AMIpktbuff_t *) malloc(sizeof(AMIpktbuff_t));
		packet_buffer->buffer = (char *) malloc(len);
		memmove(packet_buffer->buffer, ami_ctx->buffer_head, len);
		packet_buffer->len = len;
		return packet_buffer;
	}
	return NULL;
}

void ami_ctx_destroy_packet_buffer(AMIpktbuff_t * packet_buffer)
{
	if (LIKELY(DEFINED(packet_buffer))) {
		packet_buffer->len = 0;
		FREE_AND_UNDEF(packet_buffer->buffer);
	}
}


AMIvalue_t * ami_ctx_value_init() {
	AMIvalue_t * value = (AMIvalue_t *)malloc(sizeof(AMIvalue_t));
	value->content = NULL;
	value->len = 0;
	return value;
}

size_t ami_ctx_value_assign(AMIvalue_t * value, const char * content, size_t len)
{
	if(LIKELY(DEFINED(value))) {
		if (len) {
			if (LIKELY(DEFINED(content))) {
				if (UNLIKELY(DEFINED(value->content))) {
					if (value->len != len) {
						value->len = 0;
						value->content = (char *)realloc((char *)value->content, len);
					}
				} else {
					value->content = (char *)malloc(len);
				}
				memmove(value->content, content, len);
				value->len = len;
			}
		}
		return value->len;
	}
	return 0;
}

void ami_ctx_value_destroy(AMIvalue_t * value) {
	if (LIKELY(DEFINED(value))) {
		value->len = 0;
		FREE_AND_UNDEF(value->content);
		FREE_AND_UNDEF(value);
	}
}

AMIpkt_t * ami_ctx_pkt_init() {
	AMIpkt_t *packet = (AMIpkt_t*) malloc(sizeof(AMIpkt_t));
	packet->len = 0;
	UNDEF(packet->head);
	UNDEF(packet->tail);
	return packet;
}

void ami_ctx_field_destroy (AMIfield_t * field) {
	if (LIKELY(DEFINED(field))) {
		if (LIKELY(DEFINED(field->name))) ami_ctx_value_destroy(field->name);
		if (LIKELY(DEFINED(field->value))) ami_ctx_value_destroy(field->value);
		FREE_AND_UNDEF(field);
	}
}

AMIfield_t * ami_ctx_field_create(const char * field, size_t field_len, const char * value, size_t value_len)
{
	AMIfield_t * new_field = (AMIfield_t *)malloc(sizeof(AMIfield_t));
	new_field->name = ami_ctx_value_init();
	ami_ctx_value_assign(new_field->name, field, field_len);
	new_field->value = ami_ctx_value_init();
	ami_ctx_value_assign(new_field->value, value, value_len);
	return new_field;
}

void ami_ctx_pkt_destroy (AMIpkt_t * packet)
{
	if (LIKELY(DEFINED(packet))) {
		AMIfield_t * field = NULL;
		AMIfield_t * next_field = NULL;
		for (field = packet->head; field; field = next_field) {
			next_field = field->next;
			ami_ctx_field_destroy (field);
		}
		FREE_AND_UNDEF(packet);
	}
}

size_t ami_ctx_pkt_push_field (AMIpkt_t * packet, AMIfield_t * field)
{
	if (LIKELY(DEFINED(packet))) {
		if (LIKELY(DEFINED(field))) {
			if (LIKELY(packet->len)) {
				packet->tail->next = field;
			} else {
				packet->head = field;
			}
			packet->tail = field;
			UNDEF(field->next);
			packet->len++;
		}
		return packet->len;
	}
	return 0;
}

size_t ami_ctx_pkt_set_field ( AMIpkt_t * packet, const char * field, const size_t field_len, const char * value, const size_t value_len)
{
	return ami_ctx_pkt_push_field (packet, ami_ctx_field_create(field, field_len, value, value_len));
}

AMIfield_t * ami_ctx_pkt_get_field(AMIpkt_t * packet, const char * field, size_t len)
{
	if (LIKELY(DEFINED(packet))) {
		if (LIKELY(DEFINED(field))) {
			if (len) {
				for (AMIfield_t * packet_field = packet->head; packet_field; packet_field = packet_field->next) {
					if ((len == packet_field->name->len) && (memcmp(packet_field->name->content, field, packet_field->name->len) == 0)) {
						return packet_field;
					}
				}
			}
		}
	}
	return NULL;
}

AMIctx_t * ami_ctx_init()
{
	AMIctx_t * ami_ctx = (AMIctx_t *) malloc(sizeof(AMIctx_t));

	ami_ctx->last_packet_head_type  = (char *) malloc(PACKET_HEAD_BUFFER_SIZE);
	memset(ami_ctx->last_packet_head_type, '\0', PACKET_HEAD_BUFFER_SIZE);
	ami_ctx->last_packet_head_type_len = 0;

	ami_ctx->last_event = (char *) malloc(PACKET_HEAD_BUFFER_SIZE);
	memset(ami_ctx->last_event, '\0', PACKET_HEAD_BUFFER_SIZE);
	ami_ctx->last_event_len = 0;

	ami_ctx->buffer = (char *) malloc(BUFFER_SIZE);
	memset(ami_ctx->buffer, '\0', BUFFER_SIZE);

	ami_ctx->buffer_head = ami_ctx->buffer;
	ami_ctx->buffer_cursor = ami_ctx->buffer;

	ami_ctx->loop = EV_DEFAULT;

	ami_ctx->sockfd = -1;
	ami_ctx->portno = 5038;

	ami_ctx->buffer_len = 0;
	ami_ctx->buffer_pos = 0;
	ami_ctx->buffer_free = BUFFER_SIZE;

	UNDEF(ami_ctx->server);

	UNDEF(ami_ctx->event_callback);
	UNDEF(ami_ctx->read_ev_io);
	UNDEF(ami_ctx->async_ev_w);

	memset(&ami_ctx->serv_addr, '0', sizeof(ami_ctx->serv_addr));

	ami_ctx->error = false;
	ami_ctx->error_code = EAMI_NONE;

	ami_ctx->tid = (pthread_t *)malloc(sizeof(pthread_t));

	ami_ctx->lock = (pthread_mutex_t *)malloc(sizeof(pthread_mutex_t));
	pthread_mutex_init(ami_ctx->lock, NULL);

	ami_ctx->invoke_cv = (pthread_cond_t *)malloc(sizeof(pthread_cond_t));
	pthread_cond_init(ami_ctx->invoke_cv, NULL);

	ami_ctx->parse_buffer = ami_ctx_ring_buffer_init(BUFFER_PAGES);
	ami_ctx->parsed_buffer = ami_ctx_ring_buffer_init(BUFFER_PAGES);

	ami_ctx->stat_packets = 0;

	dTHX;
	ami_ctx->hv = newHV();
	ami_ctx->packet = newRV_noinc((SV *)ami_ctx->hv);

	return ami_ctx;
}

void ami_ctx_set_error(AMIctx_t * ami_ctx, const AMIerr_t code, const char *message)
{
#ifdef DEBUG
	trace("! AMI error: %s, code: %d\n", message, (uint8_t)code);
#endif
	if (LIKELY(DEFINED(ami_ctx))) {
		ami_ctx->error = true;
		ami_ctx->error_code = code;
	}
}

bool ami_ctx_is_error(AMIctx_t * ami_ctx)
{
	if (LIKELY(DEFINED(ami_ctx))) {
		return ami_ctx->error;
	}
	return true;
}

int ami_ctx_host(AMIctx_t * ami_ctx, const char * host, const char * port)
{
	if (LIKELY(DEFINED(ami_ctx))) {
		ami_ctx->serv_addr.sin_family = AF_INET;

		ami_ctx->portno = atoi(port);
		ami_ctx->serv_addr.sin_port = htons(ami_ctx->portno);

		ami_ctx->server = gethostbyname(host);

		if (ami_ctx->server == NULL) {
#ifdef DEBUG
			trace("ERROR: no such host\n");
#endif
			return -1;
		}

		bcopy((char *)ami_ctx->server->h_addr, (char *)&(ami_ctx->serv_addr.sin_addr.s_addr), ami_ctx->server->h_length);
	}
	return 0;
}

AMIpkt_t * ami_ctx_parse(const AMIpktbuff_t * packet_buffer)
{
	AMIpkt_t * parsed_packet = ami_ctx_pkt_init();

	const char *packet = packet_buffer->buffer;
	const char *cursor = packet;
	const char *f1;
	const char *f2;
	const char *v1;
	const char *v2;
	const char *yyt1;
	const char *yyt2;
	const char *yyt3;
	char yych;

	static const unsigned char yybm[] = {
		128, 128, 128, 128, 128, 128, 128, 128,
		128, 160, 128, 128, 128,   0, 128, 128,
		128, 128, 128, 128, 128, 128, 128, 128,
		128, 128, 128, 128, 128, 128, 128, 128,
		160, 128, 128, 128, 128, 128, 128, 128,
		128, 128, 128, 128, 128, 192, 192, 128,
		192, 192, 192, 192, 192, 192, 192, 192,
		192, 192, 128, 128, 128, 128, 128, 128,
		128, 192, 192, 192, 192, 192, 192, 192,
		192, 192, 192, 192, 192, 192, 192, 192,
		192, 192, 192, 192, 192, 192, 192, 192,
		192, 192, 192, 128, 128, 128, 128, 192,
		128, 192, 192, 192, 192, 192, 192, 192,
		192, 192, 192, 192, 192, 192, 192, 192,
		192, 192, 192, 192, 192, 192, 192, 192,
		192, 192, 192, 128, 128, 128, 128, 128,
		128, 128, 128, 128, 128, 128, 128, 128,
		128, 128, 128, 128, 128, 128, 128, 128,
		128, 128, 128, 128, 128, 128, 128, 128,
		128, 128, 128, 128, 128, 128, 128, 128,
		128, 128, 128, 128, 128, 128, 128, 128,
		128, 128, 128, 128, 128, 128, 128, 128,
		128, 128, 128, 128, 128, 128, 128, 128,
		128, 128, 128, 128, 128, 128, 128, 128,
		128, 128, 128, 128, 128, 128, 128, 128,
		128, 128, 128, 128, 128, 128, 128, 128,
		128, 128, 128, 128, 128, 128, 128, 128,
		128, 128, 128, 128, 128, 128, 128, 128,
		128, 128, 128, 128, 128, 128, 128, 128,
		128, 128, 128, 128, 128, 128, 128, 128,
		128, 128, 128, 128, 128, 128, 128, 128,
		128, 128, 128, 128, 128, 128, 128, 128,
	};

	static void *yytarget[256] = {
		&&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,
		&&yy3,  &&yy12, &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,
		&&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,
		&&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,
		&&yy12, &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,
		&&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy12, &&yy12, &&yy3,
		&&yy12, &&yy12, &&yy12, &&yy12, &&yy12, &&yy12, &&yy12, &&yy12,
		&&yy12, &&yy12, &&yy12, &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,
		&&yy3,  &&yy12, &&yy12, &&yy12, &&yy12, &&yy12, &&yy12, &&yy12,
		&&yy12, &&yy12, &&yy12, &&yy12, &&yy12, &&yy12, &&yy12, &&yy12,
		&&yy12, &&yy12, &&yy12, &&yy12, &&yy12, &&yy12, &&yy12, &&yy12,
		&&yy12, &&yy12, &&yy12, &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy12,
		&&yy3,  &&yy12, &&yy12, &&yy12, &&yy12, &&yy12, &&yy12, &&yy12,
		&&yy12, &&yy12, &&yy12, &&yy12, &&yy12, &&yy12, &&yy12, &&yy12,
		&&yy12, &&yy12, &&yy12, &&yy12, &&yy12, &&yy12, &&yy12, &&yy12,
		&&yy12, &&yy12, &&yy12, &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,
		&&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,
		&&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,
		&&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,
		&&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,
		&&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,
		&&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,
		&&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,
		&&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,
		&&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,
		&&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,
		&&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,
		&&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,
		&&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,
		&&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,
		&&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,
		&&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3
	};

	while (cursor != packet_buffer->buffer + packet_buffer->len) {
		yych = *cursor;
		if (yych <= '9') {
			if (yych <= ',') {
				if (yych == '\r') goto yy4;
			} else {
				if (yych != '/') {
					yyt1 = cursor;
					goto yy5;
				}
			}
		} else {
			if (yych <= '^') {
				if (yych <= '@') goto yy2;
				if (yych <= 'Z') {
					yyt1 = cursor;
					goto yy5;
				}
			} else {
				if (yych == '`') goto yy2;
				if (yych <= 'z') {
					yyt1 = cursor;
					goto yy5;
				}
			}
		}
		yy2:
			++cursor;
		yy3:
			{
			break;
			}
		yy4:
			yych = *++cursor;
			if (yych == '\n') goto yy6;
			goto yy3;
		yy5:
			yych = *(packet = ++cursor);
			{
				goto *yytarget[yych];
			}
		yy6:
			++cursor;
			{ break; }
		yy8:
			yych = *++cursor;
			if (yybm[0+yych] & 32) {
				goto yy8;
			}
			if (yych == ':') goto yy13;
		yy10:
			cursor = packet;
			goto yy3;
		yy11:
			yych = *++cursor;
		yy12:
			if (yybm[0+yych] & 64) {
				goto yy11;
			}
			if (yych <= 0x1F) {
				goto yy10;
			} else {
				if (yych <= ' ') {
					yyt2 = cursor;
					goto yy8;
				}
				if (yych <= '/') goto yy10;
				if (yych >= ';') goto yy10;
				yyt2 = cursor;
			}
		yy13:
			yych = *++cursor;
			if (yych <= '\f') {
				yyt3 = cursor;
			} else {
				if (yych <= '\r') {
					yyt3 = cursor;
					goto yy17;
				}
				if (yych == ' ') goto yy13;
				yyt3 = cursor;
			}
		yy15:
			yych = *++cursor;
			if (yybm[0+yych] & 128) {
				goto yy15;
			}
		yy17:
			yych = *++cursor;
			if (yych != '\n') goto yy10;
			++cursor;
			f1 = yyt1;
			f2 = yyt2;
			v1 = yyt3;
			v2 = cursor - 2;
			{
				ami_ctx_pkt_set_field(parsed_packet, f1, (int)(f2 - f1), v1, (int)(v2 - v1));
				continue;
			}
	}
	return parsed_packet;
}

int64_t ami_ctx_scan_char( AMIctx_t * ami_ctx, const char * value )
{
	if (LIKELY(DEFINED(ami_ctx))) {
		register char *cursor = (char *)memchr(ami_ctx->buffer_head, *value, ami_ctx->buffer_len);
		if (LIKELY(DEFINED(cursor))) {
			return cursor - ami_ctx->buffer_head + 1;
		}
	}
	return -1;
}

int64_t ami_ctx_scan_chars( AMIctx_t * ami_ctx, const char * value, size_t len )
{
	if (LIKELY(DEFINED(ami_ctx))) {
		register char *cursor = (char *)memmem(ami_ctx->buffer_head, ami_ctx->buffer_len, value, len);
		if (LIKELY(DEFINED(cursor))) {
			return cursor - ami_ctx->buffer_head + 1;
		}
	}
	return -1;
}

int64_t ami_ctx_scan_nchars( AMIctx_t * ami_ctx, size_t buffer_len, const char * value, size_t len )
{
	if (LIKELY(DEFINED(ami_ctx))) {
		register char *cursor = (char *)memmem(ami_ctx->buffer_head, buffer_len, value, len);
		if (LIKELY(DEFINED(cursor))) {
			return cursor - ami_ctx->buffer_head + 1;
		}
	}
	return -1;
}

int64_t ami_ctx_scan_packet_end( AMIctx_t * ami_ctx )
{
	if (LIKELY(DEFINED(ami_ctx))) {
		register int64_t i = 0;
		if (LIKELY((i = ami_ctx_scan_chars( ami_ctx, ast_pkt_separator_end, ast_pkt_separator_end_size)) > -1)) {
			return i+ast_pkt_separator_end_size-1;
		}
	}
	return -1;
}

int64_t ami_ctx_scan_banner_end( AMIctx_t * ami_ctx )
{
	if (LIKELY(DEFINED(ami_ctx))) {
		register int64_t i = 0;
		if (LIKELY((i = ami_ctx_scan_chars( ami_ctx, ast_pkt_separator_field_end, ast_pkt_separator_field_end_size)) > -1)) {
			if (LIKELY(ami_ctx_scan_nchars( ami_ctx, i-1, ast_pkt_banner, ast_pkt_banner_size) > -1)) {
				return i+ast_pkt_separator_field_end_size;
			}
		}
	}
	return -1;
}

static inline bool ami_ctx_scan_head( AMIctx_t * ami_ctx )
{
	if (LIKELY(DEFINED(ami_ctx))) {
		register int64_t i = 0;
		register int64_t i2 = 0;

		if (LIKELY((i = ami_ctx_scan_chars( ami_ctx, ast_pkt_separator_field_end, ast_pkt_separator_field_end_size)) > -1)) {
#ifdef DEBUG
			trace ("Head search end: %d\n", i-1);
#endif
			if (LIKELY(( i2 = ami_ctx_scan_nchars( ami_ctx, i-1, ast_pkt_separator_field_value, ast_pkt_separator_field_value_size)) > -1)) {
				ami_ctx->stat_packets++;

				ami_ctx->last_packet_head_type_len = i2 - 1;
				memcpy(ami_ctx->last_packet_head_type, ami_ctx->buffer_head, ami_ctx->last_packet_head_type_len);

				ami_ctx->last_event_len = i - i2 - 2;
				memcpy(ami_ctx->last_event, ami_ctx->buffer_head + i2 + 1, ami_ctx->last_event_len);
#ifdef DEBUG
				trace ("Head search type len: %d\n", ami_ctx->last_packet_head_type_len);
				trace_buff (ami_ctx->last_packet_head_type, ami_ctx->last_packet_head_type_len);

				trace ("Head search type value len: %d\n", ami_ctx->last_event_len);
				trace_buff (ami_ctx->last_event, ami_ctx->last_event_len);
#endif
				return true;
			}
		}
	}
	return false;
}

bool ami_ctx_scan_filter( AMIctx_t * ami_ctx )
{
	if (LIKELY(DEFINED(ami_ctx))) {
		ami_ctx_scan_head(ami_ctx);

		if (LIKELY(!memcmp(ami_ctx->last_packet_head_type, ast_pkt_head_event, min(ast_pkt_head_event_size, ami_ctx->last_packet_head_type_len)))) {
#ifdef DEBUG
			trace ("Filter event passed\n");
#endif
			if (LIKELY(!memcmp(ami_ctx->last_event, ast_pkt_head_event_well_known, min(ast_pkt_head_event_well_known_size, ami_ctx->last_event_len)))) {
#ifdef DEBUG
				trace ("Filter value passed\n");
#endif
				return true;
			}
		} else {
			return true;
		}
	}
	return false;
}


void ami_ctx_invoke_event_callback(AMIctx_t * ami_ctx)
{
	if (LIKELY(DEFINED(ami_ctx))) {
		if (LIKELY(DEFINED(ami_ctx->event_callback))) {
			dTHX;
			dSP;
#ifdef DEBUG
			trace("Event callback cb=%p\n", ami_ctx->event_callback);
#endif
			ENTER;
			SAVETMPS;
			PUSHMARK(SP);
			PUSHs(ami_ctx->packet);
			PUTBACK;
			call_sv(ami_ctx->event_callback, G_DISCARD | G_EVAL|G_VOID);
			SPAGAIN;
#ifdef DEBUG
			if (UNLIKELY(SvTRUE(ERRSV))) trace("Event callback err: %d\n", SvTRUE(ERRSV));
#endif
			PUTBACK;
			FREETMPS;
			LEAVE;
		}
	}
}

void ami_ctx_set_event_callback(AMIctx_t * ami_ctx, SV * event_callback)
{
	if (LIKELY(DEFINED(ami_ctx))) {
		if (LIKELY(DEFINED(event_callback))) {
			dTHX;
			if ((SvROK(event_callback) && SvTYPE(SvRV(event_callback)) == SVt_PVCV)) {
				if (UNLIKELY(DEFINED(ami_ctx->event_callback))) {
					SvREFCNT_dec(ami_ctx->event_callback);
				}
				ami_ctx->event_callback = newSVsv(event_callback);
			}
		}
	}
}

int ami_ctx_stop_events(AMIctx_t * ami_ctx)
{
	if (LIKELY(DEFINED(ami_ctx))) {
#ifdef DEBUG
		trace("ami_ctx_stop_events begin ctx: %p\n", ami_ctx);
		trace("ami_ctx_stop_events destroy read_ev_io: %p\n", ami_ctx->read_ev_io);
#endif

		if (LIKELY(DEFINED(ami_ctx->read_ev_io))) {
#ifdef DEBUG
			trace("ami_ctx_stop_events destroy defined read_ev_io: %p\n", ami_ctx->read_ev_io);
#endif
			UNDEF(ami_ctx->read_ev_io->data);

			if (ev_is_pending(ami_ctx->read_ev_io)) {
				ev_clear_pending(ami_ctx->loop, ami_ctx->read_ev_io);
			}

			if (LIKELY(ev_is_active(ami_ctx->read_ev_io))) {
#ifdef DEBUG
				trace("ami_ctx_stop_events stop read_ev_io\n");
#endif
				ev_io_stop(ami_ctx->loop, ami_ctx->read_ev_io);
			}
			FREE_AND_UNDEF(ami_ctx->read_ev_io);
		}
		if(LIKELY(DEFINED(ami_ctx->async_ev_w))) {
			if (LIKELY(ev_async_pending(ami_ctx->async_ev_w))) {
				ev_clear_pending(ami_ctx->loop, ami_ctx->async_ev_w);
			}
			if (LIKELY(ev_is_active(ami_ctx->async_ev_w))) {
				ev_async_stop(ami_ctx->loop, ami_ctx->async_ev_w);
			}
			UNDEF(ami_ctx->async_ev_w->data);
			FREE_AND_UNDEF(ami_ctx->async_ev_w);
		}
	}
#ifdef DEBUG
	trace("ami_ctx_stop_events end\n");
#endif
	return 0;
}

int ami_ctx_disconnect(AMIctx_t * ami_ctx)
{
	if (LIKELY(DEFINED(ami_ctx))) {
		if (ami_ctx->sockfd > 0) {
			fcntl(ami_ctx->sockfd, F_SETFL, 0);

			if (shutdown(ami_ctx->sockfd, SHUT_RDWR) == -1) {
				return ami_ctx->sockfd = -1;
			}

			if (close(ami_ctx->sockfd) == -1) {
				return ami_ctx->sockfd = -1;
			}

			ami_ctx->sockfd = -1;
		}
	}
	return 0;
}

void ami_ctx_fill_cb_packet (const AMIctx_t * ami_ctx, const AMIpkt_t * packet)
{
	dTHX;
	hv_clear(ami_ctx->hv);
	for (AMIfield_t * packet_field = packet->head; packet_field; packet_field = packet_field->next) {
		(void)hv_store(ami_ctx->hv, packet_field->name->content, packet_field->name->len, newSVpvn(packet_field->value->content, packet_field->value->len), 0);
	}
}

static void ami_ctx_ew_async_cb (struct ev_loop *loop, ev_async *w, int revents)
{
#ifdef DEBUG
	trace("EV async_cb call\n");
#endif
	AMIctx_t * ami_ctx = (AMIctx_t *)w->data;

	if (LIKELY(DEFINED(ami_ctx))) {
		AMIpkt_t * parsed_packet = NULL;
		if (LIKELY(DEFINED(ami_ctx->parsed_buffer))) {
#ifdef DEBUG
			trace("EV async_cb get parsed\n");
#endif
			while((parsed_packet = (AMIpkt_t *)ami_ctx_ring_buffer_pop(ami_ctx->parsed_buffer))) {
				trace("EV async_cb packet parsed\n");
				ami_ctx_fill_cb_packet(ami_ctx, parsed_packet);
				ami_ctx_invoke_event_callback(ami_ctx);
				ami_ctx_pkt_destroy(parsed_packet);
			}
#ifdef DEBUG
			trace("EV async_cb get parsed done\n");
#endif
		}
	}
#ifdef DEBUG
	trace("EV async_cb done\n");
#endif
}

static void ami_ctx_notify_parser_thread (AMIctx_t * ami_ctx)
{
	if (LIKELY(DEFINED(ami_ctx))) {
		pthread_mutex_lock(ami_ctx->lock);
		pthread_cond_signal(ami_ctx->invoke_cv);
		pthread_mutex_unlock(ami_ctx->lock);
	}
}

inline void ami_ctx_enqueue_packet_len (AMIctx_t * ami_ctx, size_t len)
{
	if (LIKELY(DEFINED(ami_ctx))) {
		ami_ctx_ring_buffer_push(ami_ctx->parse_buffer, (void *)ami_ctx_assign_packet_buffer(ami_ctx, len));
	}
}

inline ssize_t ami_ctx_forward_buffer_cursor (AMIctx_t * ami_ctx, ssize_t len)
{
	if (LIKELY(DEFINED(ami_ctx))) {
		ami_ctx->buffer_len += len;
		ami_ctx->buffer_cursor = ami_ctx->buffer_head + ami_ctx->buffer_len;
		ami_ctx->buffer_pos = (int)(ami_ctx->buffer_cursor - ami_ctx->buffer_head);
		ami_ctx->buffer_free = BUFFER_SIZE - ami_ctx->buffer_pos;
#ifdef DEBUG
		trace("New AMI buffer after forward len: %d, free memory: %d\n", ami_ctx->buffer_len, ami_ctx->buffer_free);
#endif
		return ami_ctx->buffer_len;
	}
	return -1;
}

inline ssize_t ami_ctx_rewind_buffer_cursor (AMIctx_t * ami_ctx, ssize_t len)
{
	if (LIKELY(DEFINED(ami_ctx))) {
#ifdef DEBUG
		trace("Residual AMI buffer len: %d\n", ami_ctx->buffer_len);
#endif
		memmove(ami_ctx->buffer_head, ami_ctx->buffer_head + len, ami_ctx->buffer_len - len);
		ami_ctx->buffer_len -= len;
		ami_ctx->buffer_cursor = ami_ctx->buffer_head + ami_ctx->buffer_len;
		ami_ctx->buffer_pos = (int)(ami_ctx->buffer_cursor - ami_ctx->buffer_head);
		ami_ctx->buffer_free = BUFFER_SIZE - ami_ctx->buffer_pos;
#ifdef DEBUG
		trace("New AMI buffer after rewind len: %d, free memory: %d\n", ami_ctx->buffer_len, ami_ctx->buffer_free);
#endif
		return ami_ctx->buffer_len;
	}
	return -1;
}

inline ssize_t ami_ctx_reset_buffer_cursor (AMIctx_t * ami_ctx)
{
	if (LIKELY(DEFINED(ami_ctx))) {
		ami_ctx->buffer_len = 0;
		ami_ctx->buffer_cursor = ami_ctx->buffer_head;
		ami_ctx->buffer_pos = 0;
		ami_ctx->buffer_free = BUFFER_SIZE;
#ifdef DEBUG
		trace("New AMI buffer after rewind len: %d, free memory: %d\n", ami_ctx->buffer_len, ami_ctx->buffer_free);
#endif
		return ami_ctx->buffer_len;
	}
	return -1;
}

inline bool ami_ctx_feed_buffer (AMIctx_t * ami_ctx)
{
	if (LIKELY(DEFINED(ami_ctx))) {
		int64_t found = 0;
		bool is_new_packets = false;
		while((found = ami_ctx_scan_packet_end(ami_ctx)) > -1) {
#ifdef DEBUG
			trace("found AMI packet end at: %d\n", found);
			char *read_packet = (char *)malloc(found);
			memcpy(read_packet, ami_ctx->buffer_head, found);
			trace("Read AMI packet:\n");
			trace_buff(read_packet, found);
			FREE_AND_UNDEF(read_packet);
			if (!(ami_ctx->stat_packets % 1000)) trace("Total packets: %d\n", ami_ctx->stat_packets);
#endif

			if (UNLIKELY(ami_ctx_scan_filter(ami_ctx))) {
#ifdef DEBUG
				char * found_packet = (char *)malloc(found);
				memcpy(found_packet, ami_ctx->buffer_head, found);
				trace("Filter passed AMI packet\n");
				trace_buff(found_packet, found);
				FREE_AND_UNDEF(found_packet);
#endif
				ami_ctx_enqueue_packet_len(ami_ctx, found);
				is_new_packets = true;
			}

			if (LIKELY(ami_ctx->buffer_len == found)) {
				(void)ami_ctx_reset_buffer_cursor(ami_ctx);
			} else {
				(void)ami_ctx_rewind_buffer_cursor(ami_ctx, found);
			}
		}
		return is_new_packets;
	}
	return false;
}

static void ami_ctx_ev_read_cb (struct ev_loop *loop, ev_io *w, int revents)
{
	AMIctx_t * ami_ctx = (AMIctx_t *)w->data;

	if (LIKELY(DEFINED(ami_ctx))) {
		if (UNLIKELY(revents & EV_ERROR && !(revents & EV_READ))) {
#ifdef DEBUG
			trace("EV error on read, fd=%d revents=0x%08x\n", ami_ctx->sockfd, revents);
#endif
			(void)ami_ctx_stop_events(ami_ctx);
			(void)ami_ctx_disconnect(ami_ctx);
			return;
		}

		ssize_t read_len = 0;

l_read:
		read_len = read(ami_ctx->sockfd, ami_ctx->buffer_cursor, min(PACKET_READ_BUFFER_SIZE, ami_ctx->buffer_free));

		if (UNLIKELY(read_len <= 0)) {
			if (LIKELY(read_len == 0)) {
#ifdef DEBUG
				trace("EOF detected in fd: %d\n", ami_ctx->sockfd);
#endif
				(void)ami_ctx_stop_events(ami_ctx);
				(void)ami_ctx_disconnect(ami_ctx);
				return;
			} else if (UNLIKELY(errno == EAGAIN || errno == EINTR)) {
#ifdef DEBUG
				trace("EAGAIN detected in fd: %d, status: %d \n", ami_ctx->sockfd, errno);
#endif
				goto l_read;
			}
		}
		else if (LIKELY(read_len > 0)) {
#ifdef DEBUG
			trace("Read AMI data fd %d, len: %d\n", ami_ctx->sockfd, read_len);
#endif
			(void)ami_ctx_forward_buffer_cursor(ami_ctx, read_len);
			if (ami_ctx_feed_buffer(ami_ctx)) ami_ctx_notify_parser_thread(ami_ctx);
		}
	}
}

static void ami_ctx_ev_read_banner_cb (struct ev_loop *loop, ev_io *w, int revents)
{
	AMIctx_t * ami_ctx = (AMIctx_t *)w->data;

	if (LIKELY(DEFINED(ami_ctx))) {
		if (UNLIKELY(revents & EV_ERROR && !(revents & EV_READ))) {
#ifdef DEBUG
			trace("EV banner error on read, fd=%d revents=0x%08x\n", ami_ctx->sockfd, revents);
#endif
			(void)ami_ctx_stop_events(ami_ctx);
			(void)ami_ctx_disconnect(ami_ctx);
			return;
		}

		ssize_t read_len = 0;

l_read:
		read_len = read(ami_ctx->sockfd, ami_ctx->buffer_cursor, ami_ctx->buffer_free);

		if (UNLIKELY(read_len <= 0)) {
			if (LIKELY(read_len == 0)) {
#ifdef DEBUG
				trace("EOF banner detected in fd: %d\n", ami_ctx->sockfd);
#endif
				(void)ami_ctx_stop_events(ami_ctx);
				(void)ami_ctx_disconnect(ami_ctx);
				return;
			} else if (UNLIKELY(errno == EAGAIN || errno == EINTR)) {
#ifdef DEBUG
				trace("EAGAIN banner detected in fd: %d, status: %d \n", ami_ctx->sockfd, errno);
#endif
				goto l_read;
			}
		}
		else if (LIKELY(read_len > 0)) {
			(void)ami_ctx_forward_buffer_cursor(ami_ctx, read_len);
#ifdef DEBUG
			trace("Read AMI banner data fd %d, len: %d\n", ami_ctx->sockfd, read_len);
			trace_buff(ami_ctx->buffer_head, ami_ctx->buffer_len);
#endif
			int64_t found = 0;
			if (LIKELY((found = ami_ctx_scan_banner_end(ami_ctx)) > -1)) {
#ifdef DEBUG
				trace("Found AMI banner end at: %d\n", found);
				char *found_packet = (char *)malloc(found);
				memmove(found_packet, ami_ctx->buffer_head, found);
				trace("Found AMI banner:\n");
				trace_buff(found_packet, found);
				FREE_AND_UNDEF(found_packet);
#endif
				(void)ami_ctx_reset_buffer_cursor(ami_ctx);
				ev_set_cb (w, ami_ctx_ev_read_cb);
			}
		}
	}
}

void * ami_ctx_thread(void * ptr)
{
	AMIctx_t * ami_ctx = (AMIctx_t *)ptr;
	AMIpktbuff_t * found_packet = NULL;
	AMIpkt_t * parsed_packet = NULL;
	bool parsed = false;
	if (LIKELY(DEFINED(ami_ctx))) {
		for(;;) {
			pthread_mutex_lock( ami_ctx->lock );
			parsed = false;
			while((found_packet = (AMIpktbuff_t *)ami_ctx_ring_buffer_pop(ami_ctx->parse_buffer))) {
#ifdef DEBUG
				trace("Thread message:\n");
				trace_buff(found_packet->buffer, found_packet->len);
#endif
				if(LIKELY((parsed_packet = ami_ctx_parse(found_packet)))) {
#ifdef DEBUG
					trace("Thread message parsed\n");
#endif
					ami_ctx_ring_buffer_push(ami_ctx->parsed_buffer, (void *)parsed_packet);
					parsed = true;
				}
				ami_ctx_destroy_packet_buffer(found_packet);
			}

			if (LIKELY(parsed)) ev_async_send(ami_ctx->loop, ami_ctx->async_ev_w);

			pthread_cond_wait(ami_ctx->invoke_cv, ami_ctx->lock);
			pthread_mutex_unlock(ami_ctx->lock);
		}
		pthread_exit(ami_ctx);
	}
}

int ami_ctx_setup_events(AMIctx_t * ami_ctx)
{
	if (LIKELY(DEFINED(ami_ctx))) {
		if (LIKELY(ami_ctx->sockfd > 0)) {
			if (LIKELY(ami_ctx->read_ev_io == NULL)) {
				ami_ctx->read_ev_io = (struct ev_io *)malloc(sizeof(struct ev_io));
				ev_io_init(ami_ctx->read_ev_io, ami_ctx_ev_read_banner_cb, ami_ctx->sockfd, EV_READ);
				ami_ctx->read_ev_io->data = (void *)ami_ctx;
				ev_io_start(ami_ctx->loop, ami_ctx->read_ev_io);

				ami_ctx->async_ev_w = (struct ev_async *)malloc(sizeof(struct ev_async));
				ev_async_init (ami_ctx->async_ev_w, ami_ctx_ew_async_cb);
				ami_ctx->async_ev_w->data = (void *)ami_ctx;
				ev_async_start (ami_ctx->loop, ami_ctx->async_ev_w);

				pthread_create (ami_ctx->tid, 0, ami_ctx_thread, ami_ctx);
				pthread_detach (*ami_ctx->tid);
			}
		} else {
			return -1;
		}
	}
	return 0;
}

int ami_ctx_connect(AMIctx_t * ami_ctx)
{
	if (LIKELY(DEFINED(ami_ctx))) {
		int flags;
		struct linger linger = { .l_onoff = 0, .l_linger = 0 };

		ami_ctx->sockfd = socket(AF_INET, SOCK_STREAM, 0);

		if (ami_ctx->sockfd < 0) {
#ifdef DEBUG
			trace("ERROR opening socket\n");
#endif
			return ami_ctx->sockfd = -1;
		}

		if (connect(ami_ctx->sockfd, (struct sockaddr *)&(ami_ctx->serv_addr), sizeof(ami_ctx->serv_addr)) < 0) {
#ifdef DEBUG
			trace("ERROR connecting\n");
#endif
			close(ami_ctx->sockfd);
			return ami_ctx->sockfd = -1;
		}

		flags = O_NONBLOCK;
		if (fcntl(ami_ctx->sockfd, F_SETFL, flags) < 0) {
			close(ami_ctx->sockfd);
			return ami_ctx->sockfd = -1;
		}

		flags = 1;
		if (setsockopt(ami_ctx->sockfd, SOL_TCP, TCP_NODELAY, &flags, sizeof(int))) {
			close(ami_ctx->sockfd);
			return ami_ctx->sockfd = -1;
		}

		flags = 1;
		if (setsockopt(ami_ctx->sockfd, SOL_SOCKET, SO_OOBINLINE, &flags, sizeof(int))) {
			close(ami_ctx->sockfd);
			return ami_ctx->sockfd = -1;
		}

		if (setsockopt(ami_ctx->sockfd, SOL_SOCKET, SO_LINGER, &linger, sizeof(linger))) {
			close(ami_ctx->sockfd);
			return ami_ctx->sockfd = -1;
		}
	}
	return 0;
}

int ami_ctx_fd(AMIctx_t * ami_ctx)
{
	if (LIKELY(DEFINED(ami_ctx))) {
		return ami_ctx->sockfd;
	}
	return -1;
}

ssize_t ami_ctx_write(AMIctx_t * ami_ctx, const char * packet)
{
	if (LIKELY(DEFINED(ami_ctx))) {
		if (LIKELY(ami_ctx->sockfd > 0)) {
			ssize_t write_len = write(ami_ctx->sockfd, packet, strlen(packet));
			return write_len;
		}
	}
	return 0;
}

struct ev_loop * ami_ctx_loop(AMIctx_t * ami_ctx, struct ev_loop * loop)
{
	if (LIKELY(DEFINED(ami_ctx))) {
		if (LIKELY(DEFINED(loop))) {
			ami_ctx->loop = loop;
		}
		return ami_ctx->loop;
	}
	return NULL;
}

void ami_ctx_destroy (AMIctx_t * ami_ctx)
{
	if (LIKELY(DEFINED(ami_ctx))) {
#ifdef DEBUG
		trace("ami_ctx_destroy begin\n");
#endif
		pthread_cancel(*ami_ctx->tid);

		pthread_mutex_destroy(ami_ctx->lock);
		pthread_cond_destroy(ami_ctx->invoke_cv);

		(void)ami_ctx_stop_events(ami_ctx);
#ifdef DEBUG
		trace("ami_ctx_stop_event\n");
#endif
		(void)ami_ctx_disconnect(ami_ctx);
#ifdef DEBUG
		trace("ami_ctx_disconnect\n");
#endif

		FREE_AND_UNDEF(ami_ctx->buffer);

		FREE_AND_UNDEF(ami_ctx->last_packet_head_type);

		FREE_AND_UNDEF(ami_ctx->last_event);

		if (ami_ctx->sockfd > 0) {
#ifdef DEBUG
			trace("ami_ctx_destroy close sockfd\n");
#endif
			close(ami_ctx->sockfd);
			ami_ctx->sockfd = -1;
		}

#ifdef DEBUG
		trace("ami_ctx_destroy main free\n");
#endif
		ami_ctx->error = true;
		ami_ctx->error_code = EAMI_DESTROY;

		ami_ctx_ring_buffer_destroy(ami_ctx->parse_buffer);
		ami_ctx_ring_buffer_destroy(ami_ctx->parsed_buffer);

		dTHX;

		if (LIKELY(DEFINED(ami_ctx->event_callback))) {
#ifdef DEBUG
			trace("ami_ctx_destroy destroy callback\n");
#endif
			SvREFCNT_dec(ami_ctx->event_callback);
			ami_ctx->event_callback = NULL;
		}

		hv_undef(ami_ctx->hv);
		ami_ctx->hv = NULL;
		sv_unref(ami_ctx->packet);
		ami_ctx->packet = NULL;

		FREE_AND_UNDEF(ami_ctx);
	}
#ifdef DEBUG
	trace("ami_ctx_destroy done\n");
#endif
}

MODULE = AMI		PACKAGE = AMIctx_tPtr  PREFIX = AMIctx_t_

void
AMIctx_t_DESTROY(ami_ctx)
		AMIctx_t *ami_ctx
	CODE:
#ifdef DEBUG
		trace("AMIctx_tPtr::DESTROY\n");
#endif
		ami_ctx_destroy(ami_ctx);
		ami_ctx = NULL;


MODULE = AMI		PACKAGE = AMI
PROTOTYPES: DISABLE

BOOT:
	{
		I_EV_API("AMI");
		}

AMIctx_t *
ami_connect(IN loop, IN host, IN port, IN event_callback)
	struct ev_loop * loop
	const char * host
	const char * port
	SV * event_callback
	INIT:
		AMIctx_t * ami_ctx = ami_ctx_init();
	CODE:
		(void)ami_ctx_loop(ami_ctx, loop);
		(void)ami_ctx_host(ami_ctx, host, port);
		if (ami_ctx_connect(ami_ctx) > -1) {
			(void)ami_ctx_setup_events(ami_ctx);
			ami_ctx_set_event_callback(ami_ctx, event_callback);
		} else {
		}

		RETVAL = ami_ctx;
	OUTPUT:
		RETVAL

int
ami_fd(IN ami_ctx)
	AMIctx_t * ami_ctx
	INIT:
		int fd = -1;
	CODE:
		fd = ami_ctx_fd(ami_ctx);
		RETVAL = fd;
	OUTPUT:
		RETVAL

int
ami_write(IN ami_ctx, IN packet)
	AMIctx_t * ami_ctx
	const char * packet
	INIT:
		int n = -1;
	CODE:
		n = ami_ctx_write(ami_ctx, packet);
		RETVAL = n;
	OUTPUT:
		RETVAL

void
ami_disconnect(IN ami_ctx)
	AMIctx_t * ami_ctx
	CODE:
		ami_ctx_destroy(ami_ctx);

SV *
to_packet(IN packet)
	const char * const packet
	INIT:
		HV * rh = newHV();
	CODE:
		register const char *cursor = packet;

		register const char *ch = cursor;
		register const char *prev_ch = ch;

		register const char *start_field = cursor;
		register const char *end_field = cursor;

		register const char *start_value = cursor;
		register const char *end_value = cursor;

		register bool process = true;

		while (process) {
			switch (*ch) {
			case ':':
				end_field = cursor - 1;
				break;
			case ' ':
				if (*prev_ch == ':') { start_value = cursor; }
				break;
			case '\r':
				if (*prev_ch == '\n') {
					process = false;
				} else {
					end_value = cursor - 1;
					(void)hv_store((HV *)rh, (const char *)start_field, (int)((const char *)end_field - (const char *)start_field), newSVpvn((const char *)start_value, (int)((const char *)end_value - (const char *)start_value)), 0);
				}
				break;
			case '\n':
				start_field = cursor;
			}
			prev_ch = ch;
			ch = cursor++;
		}
		RETVAL = newRV_noinc((SV *)rh);
	OUTPUT:
		RETVAL
