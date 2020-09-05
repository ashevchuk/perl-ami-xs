#define PERL_NO_GET_CONTEXT

#define EV_MULTIPLICITY 1

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


#define ALLOC_PAGE_SIZE sysconf(_SC_PAGESIZE)
#define BUFFER_PAGES 1024
#define BUFFER_SIZE ALLOC_PAGE_SIZE * BUFFER_PAGES
#define PACKET_HEAD_BUFFER_SIZE ALLOC_PAGE_SIZE
#define PACKET_READ_BUFFER_SIZE ALLOC_PAGE_SIZE

typedef char AMIcbuff_t;
typedef AMIcbuff_t * AMIcpbuff_t;

#define CONSTANT(A_VAR, A_VAL) static const AMIcpbuff_t A_VAR = A_VAL; static const unsigned int A_VAR ## _size = sizeof(A_VAL) - 1

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

#define ATOMIC_MEMORDER __ATOMIC_SEQ_CST
#define ATOMIC_COMPARE_EXCHANGE(ptr, expected, desired) __atomic_compare_exchange_n(ptr, expected, desired, 0, ATOMIC_MEMORDER, ATOMIC_MEMORDER)
#define ATOMIC_LOAD(ptr) __atomic_load_n(ptr, ATOMIC_MEMORDER)

#define ALLOC_MEM(A_PTR, A_LEN, A_TYPE) A_PTR = (A_TYPE *)malloc(A_LEN * sizeof(A_TYPE))
#define ALLOC_MEM_CAST(A_PTR, A_LEN, A_TYPE, A_CAST) A_PTR = (A_CAST *)malloc(A_LEN * sizeof(A_TYPE))
#define ALLOC_MEM_ZERO_FILL(A_PTR, A_LEN, A_TYPE) ALLOC_MEM(A_PTR, A_LEN, A_TYPE); memset((A_TYPE *)A_PTR, '\0', A_LEN * sizeof(A_TYPE))

#define ALLOC_DECLARE(A_PTR, A_LEN, A_TYPE) A_TYPE * A_PTR = NULL; ALLOC_MEM(A_PTR, A_LEN, A_TYPE)
#define ALLOC_DECLARE_CAST(A_PTR, A_LEN, A_TYPE, A_CAST) A_TYPE * A_PTR = NULL; ALLOC_MEM_CAST(A_PTR, A_LEN, A_TYPE, A_CAST)

#define FREE_MEM(A_PTR) free(A_PTR)

#define ALLOC_BUFF(A_PTR, A_LEN) ALLOC_MEM(A_PTR, A_LEN, AMIcbuff_t)
#define ALLOC_DECLARE_BUFF(A_PTR, A_LEN) AMIcpbuff_t A_PTR = NULL; ALLOC_MEM(A_PTR, A_LEN, AMIcbuff_t)

//#define DEFINED(A_PTR) A_PTR != NULL
#define DEFINED(A_PTR) A_PTR
#define UNDEF(A_PTR) A_PTR = NULL
#define FREE_AND_UNDEF_CHECKED(A_PTR) if (LIKELY(DEFINED(A_PTR))) { FREE_MEM(A_PTR); UNDEF(A_PTR); }
#define FREE_AND_UNDEF(A_PTR) do { FREE_MEM(A_PTR); UNDEF(A_PTR); } while(0)

#define max(a, b) ({ __typeof__ (a) _a = (a); __typeof__ (b) _b = (b); _a > _b ? _a : _b; })
#define min(a, b) ({ __typeof__ (a) _a = (a); __typeof__ (b) _b = (b); _a > _b ? _b : _a; })

#define DEBUG_STATS 1000000UL

#ifdef DEBUG_STATS
#define STATi(A_AMI_CTX, A_METRIC, A_VALUE) (A_AMI_CTX)->stat_ ## A_METRIC += A_VALUE
#define STATz(A_AMI_CTX, A_METRIC) (A_AMI_CTX)->stat_ ## A_METRIC = 0
#else
#define STATi(...)
#define STATz(...)
#endif


#ifdef DEBUG
#include <sys/ioctl.h>
#include <execinfo.h>
#include <time.h>

#define DEFAULT_TERM_COLS 80

size_t term_cols()
{
	struct winsize w;
	ioctl(STDOUT_FILENO, TIOCGWINSZ, &w);
	if (w.ws_col > 0) return w.ws_col;
	return DEFAULT_TERM_COLS;
}

#define LINE_SEPARATOR "-"

#define print_separator do { for (int i = 0; i < term_cols()/strlen(LINE_SEPARATOR); i++) fprintf(stderr, LINE_SEPARATOR); } while(0)

#define BACKTRACE_STACK_FRAMES 16

#define trace_back do { \
	void *frames[BACKTRACE_STACK_FRAMES]; \
	int size = backtrace(frames, BACKTRACE_STACK_FRAMES); \
	char **symbols = backtrace_symbols (frames, size); \
	if (symbols) { \
		fprintf(stderr, "%s:%-4i<%s> Call stack:\n", __FILE__, __LINE__, __PRETTY_FUNCTION__); \
		print_separator; \
		for (int i = size-1; i > 0; i--) { \
			fprintf(stderr, "|"); \
			for (int i2 = 0; i2 < i; i2++) fprintf(stderr, "-"); \
			fprintf(stderr, "%s\n", symbols[i]); \
		} \
		print_separator; \
	} \
	free (symbols); \
} while(0)

#define trace(A_FORMAT, ...) fprintf(stderr, "%s:%-4i<%s> " A_FORMAT, __FILE__, __LINE__, __PRETTY_FUNCTION__, ##__VA_ARGS__)
#define trace_dump(A_FORMAT, ...) fprintf(stderr, A_FORMAT, ##__VA_ARGS__)
#define trace_dump_label(A_FORMAT, A_FILE, A_LINE, A_CALLER, ...) fprintf(stderr, "%s:%-4i<%s> " A_FORMAT, A_FILE, A_LINE, A_CALLER, ##__VA_ARGS__)
#define buffer_dump(A_LABEL, A_BUFF, A_LEN) hexdump(A_LABEL, __FILE__, __LINE__, __PRETTY_FUNCTION__, A_BUFF, A_LEN)

void hexdump(const char * label, const char * file, int line, const char * caller, void const * data, size_t length) {
	int linelen = (int)(term_cols()/4);
	int split = linelen;
	char buffer[BUFFER_SIZE];
	char *ptr;
	const void *inptr;
	int pos;
	int remaining = length;
	inptr = data;
	assert(sizeof(buffer) >= (3 + (4 * (linelen / split)) + (linelen * 4)));
	trace_dump_label("%s @[%p] (%lu bytes):\n", file, line, caller, label, data, length);
	print_separator;
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
				sprintf(ptr, "%.2x ", *((unsigned char *) inptr + pos));
				lrem--;
			} else {
				sprintf(ptr, "   ");
			}
			ptr += 3;
		}
		*ptr++ = '|';
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
		trace_dump("%s\n", buffer);
		inptr += linelen;
		remaining -= linelen;
	}
	print_separator;
}
#else
#define trace(...)
#define buffer_dump(...)
#define trace_back
#endif

typedef enum AMIerr_e { EAMI_NONE = 0, EAMI_FATAL, EAMI_UNKNOWN, EAMI_DESTROY } AMIerr_t;

typedef enum AMIstate_e { SAMI_NONE = 0, SAMI_DESTROY } AMIstate_t;

typedef struct AMIbuff_s {
	uint64_t read_ptr;
	uint64_t write_ptr;
	int64_t len;
	void *ring[];
} AMIbuff_t;

typedef struct AMIvalue_s {
	size_t len;
	AMIcpbuff_t content __attribute__ ((nonstring));
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
	pthread_t * parse_thread_id;
	pthread_mutex_t * parse_thread_cv_lock;
	pthread_cond_t * parse_thread_cv;

	struct ev_async * async_ev_w;

	struct ev_io * read_ev_io;

	struct ev_loop * loop;

	AMIcpbuff_t buffer __attribute__ ((nonstring));
	AMIcpbuff_t buffer_head __attribute__ ((nonstring));
	AMIcpbuff_t buffer_cursor __attribute__ ((nonstring));

//	AMIcpbuff_t last_packet_head_type;
//	size_t last_packet_head_type_len;

	AMIfield_t * last_event;
//	AMIcpbuff_t last_event;
//	size_t last_event_len;

	SV * on_event_callback;
	SV * on_connect_callback;

	SV * on_error_callback;
	SV * on_disconnect_callback;
	SV * on_connect_error_callback;
	SV * on_timeout_callback;

	HV * hv;
	SV * packet;

	size_t buffer_len;
	size_t buffer_pos;
	size_t buffer_free;

	unsigned int portno;

	struct sockaddr_in serv_addr;
	struct hostent *server;

	int sockfd;
	bool error;
	AMIerr_t error_code;
	AMIbuff_t * parse_buffer;
	AMIbuff_t * parsed_buffer;

#ifdef DEBUG_STATS
	size_t stat_packets;
	size_t stat_bytes;
	size_t stat_callbacks;

	clock_t time_start;
	clock_t time_end;
	double time_used;
#endif
} AMIctx_t;

#define ami_ctx_value_declare(value) \
	ALLOC_DECLARE(value, 1, AMIvalue_t); \
	UNDEF(value->content); \
	value->len = 0;

#define ami_ctx_value_init(value) \
	ALLOC_MEM(value, 1, AMIvalue_t); \
	value->content = NULL; \
	value->len = 0;

#define ami_ctx_value_assign(A_VALUE, A_CONTENT, A_LEN) \
	if(LIKELY(DEFINED((A_VALUE)))) { \
		if (A_LEN > 0) { \
			if (LIKELY(DEFINED(A_CONTENT))) { \
				if (UNLIKELY(DEFINED((A_VALUE)->content))) { \
					if ((A_VALUE)->len != A_LEN) { \
						(A_VALUE)->len = 0; \
						(A_VALUE)->content = (AMIcpbuff_t)realloc((AMIcpbuff_t)(A_VALUE)->content, A_LEN); \
					} \
				} else { \
					ALLOC_BUFF((A_VALUE)->content, A_LEN); \
				} \
				memmove((A_VALUE)->content, A_CONTENT, A_LEN); \
				(A_VALUE)->len = A_LEN; \
			} \
		} \
	}

#define ami_ctx_value_destroy(A_VALUE) \
	if (LIKELY(DEFINED((A_VALUE)))) { \
		(A_VALUE)->len = 0; \
		FREE_AND_UNDEF((A_VALUE)->content); \
		FREE_AND_UNDEF((A_VALUE)); \
	}

#define ami_ctx_assign_packet_buffer(A_AMI_CTX, A_PACKET_BUFFER, A_LEN) \
	ami_ctx_value_declare(A_PACKET_BUFFER); \
	ami_ctx_value_assign(A_PACKET_BUFFER, (A_AMI_CTX)->buffer_head, A_LEN)

#define ami_ctx_pkt_declare(A_PACKET) \
	ALLOC_DECLARE((A_PACKET), 1, AMIpkt_t); \
	(A_PACKET)->len = 0; \
	UNDEF((A_PACKET)->head); \
	UNDEF((A_PACKET)->tail)

#define ami_ctx_pkt_init(A_PACKET) \
	ALLOC_MEM((A_PACKET), 1, AMIpkt_t); \
	(A_PACKET)->len = 0; \
	UNDEF((A_PACKET)->head); \
	UNDEF((A_PACKET)->tail)

#define ami_ctx_field_destroy(A_FIELD) \
	if (LIKELY(DEFINED((A_FIELD)))) { \
		ami_ctx_value_destroy((A_FIELD)->name); \
		ami_ctx_value_destroy((A_FIELD)->value); \
		FREE_AND_UNDEF((A_FIELD)); \
	}

#define ami_ctx_field_init(A_FIELD) \
	ALLOC_MEM((A_FIELD), 1, AMIfield_t); \
	ami_ctx_value_init((A_FIELD)->name); \
	ami_ctx_value_init((A_FIELD)->value)

#define ami_ctx_field_declare(A_FIELD) \
	ALLOC_DECLARE((A_FIELD), 1, AMIfield_t); \
	ami_ctx_value_init((A_FIELD)->name); \
	ami_ctx_value_init((A_FIELD)->value)

#define ami_ctx_field_create(A_NEW_FIELD, A_FIELD, A_FIELD_LEN, A_VALUE, A_VALUE_LEN) \
	ami_ctx_field_declare((A_NEW_FIELD)); \
	ami_ctx_value_assign((A_NEW_FIELD)->name, A_FIELD, A_FIELD_LEN); \
	ami_ctx_value_assign((A_NEW_FIELD)->value, A_VALUE, A_VALUE_LEN)

#define ami_ctx_field_assign(A_NEW_FIELD, A_FIELD, A_FIELD_LEN, A_VALUE, A_VALUE_LEN) \
	ami_ctx_value_assign((A_NEW_FIELD)->name, A_FIELD, A_FIELD_LEN); \
	ami_ctx_value_assign((A_NEW_FIELD)->value, A_VALUE, A_VALUE_LEN)

#define ami_ctx_pkt_destroy(A_PACKET) \
	if (LIKELY(DEFINED((A_PACKET)))) { \
		AMIfield_t * field = NULL; \
		AMIfield_t * next_field = NULL; \
		for (field = (A_PACKET)->head; DEFINED(field); field = next_field) { \
			next_field = field->next; \
			ami_ctx_field_destroy (field); \
		} \
		FREE_AND_UNDEF((A_PACKET)); \
	}

#define ami_ctx_pkt_push_field(A_PACKET, A_FIELD) \
	if (LIKELY(DEFINED((A_PACKET)))) { \
		if (LIKELY(DEFINED((A_FIELD)))) { \
			if ((A_PACKET)->len > 0) { \
				(A_PACKET)->tail->next = (A_FIELD); \
			} else { \
				(A_PACKET)->head = (A_FIELD); \
			} \
			(A_PACKET)->tail = (A_FIELD); \
			UNDEF((A_FIELD)->next); \
			(A_PACKET)->len++; \
		} \
	}

#define ami_ctx_pkt_set_field(A_PACKET, A_FIELD, A_FIELD_LEN, A_VALUE, A_VALUE_LEN) \
	ami_ctx_field_create(new_field, (A_FIELD), (A_FIELD_LEN), (A_VALUE), (A_VALUE_LEN)); \
	ami_ctx_pkt_push_field((A_PACKET), new_field)

AMIbuff_t *ami_ctx_ring_buffer_init(size_t len)
{
	AMIbuff_t * ring_buffer = malloc(sizeof(AMIbuff_t) + len * sizeof(void*));
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

AMIfield_t * ami_ctx_pkt_get_field(AMIpkt_t * packet, const AMIcpbuff_t field, size_t len)
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
	ALLOC_DECLARE(ami_ctx, 1, AMIctx_t);

	ami_ctx_field_init(ami_ctx->last_event);

	ami_ctx->buffer_len = 0;
	ami_ctx->buffer_pos = 0;
	ami_ctx->buffer_free = BUFFER_SIZE;

	ALLOC_BUFF(ami_ctx->buffer, BUFFER_SIZE);

	ami_ctx->buffer_head = ami_ctx->buffer;
	ami_ctx->buffer_cursor = ami_ctx->buffer;

	ami_ctx->loop = EV_DEFAULT;

	ami_ctx->sockfd = -1;
	ami_ctx->portno = 5038;

	UNDEF(ami_ctx->server);

	UNDEF(ami_ctx->on_event_callback);
	UNDEF(ami_ctx->on_connect_callback);
	UNDEF(ami_ctx->on_error_callback);
	UNDEF(ami_ctx->on_disconnect_callback);
	UNDEF(ami_ctx->on_connect_error_callback);
	UNDEF(ami_ctx->on_timeout_callback);

	UNDEF(ami_ctx->read_ev_io);
	UNDEF(ami_ctx->async_ev_w);

	memset(&ami_ctx->serv_addr, '0', sizeof(ami_ctx->serv_addr));

	ami_ctx->error = false;
	ami_ctx->error_code = EAMI_NONE;

	ALLOC_MEM(ami_ctx->parse_thread_id, 1, pthread_t);

	ALLOC_MEM(ami_ctx->parse_thread_cv_lock, 1, pthread_mutex_t);
	pthread_mutex_init(ami_ctx->parse_thread_cv_lock, NULL);

	ALLOC_MEM(ami_ctx->parse_thread_cv, 1, pthread_cond_t);
	pthread_cond_init(ami_ctx->parse_thread_cv, NULL);

	ami_ctx->parse_buffer = ami_ctx_ring_buffer_init(BUFFER_PAGES);
	ami_ctx->parsed_buffer = ami_ctx_ring_buffer_init(BUFFER_PAGES);

#ifdef DEBUG_STATS
	ami_ctx->time_start = clock();
	ami_ctx->time_end = clock();
	ami_ctx->time_used = ((double) (ami_ctx->time_end - ami_ctx->time_start)) / CLOCKS_PER_SEC;
	ami_ctx->stat_packets = 0;
	ami_ctx->stat_bytes = 0;
	ami_ctx->stat_callbacks = 0;
#endif

	dTHX;
	ami_ctx->hv = newHV();
	ami_ctx->packet = newRV_noinc((SV *)ami_ctx->hv);

	return ami_ctx;
}

#define ami_ctx_destroy_callback(A_CALLBACK) \
	if (LIKELY(DEFINED(A_CALLBACK))) { \
		dTHX; \
		SvREFCNT_dec(A_CALLBACK); \
		UNDEF(A_CALLBACK); \
	}

#define ami_ctx_call_perl_sub(A_AMI_CTX, A_CALLBACK, A_DATA) \
	if (LIKELY(DEFINED(A_CALLBACK))) { \
		STATi(A_AMI_CTX, callbacks, 1); \
		dTHX; \
		dSP; \
		if (LIKELY(DEFINED(A_DATA))) { \
			ENTER; SAVETMPS; \
			PUSHMARK(SP); PUSHs(A_DATA); PUTBACK; \
		} \
		call_sv(A_CALLBACK, G_VOID); \
		if (UNLIKELY(SvTRUE(ERRSV))) { \
			fprintf(stderr, "Callback err:\n"); sv_dump(ERRSV); \
		} \
		if (LIKELY(DEFINED(A_DATA))) { \
			SPAGAIN; PUTBACK; \
			FREETMPS; LEAVE; \
		} \
	}

#define ami_ctx_invoke_callback(A_AMI_CTX, A_EVENT, A_DATA) ami_ctx_call_perl_sub(A_AMI_CTX, (A_AMI_CTX)->on_ ## A_EVENT ## _callback, A_DATA)

#define ami_ctx_assign_callback(ami_ctx, on_callback, callback) \
	if (LIKELY(DEFINED(callback))) { \
		dTHX; \
		if ((SvROK(callback) && SvTYPE(SvRV(callback)) == SVt_PVCV)) { \
			if (UNLIKELY(DEFINED(on_callback))) { \
				ami_ctx_destroy_callback(on_callback); \
			} \
			on_callback = (SV*)newSVsv((SV*)callback); \
		} \
	} \

#define ami_ctx_set_callback(A_AMI_CTX, A_EVENT, A_CALLBACK) \
	if (LIKELY(DEFINED((A_CALLBACK)))) { \
		ami_ctx_assign_callback((A_AMI_CTX), (A_AMI_CTX)->on_ ## A_EVENT ## _callback, (A_CALLBACK)); \
	} \

void ami_ctx_set_event_callback(AMIctx_t * ami_ctx, SV * callback) {
	ami_ctx_set_callback(ami_ctx, event, callback);
}

#define ami_ctx_invoke_event_callback(A_AMI_CTX) ami_ctx_invoke_callback((A_AMI_CTX), event, (A_AMI_CTX)->packet)

void ami_ctx_set_connect_callback(AMIctx_t * ami_ctx, SV * callback) { ami_ctx_set_callback(ami_ctx, connect, callback); }
void ami_ctx_invoke_connect_callback(AMIctx_t * ami_ctx) { ami_ctx_invoke_callback(ami_ctx, connect, NULL); }
void ami_ctx_set_error_callback(AMIctx_t * ami_ctx, SV * callback) { ami_ctx_set_callback(ami_ctx, error, callback); }
void ami_ctx_invoke_error_callback(AMIctx_t * ami_ctx) { ami_ctx_invoke_callback(ami_ctx, error, NULL); }
void ami_ctx_set_disconnect_callback(AMIctx_t * ami_ctx, SV * callback) { ami_ctx_set_callback(ami_ctx, disconnect, callback); }
void ami_ctx_invoke_disconnect_callback(AMIctx_t * ami_ctx) { ami_ctx_invoke_callback(ami_ctx, disconnect, NULL); }
void ami_ctx_set_connect_error_callback(AMIctx_t * ami_ctx, SV * callback) { ami_ctx_set_callback(ami_ctx, connect_error, callback); }
void ami_ctx_invoke_connect_error_callback(AMIctx_t * ami_ctx) { ami_ctx_invoke_callback(ami_ctx, connect_error, NULL); }
void ami_ctx_set_timeout_callback(AMIctx_t * ami_ctx, SV * callback) { ami_ctx_set_callback(ami_ctx, timeout, callback); }
void ami_ctx_invoke_timeout_callback(AMIctx_t * ami_ctx) { ami_ctx_invoke_callback(ami_ctx, timeout, NULL); }

void ami_ctx_set_error(AMIctx_t * ami_ctx, const AMIerr_t code, const AMIcpbuff_t message)
{
#ifdef DEBUG
	trace("AMI error: %s, code: %d\n", message, (uint8_t)code);
#endif
		ami_ctx->error = true;
		ami_ctx->error_code = code;
		ami_ctx_invoke_error_callback(ami_ctx);
}

bool ami_ctx_is_error(AMIctx_t * ami_ctx)
{
	return ami_ctx->error;
}

int ami_ctx_host(AMIctx_t * ami_ctx, const AMIcpbuff_t host, const AMIcpbuff_t port)
{
		ami_ctx->serv_addr.sin_family = AF_INET;

		ami_ctx->portno = atoi(port);
		ami_ctx->serv_addr.sin_port = htons(ami_ctx->portno);

		ami_ctx->server = gethostbyname(host);

		if (ami_ctx->server == NULL) {
#ifdef DEBUG
			trace("ERROR: no such host\n");
#endif
			ami_ctx_invoke_connect_error_callback(ami_ctx);
			return -1;
		}

		bcopy((AMIcpbuff_t)ami_ctx->server->h_addr, (AMIcpbuff_t)&(ami_ctx->serv_addr.sin_addr.s_addr), ami_ctx->server->h_length);
	return 0;
}

#define ami_ctx_parse_buffer(A_PARSED_PACKET, A_PACKET_BUFFER) \
	ami_ctx_pkt_declare(A_PARSED_PACKET); \
	AMIcpbuff_t packet = (A_PACKET_BUFFER)->content; \
	AMIcpbuff_t cursor = packet; \
	AMIcpbuff_t tail = (A_PACKET_BUFFER)->content + (A_PACKET_BUFFER)->len; \
	AMIcpbuff_t f1; \
	AMIcpbuff_t f2; \
	AMIcpbuff_t v1; \
	AMIcpbuff_t v2; \
	AMIcpbuff_t yyt1; \
	AMIcpbuff_t yyt2; \
	AMIcpbuff_t yyt3; \
	char yych; \
	static const unsigned char yybm[] = { \
		128, 128, 128, 128, 128, 128, 128, 128, \
		128, 160, 128, 128, 128,   0, 128, 128, \
		128, 128, 128, 128, 128, 128, 128, 128, \
		128, 128, 128, 128, 128, 128, 128, 128, \
		160, 128, 128, 128, 128, 128, 128, 128, \
		128, 128, 128, 128, 128, 192, 192, 128, \
		192, 192, 192, 192, 192, 192, 192, 192, \
		192, 192, 128, 128, 128, 128, 128, 128, \
		128, 192, 192, 192, 192, 192, 192, 192, \
		192, 192, 192, 192, 192, 192, 192, 192, \
		192, 192, 192, 192, 192, 192, 192, 192, \
		192, 192, 192, 128, 128, 128, 128, 192, \
		128, 192, 192, 192, 192, 192, 192, 192, \
		192, 192, 192, 192, 192, 192, 192, 192, \
		192, 192, 192, 192, 192, 192, 192, 192, \
		192, 192, 192, 128, 128, 128, 128, 128, \
		128, 128, 128, 128, 128, 128, 128, 128, \
		128, 128, 128, 128, 128, 128, 128, 128, \
		128, 128, 128, 128, 128, 128, 128, 128, \
		128, 128, 128, 128, 128, 128, 128, 128, \
		128, 128, 128, 128, 128, 128, 128, 128, \
		128, 128, 128, 128, 128, 128, 128, 128, \
		128, 128, 128, 128, 128, 128, 128, 128, \
		128, 128, 128, 128, 128, 128, 128, 128, \
		128, 128, 128, 128, 128, 128, 128, 128, \
		128, 128, 128, 128, 128, 128, 128, 128, \
		128, 128, 128, 128, 128, 128, 128, 128, \
		128, 128, 128, 128, 128, 128, 128, 128, \
		128, 128, 128, 128, 128, 128, 128, 128, \
		128, 128, 128, 128, 128, 128, 128, 128, \
		128, 128, 128, 128, 128, 128, 128, 128, \
		128, 128, 128, 128, 128, 128, 128, 128, \
	}; \
 \
	static void *yytarget[256] = { \
		&&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3, \
		&&yy3,  &&yy12, &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3, \
		&&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3, \
		&&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3, \
		&&yy12, &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3, \
		&&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy12, &&yy12, &&yy3, \
		&&yy12, &&yy12, &&yy12, &&yy12, &&yy12, &&yy12, &&yy12, &&yy12, \
		&&yy12, &&yy12, &&yy12, &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3, \
		&&yy3,  &&yy12, &&yy12, &&yy12, &&yy12, &&yy12, &&yy12, &&yy12, \
		&&yy12, &&yy12, &&yy12, &&yy12, &&yy12, &&yy12, &&yy12, &&yy12, \
		&&yy12, &&yy12, &&yy12, &&yy12, &&yy12, &&yy12, &&yy12, &&yy12, \
		&&yy12, &&yy12, &&yy12, &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy12, \
		&&yy3,  &&yy12, &&yy12, &&yy12, &&yy12, &&yy12, &&yy12, &&yy12, \
		&&yy12, &&yy12, &&yy12, &&yy12, &&yy12, &&yy12, &&yy12, &&yy12, \
		&&yy12, &&yy12, &&yy12, &&yy12, &&yy12, &&yy12, &&yy12, &&yy12, \
		&&yy12, &&yy12, &&yy12, &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3, \
		&&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3, \
		&&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3, \
		&&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3, \
		&&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3, \
		&&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3, \
		&&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3, \
		&&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3, \
		&&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3, \
		&&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3, \
		&&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3, \
		&&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3, \
		&&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3, \
		&&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3, \
		&&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3, \
		&&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3, \
		&&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3,  &&yy3 \
	}; \
	while (cursor != tail) { \
		yych = *cursor; \
		if (yych <= '9') { \
			if (yych <= ',') { \
				if (yych == '\r') goto yy4; \
			} else { \
				if (yych != '/') { \
					yyt1 = cursor; \
					goto yy5; \
				} \
			} \
		} else { \
			if (yych <= '^') { \
				if (yych <= '@') goto yy2; \
				if (yych <= 'Z') { \
					yyt1 = cursor; \
					goto yy5; \
				} \
			} else { \
				if (yych == '`') goto yy2; \
				if (yych <= 'z') { \
					yyt1 = cursor; \
					goto yy5; \
				} \
			} \
		} \
		yy2: \
			++cursor; \
		yy3: \
			{ \
			break; \
			} \
		yy4: \
			yych = *++cursor; \
			if (yych == '\n') goto yy6; \
			goto yy3; \
		yy5: \
			yych = *(packet = ++cursor); \
			{ \
				goto *yytarget[(unsigned int)yych]; \
			} \
		yy6: \
			++cursor; \
			{ break; } \
		yy8: \
			yych = *++cursor; \
			if (yybm[0+yych] & 32) { \
				goto yy8; \
			} \
			if (yych == ':') goto yy13; \
		yy10: \
			cursor = packet; \
			goto yy3; \
		yy11: \
			yych = *++cursor; \
		yy12: \
			if (yybm[0+yych] & 64) { \
				goto yy11; \
			} \
			if (yych <= 0x1F) { \
				goto yy10; \
			} else { \
				if (yych <= ' ') { \
					yyt2 = cursor; \
					goto yy8; \
				} \
				if (yych <= '/') goto yy10; \
				if (yych >= ';') goto yy10; \
				yyt2 = cursor; \
			} \
		yy13: \
			yych = *++cursor; \
			if (yych <= '\f') { \
				yyt3 = cursor; \
			} else { \
				if (yych <= '\r') { \
					yyt3 = cursor; \
					goto yy17; \
				} \
				if (yych == ' ') goto yy13; \
				yyt3 = cursor; \
			} \
		yy15: \
			yych = *++cursor; \
			if (yybm[0+yych] & 128) { \
				goto yy15; \
			} \
		yy17: \
			yych = *++cursor; \
			if (yych != '\n') goto yy10; \
			++cursor; \
			f1 = yyt1; \
			f2 = yyt2; \
			v1 = yyt3; \
			v2 = cursor - 2; \
			{ \
				ami_ctx_pkt_set_field(A_PARSED_PACKET, f1, (int)(f2 - f1), v1, (int)(v2 - v1)); \
				continue; \
			} \
	}

inline int64_t ami_ctx_scan_char(const AMIctx_t * ami_ctx, const AMIcpbuff_t value )
{
	register AMIcpbuff_t cursor = (AMIcpbuff_t)memchr(ami_ctx->buffer_head, *value, ami_ctx->buffer_len);
	if (LIKELY(DEFINED(cursor))) {
		return cursor - ami_ctx->buffer_head + 1;
	}
	return -1;
}

inline int64_t ami_ctx_scan_chars(const AMIctx_t * ami_ctx, const AMIcpbuff_t value, size_t len)
{
	register AMIcpbuff_t cursor = (AMIcpbuff_t)memmem(ami_ctx->buffer_head, ami_ctx->buffer_len, value, len);
	if (LIKELY(DEFINED(cursor))) {
		return cursor - ami_ctx->buffer_head + 1;
	}
	return -1;
}

inline int64_t ami_ctx_scan_nchars(const AMIctx_t * ami_ctx, size_t buffer_len, const AMIcpbuff_t value, const size_t len )
{
	register AMIcpbuff_t cursor = (AMIcpbuff_t)memmem(ami_ctx->buffer_head, buffer_len, value, len);
	if (LIKELY(DEFINED(cursor))) {
		return cursor - ami_ctx->buffer_head + 1;
	}
	return -1;
}

static inline int64_t ami_ctx_scan_packet_end(const AMIctx_t * ami_ctx )
{
	register int64_t i = 0;
	if (LIKELY((i = ami_ctx_scan_chars( ami_ctx, ast_pkt_separator_end, ast_pkt_separator_end_size)) > -1)) {
		return i+ast_pkt_separator_end_size-1;
	}
	return -1;
}

static inline int64_t ami_ctx_scan_banner_end(const AMIctx_t * ami_ctx )
{
	register int64_t i = 0;
	if (LIKELY((i = ami_ctx_scan_chars( ami_ctx, ast_pkt_separator_field_end, ast_pkt_separator_field_end_size)) > -1)) {
		if (LIKELY(ami_ctx_scan_nchars( ami_ctx, i-1, ast_pkt_banner, ast_pkt_banner_size) > -1)) {
			return i+ast_pkt_separator_field_end_size;
		}
	}
	return -1;
}

#define ami_ctx_scan_head(A_AMI_CTX) \
	register int64_t i = 0; \
	register int64_t i2 = 0; \
	if (LIKELY((i = ami_ctx_scan_chars( (A_AMI_CTX), ast_pkt_separator_field_end, ast_pkt_separator_field_end_size)) > -1)) { \
		buffer_dump("Packet head detected", (A_AMI_CTX)->buffer_head, i-1); \
		if (LIKELY(( i2 = ami_ctx_scan_nchars( (A_AMI_CTX), i-1, ast_pkt_separator_field_value, ast_pkt_separator_field_value_size)) > -1)) { \
			STATi(A_AMI_CTX, packets, 1); \
			ami_ctx_field_assign((A_AMI_CTX)->last_event, (A_AMI_CTX)->buffer_head, i2 - 1, (A_AMI_CTX)->buffer_head + i2 + 1, i - i2 - 2); \
			buffer_dump("Packet type detected", (A_AMI_CTX)->last_event->name->content, (A_AMI_CTX)->last_event->name->len); \
			buffer_dump("Packet value detected", (A_AMI_CTX)->last_event->value->content, (A_AMI_CTX)->last_event->value->len); \
		} \
	} \

bool ami_ctx_scan_filter(AMIctx_t * ami_ctx )
{
		ami_ctx_scan_head(ami_ctx);
		return true;
		if (LIKELY(!memcmp(ami_ctx->last_event->name->content, ast_pkt_head_event, min(ast_pkt_head_event_size, ami_ctx->last_event->name->len)))) {
#ifdef DEBUG
			buffer_dump("Packet type passed filter", ami_ctx->last_event->name->content, ami_ctx->last_event->name->len);
#endif
			if (LIKELY(!memcmp(ami_ctx->last_event->value->content, ast_pkt_head_event_well_known, min(ast_pkt_head_event_well_known_size, ami_ctx->last_event->value->len)))) {
#ifdef DEBUG
				buffer_dump("Packet value passed filter", ami_ctx->last_event->value->content, ami_ctx->last_event->value->len);
#endif
				return true;
			}
		} else {
			return true;
		}
	return false;
}

int ami_ctx_stop_events(AMIctx_t * ami_ctx)
{
#ifdef DEBUG
	trace("ami_ctx_stop_events begin ctx: %p\n", ami_ctx);
	trace("ami_ctx_stop_events destroy read_ev_io: %p\n", ami_ctx->read_ev_io);
#endif
	if (LIKELY(DEFINED(ami_ctx->read_ev_io))) {
		pthread_cancel(*ami_ctx->parse_thread_id);
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

#ifdef DEBUG
	trace("ami_ctx_stop_events end\n");
#endif
	return 0;
}

int ami_ctx_disconnect(AMIctx_t * ami_ctx)
{
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
	ami_ctx_invoke_disconnect_callback(ami_ctx);

	return 0;
}

#define ami_ctx_fill_cb_packet(A_AMI_CTX, A_PACKET) \
	hv_clear((A_AMI_CTX)->hv); \
	for (AMIfield_t * packet_field = A_PACKET->head; packet_field; packet_field = packet_field->next) { \
		(void)hv_store((A_AMI_CTX)->hv, packet_field->name->content, packet_field->name->len, newSVpvn(packet_field->value->content, packet_field->value->len), 0); \
	}

static void ami_ctx_ew_async_cb (struct ev_loop *loop, ev_async *w, int revents)
{
	dTHX;
	AMIpkt_t * parsed_packet = NULL;
#ifdef DEBUG
	trace("EV async_cb get parsed AMI packets\n");
	size_t processed = 0;
#endif
	while((parsed_packet = ami_ctx_ring_buffer_pop(((AMIctx_t *)w->data)->parsed_buffer))) {
#ifdef DEBUG
		processed++;
#endif
		ami_ctx_fill_cb_packet((AMIctx_t *)w->data, parsed_packet);
		ami_ctx_invoke_event_callback((AMIctx_t *)w->data);
		ami_ctx_pkt_destroy(parsed_packet);
	}
#ifdef DEBUG
	trace("EV async_cb get parsed done: %lu packets\n", processed);
#endif
}

#define ami_ctx_notify_parser_thread(A_AMI_CTX) \
	pthread_mutex_lock((A_AMI_CTX)->parse_thread_cv_lock); \
	pthread_cond_signal((A_AMI_CTX)->parse_thread_cv); \
	pthread_mutex_unlock((A_AMI_CTX)->parse_thread_cv_lock)

void ami_ctx_enqueue_packet_len (AMIctx_t * ami_ctx, size_t len)
{
	if (LIKELY(DEFINED(ami_ctx))) {
		ami_ctx_assign_packet_buffer(ami_ctx, packet_buffer, len);
		ami_ctx_ring_buffer_push(ami_ctx->parse_buffer, packet_buffer);
	}
}

ssize_t ami_ctx_forward_buffer_cursor (AMIctx_t * ami_ctx, ssize_t len)
{
	if (LIKELY(DEFINED(ami_ctx))) {
		ami_ctx->buffer_len += len;
		ami_ctx->buffer_cursor = ami_ctx->buffer_head + ami_ctx->buffer_len;
		ami_ctx->buffer_pos = (int)(ami_ctx->buffer_cursor - ami_ctx->buffer_head);
		ami_ctx->buffer_free = BUFFER_SIZE - ami_ctx->buffer_pos;
#ifdef DEBUG
		trace("New AMI buffer after forward len: %lu, free memory: %lu\n", ami_ctx->buffer_len, ami_ctx->buffer_free);
#endif
		return ami_ctx->buffer_len;
	}
	return -1;
}

ssize_t ami_ctx_rewind_buffer_cursor (AMIctx_t * ami_ctx, ssize_t len)
{
	if (LIKELY(DEFINED(ami_ctx))) {
#ifdef DEBUG
		trace("Residual AMI buffer len: %lu\n", ami_ctx->buffer_len);
#endif
		memmove(ami_ctx->buffer_head, ami_ctx->buffer_head + len, ami_ctx->buffer_len - len);
		ami_ctx->buffer_len -= len;
		ami_ctx->buffer_cursor = ami_ctx->buffer_head + ami_ctx->buffer_len;
		ami_ctx->buffer_pos = (int)(ami_ctx->buffer_cursor - ami_ctx->buffer_head);
		ami_ctx->buffer_free = BUFFER_SIZE - ami_ctx->buffer_pos;
#ifdef DEBUG
		trace("New AMI buffer after rewind len: %lu, free memory: %lu\n", ami_ctx->buffer_len, ami_ctx->buffer_free);
#endif
		return ami_ctx->buffer_len;
	}
	return -1;
}

ssize_t ami_ctx_reset_buffer_cursor (AMIctx_t * ami_ctx)
{
	if (LIKELY(DEFINED(ami_ctx))) {
		ami_ctx->buffer_len = 0;
		ami_ctx->buffer_cursor = ami_ctx->buffer_head;
		ami_ctx->buffer_pos = 0;
		ami_ctx->buffer_free = BUFFER_SIZE;
#ifdef DEBUG
		trace("New AMI buffer after rewind len: %lu, free memory: %lu\n", ami_ctx->buffer_len, ami_ctx->buffer_free);
#endif
		return ami_ctx->buffer_len;
	}
	return -1;
}

bool ami_ctx_feed_buffer (AMIctx_t * ami_ctx)
{
	if (LIKELY(DEFINED(ami_ctx))) {
		int64_t found = 0;
		bool is_new_packets = false;
		while((found = ami_ctx_scan_packet_end(ami_ctx)) > -1) {

#ifdef DEBUG_STATS
			if (ami_ctx->stat_packets > 0 && (ami_ctx->stat_packets % DEBUG_STATS == 0)) {
				ami_ctx->time_end = clock();
				ami_ctx->time_used = ((double) (ami_ctx->time_end - ami_ctx->time_start)) / CLOCKS_PER_SEC;
				ami_ctx->time_start = clock();
				fprintf(stderr, "Stats: packets=%lu, bytes=%lu, callbacks=%lu, seconds=%f, bps=%f, pps=%f\n", ami_ctx->stat_packets, ami_ctx->stat_bytes, ami_ctx->stat_callbacks, ami_ctx->time_used, ami_ctx->stat_bytes/ami_ctx->time_used, ami_ctx->stat_packets/ami_ctx->time_used);
				STATz(ami_ctx, packets);
				STATz(ami_ctx, bytes);
				STATz(ami_ctx, callbacks);
			}
#endif

#ifdef DEBUG
			buffer_dump("Detected AMI packet", ami_ctx->buffer_head, found);
#endif
			if (UNLIKELY(ami_ctx_scan_filter(ami_ctx))) {
#ifdef DEBUG
				buffer_dump("AMI packet passed filter", ami_ctx->buffer_head, found);
#endif

#ifndef DEBUG_STATS
				ami_ctx_enqueue_packet_len(ami_ctx, found);
				is_new_packets = true;
#endif
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
		//read_len = read(ami_ctx->sockfd, ami_ctx->buffer_cursor, min(PACKET_READ_BUFFER_SIZE, ami_ctx->buffer_free));
		read_len = read(ami_ctx->sockfd, ami_ctx->buffer_cursor, ami_ctx->buffer_free);

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
			STATi(ami_ctx, bytes, read_len);
#ifdef DEBUG
			trace("Read AMI data fd:%i, len: %li\n", ami_ctx->sockfd, read_len);
#endif
			ami_ctx_forward_buffer_cursor(ami_ctx, read_len);
			if (ami_ctx_feed_buffer(ami_ctx)) {
				ami_ctx_notify_parser_thread(ami_ctx);
			}
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
				trace("EOF banner detected in fd: %i\n", ami_ctx->sockfd);
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
			STATi(ami_ctx, bytes, read_len);
			(void)ami_ctx_forward_buffer_cursor(ami_ctx, read_len);
#ifdef DEBUG
			trace("Read AMI banner data fd: %i, len: %li\n", ami_ctx->sockfd, read_len);
			buffer_dump("Read AMI banner data", ami_ctx->buffer_head, ami_ctx->buffer_len);
#endif
			int64_t found = 0;
			if (LIKELY((found = ami_ctx_scan_banner_end(ami_ctx)) > -1)) {
#ifdef DEBUG
				buffer_dump("Found AMI banner", ami_ctx->buffer_head, found);
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
	AMIvalue_t * found_packet = NULL;
	//AMIpkt_t * parsed_packet = NULL;
	bool parsed = false;
	if (LIKELY(DEFINED(ami_ctx))) {
		for(;;) {
			pthread_mutex_lock( ami_ctx->parse_thread_cv_lock );
			parsed = false;
			while((found_packet = (AMIvalue_t *)ami_ctx_ring_buffer_pop(ami_ctx->parse_buffer))) {
#ifdef DEBUG
				//trace("Thread message:\n");
				//buffer_dump("Threaded packet", found_packet->content, found_packet->len);
#endif
				ami_ctx_parse_buffer(parsed_packet, found_packet);
				if (LIKELY(DEFINED(parsed_packet))) {
				//if(LIKELY((parsed_packet = ami_ctx_parse(found_packet)))) {
#ifdef DEBUG
					//trace("Thread message parsed\n");
#endif
					ami_ctx_ring_buffer_push(ami_ctx->parsed_buffer, (void *)parsed_packet);
					parsed = true;
				}
				ami_ctx_value_destroy(found_packet);
			}

			if (LIKELY(parsed)) ev_async_send(ami_ctx->loop, ami_ctx->async_ev_w);
			pthread_testcancel();
			pthread_cond_wait(ami_ctx->parse_thread_cv, ami_ctx->parse_thread_cv_lock);
			pthread_mutex_unlock(ami_ctx->parse_thread_cv_lock);
		}
		pthread_exit(ami_ctx);
	}

	return NULL;
}

int ami_ctx_setup_events(AMIctx_t * ami_ctx)
{
	if (LIKELY(DEFINED(ami_ctx))) {
		if (LIKELY(ami_ctx->sockfd > 0)) {
			if (LIKELY(ami_ctx->read_ev_io == NULL)) {
				ALLOC_MEM(ami_ctx->read_ev_io, 1, struct ev_io);
				ev_io_init(ami_ctx->read_ev_io, ami_ctx_ev_read_banner_cb, ami_ctx->sockfd, EV_READ);
				ami_ctx->read_ev_io->data = (void *)ami_ctx;
				ev_io_start(ami_ctx->loop, ami_ctx->read_ev_io);

				ALLOC_MEM(ami_ctx->async_ev_w, 1, struct ev_async);
				ev_async_init (ami_ctx->async_ev_w, ami_ctx_ew_async_cb);
				ami_ctx->async_ev_w->data = (void *)ami_ctx;
				ev_async_start (ami_ctx->loop, ami_ctx->async_ev_w);

				pthread_create (ami_ctx->parse_thread_id, NULL, ami_ctx_thread, (void *)ami_ctx);
				pthread_detach (*ami_ctx->parse_thread_id);
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
			ami_ctx_invoke_connect_error_callback(ami_ctx);

			return ami_ctx->sockfd = -1;
		}

		if (connect(ami_ctx->sockfd, (struct sockaddr *)&(ami_ctx->serv_addr), sizeof(ami_ctx->serv_addr)) < 0) {
#ifdef DEBUG
			trace("ERROR connecting\n");
#endif
			close(ami_ctx->sockfd);

			ami_ctx_invoke_connect_error_callback(ami_ctx);

			return ami_ctx->sockfd = -1;
		}

		flags = O_NONBLOCK;
		if (fcntl(ami_ctx->sockfd, F_SETFL, flags) < 0) {
			close(ami_ctx->sockfd);

			ami_ctx_invoke_connect_error_callback(ami_ctx);

			return ami_ctx->sockfd = -1;
		}

		flags = 1;
		if (setsockopt(ami_ctx->sockfd, SOL_TCP, TCP_NODELAY, &flags, sizeof(int))) {
			close(ami_ctx->sockfd);

			ami_ctx_invoke_connect_error_callback(ami_ctx);

			return ami_ctx->sockfd = -1;
		}

		flags = 1;
		if (setsockopt(ami_ctx->sockfd, SOL_SOCKET, SO_OOBINLINE, &flags, sizeof(int))) {
			close(ami_ctx->sockfd);

			ami_ctx_invoke_connect_error_callback(ami_ctx);

			return ami_ctx->sockfd = -1;
		}

		if (setsockopt(ami_ctx->sockfd, SOL_SOCKET, SO_LINGER, &linger, sizeof(linger))) {
			close(ami_ctx->sockfd);

			ami_ctx_invoke_connect_error_callback(ami_ctx);

			return ami_ctx->sockfd = -1;
		}

		ami_ctx_invoke_connect_callback(ami_ctx);
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

ssize_t ami_ctx_write(AMIctx_t * ami_ctx, const AMIcpbuff_t packet)
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
		(void)ami_ctx_stop_events(ami_ctx);
		(void)ami_ctx_disconnect(ami_ctx);

		pthread_mutex_destroy(ami_ctx->parse_thread_cv_lock);
		pthread_cond_destroy(ami_ctx->parse_thread_cv);

		FREE_AND_UNDEF(ami_ctx->parse_thread_cv_lock);
		FREE_AND_UNDEF(ami_ctx->parse_thread_cv);
		FREE_AND_UNDEF(ami_ctx->parse_thread_id);

		FREE_AND_UNDEF(ami_ctx->buffer);

		ami_ctx_field_destroy(ami_ctx->last_event);

		ami_ctx_ring_buffer_destroy(ami_ctx->parse_buffer);
		ami_ctx_ring_buffer_destroy(ami_ctx->parsed_buffer);

		if (ami_ctx->sockfd > 0) {
			close(ami_ctx->sockfd);
			ami_ctx->sockfd = -1;
		}

		ami_ctx->error = true;
		ami_ctx->error_code = EAMI_DESTROY;

		ami_ctx_destroy_callback(ami_ctx->on_event_callback);
		ami_ctx_destroy_callback(ami_ctx->on_connect_callback);
		ami_ctx_destroy_callback(ami_ctx->on_error_callback);
		ami_ctx_destroy_callback(ami_ctx->on_disconnect_callback);
		ami_ctx_destroy_callback(ami_ctx->on_connect_error_callback);
		ami_ctx_destroy_callback(ami_ctx->on_timeout_callback);

		dTHX;
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

MODULE = Thirdlane::AMI::XS		PACKAGE = AMIctx_tPtr  PREFIX = AMIctx_t_

void
AMIctx_t_DESTROY(ami_ctx)
		AMIctx_t * ami_ctx
	CODE:
#ifdef DEBUG
		trace("AMIctx_tPtr::DESTROY\n");
#endif
		ami_ctx_destroy(ami_ctx);
		ami_ctx = NULL;


MODULE = Thirdlane::AMI::XS		PACKAGE = Thirdlane::AMI::XS
PROTOTYPES: DISABLE

BOOT:
	{
		I_EV_API("Thirdlane::AMI::XS");
		}

AMIctx_t *
ami_connect(IN loop, IN host, IN port, IN on_event_callback)
	struct ev_loop * loop
	const AMIcpbuff_t host
	const AMIcpbuff_t port
	SV * on_event_callback
	INIT:
		AMIctx_t * ami_ctx = ami_ctx_init();
	CODE:
		(void)ami_ctx_loop(ami_ctx, loop);
		(void)ami_ctx_host(ami_ctx, host, port);
		if (ami_ctx_connect(ami_ctx) > -1) {
			(void)ami_ctx_setup_events(ami_ctx);
			ami_ctx_set_event_callback(ami_ctx, on_event_callback);
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
	const AMIcpbuff_t packet
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
	const AMIcpbuff_t packet
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
					(void)hv_store((HV *)rh, start_field, (int)(end_field - start_field), newSVpvn(start_value, (int)(end_value - start_value)), 0);
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
