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

#define PTR_T(A_TYPE) __typeof__(A_TYPE *)

typedef char AMIcbuff_t;
typedef PTR_T(AMIcbuff_t) AMIcpbuff_t;

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

#define UNDEF(A_PTR) A_PTR = NULL

#define ALLOC_MEM_LEN(A_LEN) malloc(A_LEN)
#define ALLOC_MEM(A_PTR, A_LEN, A_TYPE) A_PTR = (A_TYPE *)ALLOC_MEM_LEN(A_LEN * sizeof(A_TYPE))
#define ALLOC_MEM_CAST(A_PTR, A_LEN, A_TYPE, A_CAST) A_PTR = (A_CAST *)ALLOC_MEM_LEN(A_LEN * sizeof(A_TYPE))
#define ALLOC_MEM_ZERO_FILL(A_PTR, A_LEN, A_TYPE) ALLOC_MEM(A_PTR, A_LEN, A_TYPE); memset((A_TYPE *)A_PTR, '\0', A_LEN * sizeof(A_TYPE))

#define ALLOC_MEM_TYPE(A_TYPE) ALLOC_MEM_LEN(sizeof(A_TYPE))
#define ALLOC_MEM_OBJ(A_PTR) ALLOC_MEM_TYPE(__typeof__(A_PTR))
#define ALLOC_OBJ(A_PTR) A_PTR = ALLOC_MEM_OBJ(A_PTR)

#define ALLOC_DECLARE(A_PTR, A_LEN, A_TYPE) A_TYPE * A_PTR = NULL; ALLOC_MEM(A_PTR, A_LEN, A_TYPE)
#define ALLOC_DECLARE_CAST(A_PTR, A_LEN, A_TYPE, A_CAST) A_TYPE * A_PTR = NULL; ALLOC_MEM_CAST(A_PTR, A_LEN, A_TYPE, A_CAST)

#define ALLOC_DECLARE_OBJ(A_PTR, A_TYPE) PTR_T(A_TYPE) A_PTR = ALLOC_MEM_TYPE(A_TYPE)

#define FREE_MEM(A_PTR) free(A_PTR)

#define ALLOC_BUFF(A_PTR, A_LEN) ALLOC_MEM(A_PTR, A_LEN, AMIcbuff_t)
#define ALLOC_DECLARE_BUFF(A_PTR, A_LEN) AMIcpbuff_t A_PTR = NULL; ALLOC_MEM(A_PTR, A_LEN, AMIcbuff_t)

//#define DEFINED(A_PTR) A_PTR != NULL
#define DEFINED(A_PTR) A_PTR

#define FREE_AND_UNDEF_CHECKED(A_PTR) if (LIKELY(DEFINED(A_PTR))) { FREE_MEM(A_PTR); UNDEF(A_PTR); }
#define FREE_AND_UNDEF(A_PTR) do { FREE_MEM(A_PTR); UNDEF(A_PTR); } while(0)

#define max(a, b) ({ __typeof__ (a) _a = (a); __typeof__ (b) _b = (b); _a > _b ? _a : _b; })
#define min(a, b) ({ __typeof__ (a) _a = (a); __typeof__ (b) _b = (b); _a > _b ? _b : _a; })

#define DEBUG_STATS 1000000UL

#ifdef DEBUG_STATS
#include <math.h>
#include <time.h>

#define STATi(A_AMI_CTX, A_METRIC, A_VALUE) (A_AMI_CTX)->stat_ ## A_METRIC += A_VALUE
#define STATz(A_AMI_CTX, A_METRIC) (A_AMI_CTX)->stat_ ## A_METRIC = 0
#define STATS(A_AMI_CTX) \
	if ((A_AMI_CTX)->stat_packets > 0 && ((A_AMI_CTX)->stat_packets % DEBUG_STATS == 0)) { \
		(A_AMI_CTX)->time_end = clock(); \
		(A_AMI_CTX)->time_used = ((double) ((A_AMI_CTX)->time_end - (A_AMI_CTX)->time_start)) / CLOCKS_PER_SEC; \
		(A_AMI_CTX)->time_start = clock(); \
		fprintf(stderr, "%.2f seconds for %lu packets parsed, %lu bytes received, %lu callbacks invoked at %.2f bytes/s, %.2f packets/s, %.2f Mibit/s\n", (A_AMI_CTX)->time_used, (A_AMI_CTX)->stat_packets, (A_AMI_CTX)->stat_bytes, (A_AMI_CTX)->stat_callbacks, (A_AMI_CTX)->stat_bytes/(A_AMI_CTX)->time_used, (A_AMI_CTX)->stat_packets/(A_AMI_CTX)->time_used, ((((A_AMI_CTX)->stat_bytes/(A_AMI_CTX)->time_used) * 8) / pow(2, 20))); \
		STATz(A_AMI_CTX, packets); \
		STATz(A_AMI_CTX, bytes); \
		STATz(A_AMI_CTX, callbacks); \
	}
#else
#define STATi(...)
#define STATz(...)
#define STATS(...)
#endif


#ifdef DEBUG
#include <sys/ioctl.h>
#include <execinfo.h>

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

typedef enum AMIerr_e {
	EAMI_NONE      = 0b00000000,
	EAMI_FATAL     = 0b00000001,
	EAMI_NON_FATAL = 0b00000010,
	EAMI_TIMEOUT   = 0b00000100,
	EAMI_DESTROY   = 0b10000000
} AMIerr_t;

typedef enum AMIstate_e {
	SAMI_NONE          = 0b00000000,
	SAMI_CONNECTING    = 0b00000001,
	SAMI_CONNECTED     = 0b00000010,
	SAMI_DISCONNECTING = 0b00000100,
	SAMI_DISCONNECTED  = 0b00001000,
	SAMI_HANDSHAKE     = 0b00010000,
	SAMI_LOGIN         = 0b00100000,
	SAMI_READY         = 0b01000000,
	SAMI_INVALID       = 0b10000000
} AMIstate_t;

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
	struct ev_loop * loop;
	struct ev_io * read_ev_io;

	AMIcpbuff_t buffer;
	AMIcpbuff_t buffer_cursor;

	AMIfield_t * last_event;

	SV * on_event_callback;
	SV * on_connect_callback;
	SV * on_error_callback;
	SV * on_disconnect_callback;
	SV * on_connect_error_callback;
	SV * on_timeout_callback;

	HV * hv;
	SV * packet;

	size_t buffer_len;

	unsigned int portno;

	struct sockaddr_in serv_addr;
	struct hostent *server;

	int sockfd;

	bool error;
	uint8_t error_code;
	uint8_t state;

#ifdef DEBUG_STATS
	size_t stat_packets;
	size_t stat_bytes;
	size_t stat_callbacks;

	clock_t time_start;
	clock_t time_end;
	double time_used;
#endif
} AMIctx_t;

void ami_ctx_disconnect(AMIctx_t * ami_ctx);

#define ami_ctx_value_declare(value) \
	ALLOC_DECLARE_OBJ(value, AMIvalue_t); \
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
	ami_ctx_value_assign(A_PACKET_BUFFER, (A_AMI_CTX)->buffer, A_LEN)

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
	ALLOC_BUFF(ami_ctx->buffer, BUFFER_SIZE);
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

	memset(&ami_ctx->serv_addr, '0', sizeof(ami_ctx->serv_addr));

	ami_ctx->error = false;
	ami_ctx->error_code = EAMI_NONE;
	ami_ctx->state = SAMI_NONE;

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

void ami_ctx_set_event_callback(AMIctx_t * ami_ctx, SV * callback) { ami_ctx_set_callback(ami_ctx, event, callback); }
void ami_ctx_set_connect_callback(AMIctx_t * ami_ctx, SV * callback) { ami_ctx_set_callback(ami_ctx, connect, callback); }
void ami_ctx_set_error_callback(AMIctx_t * ami_ctx, SV * callback) { ami_ctx_set_callback(ami_ctx, error, callback); }
void ami_ctx_set_disconnect_callback(AMIctx_t * ami_ctx, SV * callback) { ami_ctx_set_callback(ami_ctx, disconnect, callback); }
void ami_ctx_set_connect_error_callback(AMIctx_t * ami_ctx, SV * callback) { ami_ctx_set_callback(ami_ctx, connect_error, callback); }
void ami_ctx_set_timeout_callback(AMIctx_t * ami_ctx, SV * callback) { ami_ctx_set_callback(ami_ctx, timeout, callback); }

#define ami_ctx_invoke_event_callback(A_AMI_CTX) ami_ctx_invoke_callback((A_AMI_CTX), event, (A_AMI_CTX)->packet)
void ami_ctx_invoke_connect_callback(AMIctx_t * ami_ctx) { ami_ctx_invoke_callback(ami_ctx, connect, NULL); }
void ami_ctx_invoke_error_callback(AMIctx_t * ami_ctx) { ami_ctx_invoke_callback(ami_ctx, error, NULL); }
void ami_ctx_invoke_disconnect_callback(AMIctx_t * ami_ctx) { ami_ctx_invoke_callback(ami_ctx, disconnect, NULL); }
void ami_ctx_invoke_connect_error_callback(AMIctx_t * ami_ctx) { ami_ctx_invoke_callback(ami_ctx, connect_error, NULL); }
void ami_ctx_invoke_timeout_callback(AMIctx_t * ami_ctx) { ami_ctx_invoke_callback(ami_ctx, timeout, NULL); }

#define ami_ctx_unset_state(A_AMI_CTX, A_STATE) (A_AMI_CTX)->state &= ~A_STATE;
#define ami_ctx_set_state(A_AMI_CTX, A_STATE) (A_AMI_CTX)->state |= A_STATE;

void ami_ctx_unset_error(AMIctx_t * ami_ctx, const uint8_t code)
{
	ami_ctx->error_code &= ~code;
	if((ami_ctx->error = (bool)(ami_ctx->error_code != EAMI_NONE))) {
		ami_ctx_set_state(ami_ctx, SAMI_INVALID);
	} else {
		ami_ctx_unset_state(ami_ctx, SAMI_INVALID);
	}
}

void ami_ctx_set_error(AMIctx_t * ami_ctx, const uint8_t code, const char * message)
{
	ami_ctx->error_code |= code;
	if((ami_ctx->error = (bool)(ami_ctx->error_code != EAMI_NONE))) {
		ami_ctx_set_state(ami_ctx, SAMI_INVALID);
		fprintf(stderr, "Error: %s(%d) ", message, code);
		if (ami_ctx->error_code & EAMI_FATAL) {
			ami_ctx_unset_error(ami_ctx, EAMI_NON_FATAL);
			fprintf(stderr, "FATAL ");
		}
		if (ami_ctx->error_code & EAMI_NON_FATAL) {
			fprintf(stderr, "NOT FATAL ");
		}
		if (ami_ctx->error_code & EAMI_DESTROY) {
			fprintf(stderr, "DESTROY PHASE ");
		}
		fprintf(stderr, "\n");
		ami_ctx_disconnect(ami_ctx);
		ami_ctx_invoke_error_callback(ami_ctx);
	} else {
		ami_ctx_unset_state(ami_ctx, SAMI_INVALID);
	}
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

#define ami_ctx_parse_buffer(A_PARSED_PACKET, A_PACKET_BUFFER, A_LEN) \
	register AMIcpbuff_t packet = A_PACKET_BUFFER; \
	register AMIcpbuff_t cursor = packet; \
	register AMIcpbuff_t tail = A_PACKET_BUFFER + A_LEN; \
	register AMIcpbuff_t f1; \
	register AMIcpbuff_t f2; \
	register AMIcpbuff_t v1; \
	register AMIcpbuff_t v2; \
	register AMIcpbuff_t yyt1; \
	register AMIcpbuff_t yyt2; \
	register AMIcpbuff_t yyt3; \
	register char yych; \
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
				(void)hv_store(A_PARSED_PACKET, f1, (int)(f2 - f1), newSVpvn(v1, (int)(v2 - v1)), 0); \
				continue; \
			} \
	}

#define ami_ctx_scan_chars(A_AMI_CTX, A_POS, A_VALUE, A_LEN) \
	register AMIcpbuff_t cursor = memmem((A_AMI_CTX)->buffer, (A_AMI_CTX)->buffer_len, A_VALUE, A_LEN); \
	A_POS = LIKELY(DEFINED(cursor)) ? (cursor - (A_AMI_CTX)->buffer + 1) : -1

#define ami_ctx_scan_nchars(A_AMI_CTX, A_POS, A_BUFFER_LEN, A_VALUE, A_LEN) \
	register AMIcpbuff_t cursor = memmem((A_AMI_CTX)->buffer, A_BUFFER_LEN, A_VALUE, A_LEN); \
	A_POS = LIKELY(DEFINED(cursor)) ? (cursor - (A_AMI_CTX)->buffer + 1) : -1

#define ami_ctx_scan_packet_end(A_AMI_CTX, A_POS) \
	register int64_t i = 0; \
	ami_ctx_scan_chars(A_AMI_CTX, i, ast_pkt_separator_end, ast_pkt_separator_end_size); \
	A_POS = LIKELY(i != -1) ? (i+ast_pkt_separator_end_size-1) : -1

int64_t ami_ctx_scan_banner_end(const AMIctx_t * ami_ctx )
{
	register int64_t i = 0;
	register int64_t i2 = 0;
	ami_ctx_scan_chars( ami_ctx, i, ast_pkt_separator_field_end, ast_pkt_separator_field_end_size);
	if (LIKELY(i != -1)) {
		ami_ctx_scan_nchars( ami_ctx, i2, i-1, ast_pkt_banner, ast_pkt_banner_size);
		if (LIKELY(i2 != -1)) {
			return i+ast_pkt_separator_field_end_size;
		}
	}
	return -1;
}

#define ami_ctx_scan_head(A_AMI_CTX) \
	register int64_t i = 0; \
	register int64_t i2 = 0; \
	ami_ctx_scan_chars( (A_AMI_CTX), i, ast_pkt_separator_field_end, ast_pkt_separator_field_end_size); \
	if (LIKELY(i != -1)) { \
		buffer_dump("Packet head detected", (A_AMI_CTX)->buffer, i-1); \
		ami_ctx_scan_nchars( (A_AMI_CTX), i2, i-1, ast_pkt_separator_field_value, ast_pkt_separator_field_value_size); \
		if (LIKELY(i2 != -1)) { \
			STATi(A_AMI_CTX, packets, 1); \
			ami_ctx_field_assign((A_AMI_CTX)->last_event, (A_AMI_CTX)->buffer, i2 - 1, (A_AMI_CTX)->buffer + i2 + 1, i - i2 - 2); \
			buffer_dump("Packet type detected", (A_AMI_CTX)->last_event->name->content, (A_AMI_CTX)->last_event->name->len); \
			buffer_dump("Packet value detected", (A_AMI_CTX)->last_event->value->content, (A_AMI_CTX)->last_event->value->len); \
		} \
	} \

bool ami_ctx_scan_filter(AMIctx_t * ami_ctx )
{
		ami_ctx_scan_head(ami_ctx);
//		return true;
		if (LIKELY(!memcmp(ami_ctx->last_event->name->content, ast_pkt_head_event, min(ast_pkt_head_event_size, ami_ctx->last_event->name->len)))) {
			buffer_dump("Packet type passed filter", ami_ctx->last_event->name->content, ami_ctx->last_event->name->len);
			if (LIKELY(!memcmp(ami_ctx->last_event->value->content, ast_pkt_head_event_well_known, min(ast_pkt_head_event_well_known_size, ami_ctx->last_event->value->len)))) {
				buffer_dump("Packet value passed filter", ami_ctx->last_event->value->content, ami_ctx->last_event->value->len);
				return true;
			}
		} else {
			return true;
		}
	return false;
}

void ami_ctx_disable_events(AMIctx_t * ami_ctx)
{
	if (LIKELY(DEFINED(ami_ctx->read_ev_io))) {
		trace("Disable events ctx: %p, read_ev_io: %p\n", ami_ctx, ami_ctx->read_ev_io);
		if (ev_is_pending(ami_ctx->read_ev_io)) {
			trace("Clear pending events\n");
			ev_clear_pending(ami_ctx->loop, ami_ctx->read_ev_io);
		}
		if (LIKELY(ev_is_active(ami_ctx->read_ev_io))) {
			trace("Stop event listener\n");
			ev_io_stop(ami_ctx->loop, ami_ctx->read_ev_io);
		}
		trace("Disable events done\n");
	}
}

void ami_ctx_unset_events(AMIctx_t * ami_ctx)
{
	if (LIKELY(DEFINED(ami_ctx->read_ev_io))) {
		trace("Unset events ctx: %p, read_ev_io: %p\n", ami_ctx, ami_ctx->read_ev_io);
		ami_ctx_disable_events(ami_ctx);
		UNDEF(ami_ctx->read_ev_io->data);
		FREE_AND_UNDEF(ami_ctx->read_ev_io);
		trace("Unset events done\n");
	}
}

void ami_ctx_disconnect(AMIctx_t * ami_ctx)
{
	ami_ctx_disable_events(ami_ctx);

	if (ami_ctx->sockfd != -1) {
		trace("Shutdown socket fd:%i\n", ami_ctx->sockfd);
		fcntl(ami_ctx->sockfd, F_SETFL, 0);
		if (shutdown(ami_ctx->sockfd, SHUT_RDWR) == -1) {
			trace("SHUT_RDWR error fd:%i\n", ami_ctx->sockfd);
		}
		if (close(ami_ctx->sockfd) == -1) {
			trace("Close error fd:%i\n", ami_ctx->sockfd);
		}
		ami_ctx->sockfd = -1;
		ami_ctx_invoke_disconnect_callback(ami_ctx);
	}
}

#define ami_ctx_enqueue_packet_len(A_AMI_CTX, A_LEN) \
	hv_clear((A_AMI_CTX)->hv); \
	ami_ctx_parse_buffer((A_AMI_CTX)->hv, (A_AMI_CTX)->buffer, A_LEN); \
	ami_ctx_invoke_event_callback(A_AMI_CTX)

#define ami_ctx_forward_buffer_cursor(A_AMI_CTX, A_LEN) \
	(A_AMI_CTX)->buffer_len += A_LEN; \
	(A_AMI_CTX)->buffer_cursor += A_LEN;

//(A_AMI_CTX)->buffer_cursor = (A_AMI_CTX)->buffer + (A_AMI_CTX)->buffer_len;
//	trace("AMI buffer after forward len: %lu\n", (A_AMI_CTX)->buffer_len)

#define ami_ctx_rewind_buffer_cursor(A_AMI_CTX, A_LEN) \
	memmove((A_AMI_CTX)->buffer, (A_AMI_CTX)->buffer + A_LEN, (A_AMI_CTX)->buffer_len - A_LEN); \
	(A_AMI_CTX)->buffer_len -= A_LEN; \
	(A_AMI_CTX)->buffer_cursor -= A_LEN;

	//(A_AMI_CTX)->buffer_cursor = (A_AMI_CTX)->buffer + (A_AMI_CTX)->buffer_len;
	//trace("AMI buffer after rewind len: %lu\n", (A_AMI_CTX)->buffer_len)

#define ami_ctx_reset_buffer_cursor(A_AMI_CTX) \
	(A_AMI_CTX)->buffer_len = 0; \
	(A_AMI_CTX)->buffer_cursor = (A_AMI_CTX)->buffer; \
	trace("AMI buffer reset\n")

#define ami_ctx_feed_buffer(A_AMI_CTX) \
	int64_t found = 0; \
	dTHX; \
	for(;;) { \
		ami_ctx_scan_packet_end(A_AMI_CTX, found); \
		if (found != -1) { \
			STATS(A_AMI_CTX); \
			buffer_dump("Detected AMI packet", (A_AMI_CTX)->buffer, found); \
			if (UNLIKELY(ami_ctx_scan_filter(A_AMI_CTX))) { \
				buffer_dump("AMI packet passed filter", (A_AMI_CTX)->buffer, found); \
				ami_ctx_enqueue_packet_len(A_AMI_CTX, found); \
			} \
			if (UNLIKELY((A_AMI_CTX)->buffer_len == found)) { \
				ami_ctx_reset_buffer_cursor(A_AMI_CTX); \
			} else { \
				ami_ctx_rewind_buffer_cursor(A_AMI_CTX, found); \
			} \
		} else break; \
	}

static void ami_ctx_ev_read_cb (struct ev_loop *loop, ev_io *w, int revents)
{
	AMIctx_t * ami_ctx = (AMIctx_t *)w->data;

	if (UNLIKELY((BUFFER_SIZE - ami_ctx->buffer_len) <= 0)) {
		trace("AMI buffer full\n");
		ami_ctx_reset_buffer_cursor(ami_ctx);
	}

	if (UNLIKELY(revents & EV_ERROR && !(revents & EV_READ))) {
		ami_ctx_set_error(ami_ctx, EAMI_FATAL, "AMI socket read error");
		return;
	}

	ssize_t read_len = 0;

l_read:
	read_len = read(ami_ctx->sockfd, ami_ctx->buffer_cursor, BUFFER_SIZE - ami_ctx->buffer_len);

	if (UNLIKELY(read_len <= 0)) {
		if (LIKELY(read_len == 0)) {
			trace("EOF detected in fd: %d\n", ami_ctx->sockfd);
			ami_ctx_set_error(ami_ctx, EAMI_NON_FATAL, "AMI socket read EOF");
			return;
		} else if (UNLIKELY(errno == EAGAIN || errno == EINTR)) {
			trace("EAGAIN detected in fd: %d, status: %d \n", ami_ctx->sockfd, errno);
			goto l_read;
		}
	} else {
		STATi(ami_ctx, bytes, read_len);
		trace("Read AMI data fd:%i, len: %li\n", ami_ctx->sockfd, read_len);
		ami_ctx_forward_buffer_cursor(ami_ctx, read_len);
		ami_ctx_feed_buffer(ami_ctx);
	}
}

static void ami_ctx_ev_read_banner_cb (struct ev_loop *loop, ev_io *w, int revents)
{
	AMIctx_t * ami_ctx = (AMIctx_t *)w->data;

	if (UNLIKELY((BUFFER_SIZE - ami_ctx->buffer_len) <= 0)) {
		trace("AMI buffer full\n");
		ami_ctx_reset_buffer_cursor(ami_ctx);
	}

	if (UNLIKELY(revents & EV_ERROR && !(revents & EV_READ))) {
		trace("EV banner error on read, fd=%d revents=0x%08x\n", ami_ctx->sockfd, revents);
		ami_ctx_set_error(ami_ctx, EAMI_FATAL, "AMI socket read error");
		return;
	}

	ssize_t read_len = 0;

l_read:
	read_len = read(ami_ctx->sockfd, ami_ctx->buffer_cursor, BUFFER_SIZE - ami_ctx->buffer_len);

	if (UNLIKELY(read_len <= 0)) {
		if (LIKELY(read_len == 0)) {
			trace("EOF banner detected in fd: %i\n", ami_ctx->sockfd);
			ami_ctx_set_error(ami_ctx, EAMI_NON_FATAL, "AMI socket read EOF");
			return;
		} else if (UNLIKELY(errno == EAGAIN || errno == EINTR)) {
			trace("EAGAIN banner detected in fd: %d, status: %d \n", ami_ctx->sockfd, errno);
			goto l_read;
		}
	} else {
		STATi(ami_ctx, bytes, read_len);
		ami_ctx_forward_buffer_cursor(ami_ctx, read_len);
		trace("Read AMI banner data fd: %i, len: %li\n", ami_ctx->sockfd, read_len);
		buffer_dump("Read AMI banner data", ami_ctx->buffer, ami_ctx->buffer_len);

		int64_t found = 0;
		if (LIKELY((found = ami_ctx_scan_banner_end(ami_ctx)) > -1)) {
			ami_ctx_unset_state(ami_ctx, SAMI_HANDSHAKE);
			ami_ctx_set_state(ami_ctx, SAMI_READY);
			buffer_dump("Found AMI banner", ami_ctx->buffer, found);
			ami_ctx_reset_buffer_cursor(ami_ctx);
			ev_set_cb (w, ami_ctx_ev_read_cb);
			ami_ctx_invoke_connect_callback(ami_ctx);
		}
	}
}

int ami_ctx_setup_events(AMIctx_t * ami_ctx)
{
	if (LIKELY(DEFINED(ami_ctx))) {
		if (LIKELY(ami_ctx->sockfd > 0)) {
			if (LIKELY(ami_ctx->read_ev_io == NULL)) {
				ami_ctx_set_state(ami_ctx, SAMI_HANDSHAKE);
				ALLOC_MEM(ami_ctx->read_ev_io, 1, struct ev_io);
				ev_io_init(ami_ctx->read_ev_io, ami_ctx_ev_read_banner_cb, ami_ctx->sockfd, EV_READ);
				ami_ctx->read_ev_io->data = (void *)ami_ctx;
				ev_io_start(ami_ctx->loop, ami_ctx->read_ev_io);
			}
		} else {
			return -1;
		}
	}
	return 0;
}

bool ami_ctx_connect(AMIctx_t * ami_ctx)
{
	if (LIKELY(DEFINED(ami_ctx))) {
		ami_ctx_unset_state(ami_ctx, SAMI_CONNECTED);
		ami_ctx_set_state(ami_ctx, SAMI_CONNECTING);
		static int opt_nonblock_flag = O_NONBLOCK;
		static int opt_enable_flag = 1;
		static struct linger opt_linger = { .l_onoff = 0, .l_linger = 0 };

		ami_ctx->sockfd = socket(AF_INET, SOCK_STREAM, 0);

		if (ami_ctx->sockfd < 0) {
			ami_ctx_set_error(ami_ctx, EAMI_FATAL, "Opening socket");
		} else if (connect(ami_ctx->sockfd, (struct sockaddr *)&(ami_ctx->serv_addr), sizeof(ami_ctx->serv_addr)) < 0) {
			ami_ctx_set_error(ami_ctx, EAMI_FATAL, "Setup connection");
		} else if (fcntl(ami_ctx->sockfd, F_SETFL, opt_nonblock_flag) < 0) {
			ami_ctx_set_error(ami_ctx, EAMI_FATAL, "Setting O_NONBLOCK option");
		} else if (setsockopt(ami_ctx->sockfd, SOL_TCP, TCP_NODELAY, &opt_enable_flag, sizeof(int))) {
			ami_ctx_set_error(ami_ctx, EAMI_FATAL, "Setting TCP_NODELAY option");
		} else if (setsockopt(ami_ctx->sockfd, SOL_SOCKET, SO_OOBINLINE, &opt_enable_flag, sizeof(int))) {
			ami_ctx_set_error(ami_ctx, EAMI_FATAL, "Setting SO_OOBINLINE option");
		} else if (setsockopt(ami_ctx->sockfd, SOL_SOCKET, SO_LINGER, &opt_linger, sizeof(opt_linger))) {
			ami_ctx_set_error(ami_ctx, EAMI_FATAL, "Setting SO_LINGER option");
		} else {
			ami_ctx_unset_state(ami_ctx, SAMI_CONNECTING);
			ami_ctx_set_state(ami_ctx, SAMI_CONNECTED);
			return true;
		}

		ami_ctx_unset_state(ami_ctx, SAMI_CONNECTING);

		if (ami_ctx->sockfd > 0) {
			close(ami_ctx->sockfd);
			ami_ctx->sockfd = -1;
		}
		ami_ctx_invoke_connect_error_callback(ami_ctx);
	}

	return false;
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
		ami_ctx_unset_events(ami_ctx);
		ami_ctx_disconnect(ami_ctx);

		FREE_AND_UNDEF(ami_ctx->buffer);

		ami_ctx_field_destroy(ami_ctx->last_event);

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
		UNDEF(ami_ctx->hv);
		sv_unref(ami_ctx->packet);
		UNDEF(ami_ctx->packet);

		FREE_AND_UNDEF(ami_ctx);
	}
	trace("ami_ctx_destroy done\n");
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
ami_init(IN loop)
	struct ev_loop * loop
	INIT:
		AMIctx_t * ami_ctx = ami_ctx_init();
	CODE:
		(void)ami_ctx_loop(ami_ctx, loop);
		RETVAL = ami_ctx;
	OUTPUT:
		RETVAL

void
ami_connect(IN ami_ctx, IN host, IN port)
	AMIctx_t * ami_ctx
	const AMIcpbuff_t host
	const AMIcpbuff_t port
	CODE:
		(void)ami_ctx_host(ami_ctx, host, port);
		if (ami_ctx_connect(ami_ctx)) {
			ami_ctx_setup_events(ami_ctx);
		}

void
ami_on_event(IN ami_ctx, IN callback)
	AMIctx_t * ami_ctx
	SV * callback
	CODE:
		ami_ctx_set_event_callback(ami_ctx, callback);

void
ami_on_connect(IN ami_ctx, IN callback)
	AMIctx_t * ami_ctx
	SV * callback
	CODE:
		ami_ctx_set_connect_callback(ami_ctx, callback);

void
ami_on_error(IN ami_ctx, IN callback)
	AMIctx_t * ami_ctx
	SV * callback
	CODE:
		ami_ctx_set_error_callback(ami_ctx, callback);

void
ami_on_disconnect(IN ami_ctx, IN callback)
	AMIctx_t * ami_ctx
	SV * callback
	CODE:
		ami_ctx_set_disconnect_callback(ami_ctx, callback);

void
ami_on_connect_error(IN ami_ctx, IN callback)
	AMIctx_t * ami_ctx
	SV * callback
	CODE:
		ami_ctx_set_connect_error_callback(ami_ctx, callback);

void
ami_on_timeout(IN ami_ctx, IN callback)
	AMIctx_t * ami_ctx
	SV * callback
	CODE:
		ami_ctx_set_timeout_callback(ami_ctx, callback);

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
