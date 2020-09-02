#define PERL_NO_GET_CONTEXT

#define ALLOC_PAGE_SIZE sysconf(_SC_PAGESIZE)
#define BUFFER_PAGES 1024
#define BUFFER_SIZE ALLOC_PAGE_SIZE * BUFFER_PAGES

#define EV_MULTIPLICITY 1

#define CONSTANT(A_VAR, A_VAL) static const char * const A_VAR = A_VAL; static const unsigned int A_VAR ## _size = sizeof(A_VAL) - 1

#define AST_PKT_SEPARATOR_CR "\r"
#define AST_PKT_SEPARATOR_NL "\n"
#define AST_PKT_SEPARATOR_FIELD AST_PKT_SEPARATOR_CR AST_PKT_SEPARATOR_NL
#define AST_PKT_SEPARATOR_END AST_PKT_SEPARATOR_FIELD AST_PKT_SEPARATOR_FIELD
#define AST_PKT_SEPARATOR_FIELD_MULTI_LINE_END AST_PKT_SEPARATOR_NL "--END COMMAND--" AST_PKT_SEPARATOR_END
#define AST_PKT_SEPARATOR_FIELD_END AST_PKT_SEPARATOR_CR

#define AST_PKT_BANNER "Asterisk" //"Asterisk Call Manager/\d+.\d+.\d+\r\n"

CONSTANT(ast_pkt_separator_cr, AST_PKT_SEPARATOR_CR);
CONSTANT(ast_pkt_separator_nl, AST_PKT_SEPARATOR_NL);

CONSTANT(ast_pkt_separator_field, AST_PKT_SEPARATOR_FIELD);
CONSTANT(ast_pkt_separator_end, AST_PKT_SEPARATOR_END);
CONSTANT(ast_pkt_separator_field_multi_line_end, AST_PKT_SEPARATOR_FIELD_MULTI_LINE_END);
CONSTANT(ast_pkt_separator_field_end, AST_PKT_SEPARATOR_FIELD_END);

CONSTANT(ast_pkt_banner, AST_PKT_BANNER);

#define ATOMIC_MEMORDER __ATOMIC_SEQ_CST
#define ATOMIC_COMPARE_EXCHANGE(ptr, expected, desired) __atomic_compare_exchange_n(ptr, expected, desired, 0, ATOMIC_MEMORDER, ATOMIC_MEMORDER)
#define ATOMIC_LOAD(ptr) __atomic_load_n(ptr, ATOMIC_MEMORDER)

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
		if (write_ptr - read_ptr >= ring_buffer->len) {
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
		if (read_ptr >= write_ptr) {
			return NULL;
		}
		real_ptr = read_ptr % ring_buffer->len;
		value = ring_buffer->ring[real_ptr];
		if (!value) {
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
	free((AMIbuff_t *)ring_buffer);
}

AMIctx_t * ami_ctx_init()
{
  AMIctx_t * ami_ctx = (AMIctx_t *) malloc(sizeof(AMIctx_t));

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

  ami_ctx->server = NULL;

  ami_ctx->event_callback = NULL;
  ami_ctx->read_ev_io = NULL;
  ami_ctx->async_ev_w = NULL;

  memset(&ami_ctx->serv_addr, '0', sizeof(ami_ctx->serv_addr));

  ami_ctx->error = false;
  ami_ctx->error_code = EAMI_NONE;

  dTHX;

  ami_ctx->hv = newHV();
  ami_ctx->packet = newRV_noinc((SV *)ami_ctx->hv);
//    PUSHs(sv_2mortal(newRV_noinc((SV *)packet)));

  ami_ctx->tid = (pthread_t *)malloc(sizeof(pthread_t));

  ami_ctx->lock = (pthread_mutex_t *)malloc(sizeof(pthread_mutex_t));
  pthread_mutex_init(ami_ctx->lock, NULL);

  ami_ctx->invoke_cv = (pthread_cond_t *)malloc(sizeof(pthread_cond_t));
  pthread_cond_init(ami_ctx->invoke_cv, NULL);

  ami_ctx->parse_buffer = ami_ctx_ring_buffer_init(BUFFER_PAGES);

  return ami_ctx;
}

void ami_ctx_set_error(AMIctx_t * ami_ctx, const AMIerr_t code, const char *message)
{
  trace("! AMI error: %s, code: %d\n", message, (uint8_t)code);

  if (ami_ctx) {
	ami_ctx->error = true;
	ami_ctx->error_code = code;
  }
}

bool ami_ctx_is_error(AMIctx_t * ami_ctx)
{
  if (ami_ctx) {
	return ami_ctx->error;
  }
  return true;
}


int ami_ctx_host(AMIctx_t * ami_ctx, const char * host, const char * port)
{
  if (ami_ctx) {
	ami_ctx->serv_addr.sin_family = AF_INET;

	ami_ctx->portno = atoi(port);
	ami_ctx->serv_addr.sin_port = htons(ami_ctx->portno);

	ami_ctx->server = gethostbyname(host);

	if (ami_ctx->server == NULL) {
		trace("ERROR, no such host\n");
		return -1;
	}

	bcopy((char *)ami_ctx->server->h_addr, (char *)&(ami_ctx->serv_addr.sin_addr.s_addr), ami_ctx->server->h_length);
  }
  return 0;
}

//HV * ami_ctx_parse(AMIctx_t * ami_ctx)
bool ami_ctx_parse(AMIctx_t * ami_ctx)
{
  if (ami_ctx) {
		dTHX;
		//HV * rh = newHV();
		hv_clear(ami_ctx->hv);
		const char *packet = ami_ctx->buffer_head;
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
		while (cursor != ami_ctx->buffer_cursor + 1) {
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
			  (void)hv_store(ami_ctx->hv, f1, (int)(f2 - f1), newSVpvn(v1, (int)(v2 - v1)), 0);
			  continue;
			}
		}
//	return newRV_noinc((SV *)rh);
	return true;
	}

	return false;
}

SV * ami_ctx_parse_thr(const char *packet)
{
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
		while (1) {
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
			//  (void)hv_store(rh, f1, (int)(f2 - f1), newSVpvn(v1, (int)(v2 - v1)), 0);
			  continue;
			}
		}
	return NULL;
}

uint64_t ami_ctx_scan_char( AMIctx_t * ami_ctx, const char * value )
{
  if (ami_ctx) {
  trace ("Scan char\n");
	register char *cursor = (char *)memchr(ami_ctx->buffer_head, *value, ami_ctx->buffer_len);
	trace ("Scan char end\n");
	if (cursor) {
		trace ("Char found at position %d.\n", cursor-ami_ctx->buffer_head+1);
		return cursor - ami_ctx->buffer_head + 1;
	}
  }
	return 0;
}

int64_t ami_ctx_scan_chars( AMIctx_t * ami_ctx, const char * value, size_t len )
{
  if (ami_ctx) {
	register char *cursor = (char *)memmem(ami_ctx->buffer_head, ami_ctx->buffer_len, value, len);
	if (cursor) {
		trace ("Chars found at position %d.\n", cursor-ami_ctx->buffer_head);
		return cursor - ami_ctx->buffer_head + 1;
	}
  }
	return -1;
}

int64_t ami_ctx_scan_nchars( AMIctx_t * ami_ctx, size_t buffer_len, const char * value, size_t len )
{
  if (ami_ctx) {
	register char *cursor = (char *)memmem(ami_ctx->buffer_head, buffer_len, value, len);
	if (cursor) {
		trace ("Chars found at position %d.\n", cursor-ami_ctx->buffer_head);
		return cursor - ami_ctx->buffer_head + 1;
	}
  }
	return -1;
}

uint64_t ami_ctx_scan_packet_end( AMIctx_t * ami_ctx )
{
  if (ami_ctx) {
	register int64_t i = 0;
	if ((i = ami_ctx_scan_chars( ami_ctx, ast_pkt_separator_end, ast_pkt_separator_end_size)) > -1) {
		trace ("Packet search end: %d\n", i-1);
			char *banner = strndup(ami_ctx->buffer_head, i-1);
			trace_buff (banner, i-1);
			free(banner);
			return i+3;
	}
  }
  return 0;
}

uint64_t ami_ctx_scan_banner_end( AMIctx_t * ami_ctx )
{
  if (ami_ctx) {
	register int64_t i = 0;

	if ((i = ami_ctx_scan_chars( ami_ctx, ast_pkt_separator_field_end, ast_pkt_separator_field_end_size)) > -1) {
		trace ("Banner search end: %d\n", i-1);
		if (ami_ctx_scan_nchars( ami_ctx, i-1, ast_pkt_banner, ast_pkt_banner_size) > -1) {
			char *banner = strndup(ami_ctx->buffer_head, i-1);
			trace ("Banner search len: %d\n", i-1);
			trace_buff (banner, i-1);

			trace ("Banner found at position %d\n", i-1);
			free(banner);
			return i+1;
		}
	}
  }
  return 0;
}

//void ami_ctx_invoke_event_callback(AMIctx_t * ami_ctx, HV * packet)
void ami_ctx_invoke_event_callback(AMIctx_t * ami_ctx)
{
  if (ami_ctx != NULL) {

	int index = 42;

	dTHX;
	dSP;

	if (ami_ctx->event_callback != NULL) {

//    trace("event callback cb=%p\n", ami_ctx->event_callback);

	ENTER;
	SAVETMPS;

	PUSHMARK(SP);

	PUSHs(ami_ctx->packet);

//    PUSHs(sv_2mortal(newRV_noinc((SV *)packet)));
	PUSHs(ami_ctx->packet);

	PUTBACK;

	call_sv(ami_ctx->event_callback, G_DISCARD | G_EVAL|G_VOID);

	SPAGAIN;

//    trace("event callback err: %d\n", SvTRUE(ERRSV) ? 1 : 0);

	PUTBACK;

	FREETMPS;
	LEAVE;
	}
  }
}

void ami_ctx_feed(AMIctx_t * ami_ctx)
{
  if (ami_ctx) {

	if (ami_ctx_parse(ami_ctx)) {
	ami_ctx_invoke_event_callback(ami_ctx);
	}
  }
}

void ami_ctx_set_event_callback(AMIctx_t * ami_ctx, SV * event_callback)
{
  if (ami_ctx) {
	if (event_callback != NULL) {
	dTHX;
	if ((SvROK(event_callback) && SvTYPE(SvRV(event_callback)) == SVt_PVCV)) {
		if (ami_ctx->event_callback) {
			SvREFCNT_dec(ami_ctx->event_callback);
		}
		ami_ctx->event_callback = newSVsv(event_callback);
	}
	}
  }
}

int ami_ctx_stop_events(AMIctx_t * ami_ctx)
{
  if (ami_ctx) {
	trace("ami_ctx_stop_events begin ctx: %p\n", ami_ctx);
	trace("ami_ctx_stop_events destroy read_ev_io: %p\n", ami_ctx->read_ev_io);
	if (ami_ctx->read_ev_io) {
		trace("ami_ctx_stop_events destroy defined read_ev_io: %p\n", ami_ctx->read_ev_io);
		ami_ctx->read_ev_io->data = NULL;

		if (ev_is_pending(ami_ctx->read_ev_io)) {
			ev_clear_pending(ami_ctx->loop, ami_ctx->read_ev_io);
		}

		if (ev_is_active(ami_ctx->read_ev_io)) {
			trace("ami_ctx_stop_events stop read_ev_io\n");
			ev_io_stop(ami_ctx->loop, ami_ctx->read_ev_io);
		}
		trace("ami_ctx_stop_events free read_ev_io\n");
		free(ami_ctx->read_ev_io);
		ami_ctx->read_ev_io = NULL;
	}
	if(ami_ctx->async_ev_w) {
		if (ev_async_pending(ami_ctx->async_ev_w)) {
		ev_clear_pending(ami_ctx->loop, ami_ctx->async_ev_w);
		}
		if (ev_is_active(ami_ctx->async_ev_w)) {
		ev_async_stop(ami_ctx->loop, ami_ctx->async_ev_w);
		}
		free(ami_ctx->async_ev_w);
		ami_ctx->async_ev_w = NULL;
	}
  }
  trace("ami_ctx_stop_events end\n");
  return 0;
}


int ami_ctx_disconnect(AMIctx_t * ami_ctx)
{
  if (ami_ctx != NULL) {
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

static void ami_ctx_ew_async_cb (struct ev_loop *loop, ev_async *w, int revents)
{
	trace("EV async_cb call\n");
}

static void ami_ctx_notify_parser_thread (AMIctx_t * ami_ctx)
{
	if (ami_ctx) {
		pthread_mutex_lock(ami_ctx->lock);
		pthread_cond_signal(ami_ctx->invoke_cv);
		pthread_mutex_unlock(ami_ctx->lock);
	}
}

static void ami_ctx_ev_read_cb (struct ev_loop *loop, ev_io *w, int revents)
{
	AMIctx_t * ami_ctx = (AMIctx_t *)w->data;

	if (ami_ctx) {
		if (revents & EV_ERROR && !(revents & EV_READ)) {
			trace("EV error on read, fd=%d revents=0x%08x\n", ami_ctx->sockfd, revents);
			(void)ami_ctx_stop_events(ami_ctx);
			(void)ami_ctx_disconnect(ami_ctx);
			return;
		}

		ssize_t read_len = 0;

		l_read:
		read_len = read(ami_ctx->sockfd, ami_ctx->buffer_cursor, ami_ctx->buffer_free);

		if (read_len <= 0) {
			if (read_len == 0) {
				trace("EOF detected in fd: %d\n", ami_ctx->sockfd);
				(void)ami_ctx_stop_events(ami_ctx);
				(void)ami_ctx_disconnect(ami_ctx);
				return;
			}
			if (errno == EAGAIN || errno == EINTR) {
				trace("EAGAIN detected in fd: %d, status: %d \n", ami_ctx->sockfd, errno);
				goto l_read;
			}
		}
		else if (read_len > 0) {
			trace("Read AMI data fd %d, len: %d\n", ami_ctx->sockfd, read_len);
			ami_ctx->buffer_len += read_len;
			ami_ctx->buffer_cursor = ami_ctx->buffer_head + ami_ctx->buffer_len;
			ami_ctx->buffer_pos = (int)(ami_ctx->buffer_cursor - ami_ctx->buffer_head);
			ami_ctx->buffer_free = BUFFER_SIZE - ami_ctx->buffer_pos;
	//	    trace("new AMI buffer len: %d\n", ami_ctx->buffer_len);
			uint64_t found = 0;
			while((found = ami_ctx_scan_packet_end(ami_ctx))) {
		//		trace("found AMI packet end at: %d\n", found);
				char *found_packet = (char *)malloc(found + 1);
				found_packet[found] = '\0';
				memmove(found_packet, ami_ctx->buffer_head, found);
				trace("Found AMI packet:\n");
				trace_buff(found_packet, found);
				ami_ctx_ring_buffer_push(ami_ctx->parse_buffer, (void *)found_packet);
				ami_ctx_notify_parser_thread(ami_ctx);
				if (ami_ctx->buffer_len > found) { // residual data
		//			trace("residual AMI buffer len: %d\n", ami_ctx->buffer_len);
					memmove(ami_ctx->buffer_head, ami_ctx->buffer_head + found, ami_ctx->buffer_len - found);
					ami_ctx->buffer_len -= found;
					ami_ctx->buffer_cursor = ami_ctx->buffer_head + ami_ctx->buffer_len;
					ami_ctx->buffer_pos = (int)(ami_ctx->buffer_cursor - ami_ctx->buffer_head);
					ami_ctx->buffer_free = BUFFER_SIZE - ami_ctx->buffer_pos;
				} else {
		//			trace("no residual AMI data. clear buffer\n");
					ami_ctx->buffer_len = 0;
					ami_ctx->buffer_cursor = ami_ctx->buffer_head;
					ami_ctx->buffer_pos = 0;
					ami_ctx->buffer_free = BUFFER_SIZE;
				}
			}
		}
	}
}

static void ami_ctx_ev_read_banner_cb (struct ev_loop *loop, ev_io *w, int revents)
{
	AMIctx_t * ami_ctx = (AMIctx_t *)w->data;

	if (ami_ctx) {
		if (revents & EV_ERROR && !(revents & EV_READ)) {
			trace("EV banner error on read, fd=%d revents=0x%08x\n", ami_ctx->sockfd, revents);
			(void)ami_ctx_stop_events(ami_ctx);
			(void)ami_ctx_disconnect(ami_ctx);
			return;
		}

		ssize_t read_len = 0;

		l_read:
		read_len = read(ami_ctx->sockfd, ami_ctx->buffer_cursor, ami_ctx->buffer_free);

		if (read_len <= 0) {
			if (read_len == 0) {
				trace("EOF banner detected in fd: %d\n", ami_ctx->sockfd);
				(void)ami_ctx_stop_events(ami_ctx);
				(void)ami_ctx_disconnect(ami_ctx);
				return;
			}
			if (errno == EAGAIN || errno == EINTR) {
				trace("EAGAIN banner detected in fd: %d, status: %d \n", ami_ctx->sockfd, errno);
				goto l_read;
			}
		}
		else if (read_len > 0) {
			trace("Read AMI banner data fd %d, len: %d\n", ami_ctx->sockfd, read_len);
			trace("AMI banner data:\n");
			ami_ctx->buffer_len += read_len;
			ami_ctx->buffer_cursor = ami_ctx->buffer_head + ami_ctx->buffer_len;
			ami_ctx->buffer_pos = (int)(ami_ctx->buffer_cursor - ami_ctx->buffer_head);
			ami_ctx->buffer_free = BUFFER_SIZE - ami_ctx->buffer_pos;
			trace("New AMI banner buffer len: %d\n", ami_ctx->buffer_len);
			trace_buff(ami_ctx->buffer_head, ami_ctx->buffer_len);
			uint64_t found = 0;
			if((found = ami_ctx_scan_banner_end(ami_ctx))) {
				trace("Found AMI banner end at: %d\n", found);
				char *found_packet = (char *)malloc(found + 1);
				found_packet[found] = '\0';
				memmove(found_packet, ami_ctx->buffer_head, found);
				trace("Found AMI banner:\n");
				trace_buff(found_packet, found);
				ami_ctx->buffer_len = 0;
				ami_ctx->buffer_cursor = ami_ctx->buffer_head;
				ami_ctx->buffer_pos = 0;
				ami_ctx->buffer_free = BUFFER_SIZE;
				ev_set_cb (w, ami_ctx_ev_read_cb);
			} else {
				trace("Not found AMI banner\n");
			}
		}
	}
}

void * ami_ctx_thread(void * ptr)
{
 AMIctx_t * ami_ctx = (AMIctx_t *)ptr;
 if (ami_ctx) {
	for(;;) {
		pthread_mutex_lock( ami_ctx->lock );

		char * found_packet = (char *)ami_ctx_ring_buffer_pop(ami_ctx->parse_buffer);
		if (found_packet) {
			trace("Thread message:\n", found_packet);
			trace_buff(found_packet, strlen(found_packet));
			SV * packet = ami_ctx_parse_thr(found_packet);
			if (packet) {
				trace("Thread message parsed\n");
			}
			free(found_packet);
		}
		pthread_cond_wait( ami_ctx->invoke_cv, ami_ctx->lock );
		pthread_mutex_unlock( ami_ctx->lock );
	}
	pthread_exit(ami_ctx);
 }
}

int ami_ctx_setup_events(AMIctx_t * ami_ctx)
{
  if (ami_ctx) {
	if (ami_ctx->sockfd > 0) {
		if (ami_ctx->read_ev_io == NULL) {
			ami_ctx->read_ev_io = (struct ev_io *)malloc(sizeof(struct ev_io));
			ev_io_init(ami_ctx->read_ev_io, ami_ctx_ev_read_banner_cb, ami_ctx->sockfd, EV_READ);
			ami_ctx->read_ev_io->data = (void *)ami_ctx;
			ev_io_start(ami_ctx->loop, ami_ctx->read_ev_io);

			ami_ctx->async_ev_w = (struct ev_async *)malloc(sizeof(struct ev_async));
			ev_async_init (ami_ctx->async_ev_w, ami_ctx_ew_async_cb);
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
  if (ami_ctx) {
	int flags;
	struct linger linger = { .l_onoff = 0, .l_linger = 0 };

	ami_ctx->sockfd = socket(AF_INET, SOCK_STREAM, 0);

	if (ami_ctx->sockfd < 0) {
		trace("ERROR opening socket\n");
		return ami_ctx->sockfd = -1;
	}

	if (connect(ami_ctx->sockfd, (struct sockaddr *)&(ami_ctx->serv_addr), sizeof(ami_ctx->serv_addr)) < 0) {
		trace("ERROR connecting\n");
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
  if (ami_ctx) {
	return ami_ctx->sockfd;
  }
  return -1;
}

int ami_ctx_write(AMIctx_t * ami_ctx, const char * packet)
{
  if (ami_ctx) {
	if (ami_ctx->sockfd > 0) {
	int n = 0;
	n = write(ami_ctx->sockfd, packet, strlen(packet));
	return n;
	}
  }
  return 0;
}

struct ev_loop * ami_ctx_loop(AMIctx_t * ami_ctx, struct ev_loop * loop)
{
  if (ami_ctx) {
	if (loop) {
		ami_ctx->loop = loop;
	}

	return ami_ctx->loop;
  }

  return NULL;
}

void ami_ctx_destroy (AMIctx_t * ami_ctx)
{
  if (ami_ctx) {
	trace("ami_ctx_destroy begin\n");

	pthread_cancel(*ami_ctx->tid);

	pthread_mutex_destroy(ami_ctx->lock);
	pthread_cond_destroy(ami_ctx->invoke_cv);

	(void)ami_ctx_stop_events(ami_ctx);
	trace("ami_ctx_stop_event\n");

	(void)ami_ctx_disconnect(ami_ctx);
	trace("ami_ctx_disconnect\n");

	if (ami_ctx->buffer != NULL) {
		trace("ami_ctx_destroy free buffer\n");
	free(ami_ctx->buffer);
	ami_ctx->buffer = NULL;
	}
	if (ami_ctx->sockfd > 0) {
		trace("ami_ctx_destroy close sockfd\n");
	close(ami_ctx->sockfd);
	ami_ctx->sockfd = -1;
	}
	if (ami_ctx->event_callback) {
		trace("ami_ctx_destroy destroy callback\n");
	dTHX;
	SvREFCNT_dec(ami_ctx->event_callback);
		ami_ctx->event_callback = NULL;
		trace("ami_ctx_destroy after destroy callback\n");
	}

	dTHX;

	hv_undef(ami_ctx->hv);
	ami_ctx->hv = NULL;
	sv_unref(ami_ctx->packet);
	ami_ctx->packet = NULL;

	trace("ami_ctx_destroy main free\n");
	ami_ctx->error = true;
	ami_ctx->error_code = EAMI_DESTROY;

	ami_ctx_ring_buffer_destroy(ami_ctx->parse_buffer);

	free(ami_ctx);
	ami_ctx = NULL;
  }
  trace("ami_ctx_destroy done\n");
}

/*!
 * AMI header structure.
 */
typedef struct __attribute__((__packed__)) AMIHeader_ {
  size_t name_size;   /*!< Name field size */
  char *name;         /*!< AMI header name as string. */
  size_t value_size;  /*!< _value field size */
  char *value;        /*!< AMI header value as string. */
  struct AMIHeader_   *next; /*!< Next AMI header pointer. Linked list element. */
} AMIHeader;

/*!
 * AMI packet structure.
 */
typedef struct __attribute__((__packed__)) AMIPacket_ {
  int             size;   /*!< Number of headers. */
  size_t          length; /*!< Total length of all headers as string. */
  AMIHeader       *head;  /*!< Linked list head pointer to AMI header. */
  AMIHeader       *tail;  /*!< Linked list tail pointer to AMI header. */
} AMIPacket;


AMIPacket *amipack_init() {
  AMIPacket *pack = (AMIPacket*) malloc(sizeof(AMIPacket));
  pack->size = 0;
  pack->length = 0;
  pack->head = NULL;
  pack->tail = NULL;

  return pack;
}

void amiheader_destroy (AMIHeader *hdr) {
  if (hdr) {
	if (hdr->name) free(hdr->name);
	if (hdr->value) free(hdr->value);
	free(hdr);
  }
  hdr = NULL;
}

AMIHeader *amiheader_create(char *name, size_t name_size, char *value, size_t value_size) {
  AMIHeader *header = (AMIHeader *) malloc (sizeof (AMIHeader));

  header->name = name;
  header->name_size = name_size;

  header->value = value;
  header->value_size = value_size;

  return header;
}

void amipack_destroy (AMIPacket *pack)
{
  AMIHeader *hdr, *hnext;

  for ( hdr = pack->head; hdr != NULL; hdr = hnext) {
	hnext = hdr->next;
	amiheader_destroy (hdr);
  }

  if (pack != NULL) {
	free(pack);
	pack = NULL;
  }
}

int amipack_list_append(AMIPacket *pack, AMIHeader *header) {
  pack->length += header->name_size + header->value_size;

  if (pack->size == 0) {
	pack->head = header;
  } else {
	pack->tail->next = header;
  }

  pack->tail = header;
  header->next  = NULL;

  pack->size++;

  return pack->size;
}

int amipack_append( AMIPacket *pack, char *hdr_name, size_t name_size, char *hdr_value, size_t value_size)
{
  AMIHeader *header = amiheader_create(hdr_name, name_size, hdr_value, value_size);
  return amipack_list_append (pack, header);
}

size_t amiheader_find(AMIPacket *pack, char *name, char **val) {
  size_t size = strlen(name);
  if (size == 0) return -1;

  for (AMIHeader *hdr = pack->head; hdr; hdr = hdr->next) {
	if (size == hdr->name_size && strncasecmp(name, hdr->name, hdr->name_size) == 0) {
	  *val = hdr->value;
	  return hdr->value_size;
	}
  }
  return -1;
}

int amipack_scan( char *p, size_t len )
{
	int i = 0, found = 0;
	while(i < len-3 && !found){
	found = (p[i] == '\r' && p[i+1] == '\n' && p[i+2] =='\r' && p[i+3] == '\n');
	i++;
	}
	return found ? i + 3 : 0;
}

int amipack_feed(char *p, size_t plen)
{
	int len;

	while((len = amipack_scan(p, plen)) > 0) {

	if (plen < len) {
		break;
	}

//	char *buf = strndup(p, plen);
//	AMIPacket *ami_pack = amipack_parse(buf, NULL, plen);

//      for (AMIHeader *hdr = ami_pack->head; hdr; hdr = hdr->next) {
//        json_printf(&out, "%Q: %Q", hdr->name, hdr->value);
//        if (hdr != ami_pack->tail) {
//          json_printf(&out, ",");
//        }
//      }
//	if (ami_pack) amipack_destroy(ami_pack);

	return  len;
	}
}

//parsers

AMIPacket *amipack_parser_message(const char *packet)
{
  AMIPacket *pack = amipack_init ();
  const char *cursor = packet;
  const char *f1;
  const char *f2;
  const char *v1;
  const char *v2;
  const char *yyt1;
  const char *yyt2;
  const char *yyt3;

loop:
{
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
			  amipack_destroy (pack);
			  pack = NULL;
			  goto done;
			}
yy4:
	yych = *++cursor;
	if (yych == '\n') goto yy6;
	goto yy3;
yy5:
	yych = *(packet = ++cursor);
	{
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
		goto *yytarget[yych];
	}
yy6:
	++cursor;
	{ goto done; }
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
		if (yych == '\t') {
			yyt2 = cursor;
			goto yy8;
		}
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
		if (yych == '\t') goto yy13;
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
	  int field_len = (int)(f2 - f1);
	  int value_len   = (int)(v2 - v1);
	  amipack_append(pack, strndup(f1, field_len), field_len,
						   strndup(v1, value_len), value_len);
	  goto loop;
	}
}

done:
  return pack;
}

size_t amipack_fields_count(const char * packet) {
	register const char *cursor = packet;
	register size_t count = 0;

	while (*cursor) {
		if (*cursor++ == '\n') count++;
	}
	count && count--;
	return count;
}

MODULE = AMI		PACKAGE = AMIctx_tPtr  PREFIX = AMIctx_t_

void
AMIctx_t_DESTROY(ami_ctx)
		AMIctx_t *ami_ctx
	CODE:
		trace("AMIctx_tPtr::DESTROY\n");
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
	const char * packet
	INIT:
		HV * rh;
	CODE:
		AMIPacket *ami_pack = NULL;
		if ((ami_pack = amipack_parser_message(packet)) == NULL) {
			XSRETURN_UNDEF;
		} else {
	#//	    rh = (HV *)sv_2mortal((SV *)newHV());
			rh = newHV();
			for (AMIHeader *hdr = ami_pack->head; hdr; hdr = hdr->next) {
			(void)hv_store(rh, hdr->name, hdr->name_size, newSVpvn(hdr->value, hdr->value_size), 0);
			}
			amipack_destroy(ami_pack);
		}
		RETVAL = newRV_noinc((SV *)rh);
	#//	RETVAL = newRV_inc((SV *)rh);
	OUTPUT:
		RETVAL

SV *
to_packet_o(IN packet)
	const char * packet
	INIT:
		HV * rh;
	CODE:
		rh = newHV();
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
		while (1) {
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
			  (void)hv_store(rh, f1, (int)(f2 - f1), newSVpvn(v1, (int)(v2 - v1)), 0);
			  continue;
			}
		}
		RETVAL = newRV_noinc((SV *)rh);
	OUTPUT:
		RETVAL

SV *
to_packet_oos(IN packet)
	const char * packet
	INIT:
		HV * rh;
	CODE:
		rh = newHV();
		const char *cursor = packet;
		const char *f1, *f2, *v1, *v2;
		const char *yyt1;
		const char *yyt2;
		const char *yyt3;
		char yych;

		while (1) {
			yych = *cursor;
			if (yych == '\r') {
				goto yy4;
			}
			else if(yych > 0x19 && yych < 0x7e) {
				yyt1 = cursor;
				goto yy5;
			} else {
				goto yy2;
			}

		yy2:
			++cursor;

		yy3:
			{
			break;
			}

		yy4:
			yych = *++cursor;
			if (yych == '\n') {
				goto yy6;
			} else {
				break;
			}

		yy5:
			yych = *(packet = ++cursor);
			if(yych > 0x19 && yych < 0x7e) {
				goto yy12;
			} else {
				break;
			}

		yy6:
			++cursor;
			break;

		yy8:
			yych = *++cursor;
			if(yych == ' ') {
				goto yy8;
			} else if(yych == ':') {
				goto yy13;
			} else {
				goto yy10;
			}

		yy10:
			cursor = packet;
			break;

		yy11:
			yych = *++cursor;

		yy12:
			if(yych == ':') {
				yyt2 = cursor;
				goto yy13;
			}
			else if(yych == ' ') {
				yyt2 = cursor;
				goto yy8;
			}
			else if(yych > 0x19 && yych < 0x7e) {
				goto yy11;
			} else {
				goto yy10;
			}

		yy13:
			yych = *++cursor;
			if (yych == ' ') {
				goto yy13;
			} else if (yych == '\r') {
				yyt3 = cursor;
				goto yy17;
			} else {
				yyt3 = cursor;
				goto yy15;
			}
		yy15:
			yych = *++cursor;
			if (yych == '\r') {
				goto yy17;
			} else {
				goto yy15;
			}
		yy17:
			yych = *++cursor;
			if (yych == '\n') {
				goto yy18;
			} else {
				goto yy10;
			}
		yy18:
			++cursor;
			f1 = yyt1;
			f2 = yyt2;
			v1 = yyt3;
			v2 = cursor - 2;
			{
			  (void)hv_store(rh, f1, (int)(f2 - f1), newSVpvn(v1, (int)(v2 - v1)), 0);
			  continue;
			}
		}
		RETVAL = newRV_noinc((SV *)rh);
	OUTPUT:
		RETVAL


SV *
to_packet_oo(IN packet)
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
