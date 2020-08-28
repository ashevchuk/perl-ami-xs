#define PERL_NO_GET_CONTEXT

#define ALLOC_PAGE_SIZE sysconf(_SC_PAGESIZE)
#define BUFFER_PAGES 1024
#define BUFFER_SIZE ALLOC_PAGE_SIZE * BUFFER_PAGES

#ifdef DEBUG
#define trace(f_, ...) warn("%s:%-4d [%d] " f_, __FILE__, __LINE__, (int)getpid(), ##__VA_ARGS__)
#else
#define trace(...)
#endif

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

// #include <pthread.h>

typedef struct
{

    uint64_t readPointer;
    uint64_t writePointer;
    int64_t size;

    void *buffer[];

} RingBuffer;

typedef enum AMIerr_e { EAMI_NONE = 0, EAMI_FATAL, EAMI_UNKNOWN, EAMI_DESTROY } AMIerr;

typedef struct AMIctx_s {
    struct ev_io * read_ev_io;

    struct ev_loop * loop;

    char * buffer;
    char * buffer_head;
    char * buffer_cursor;

    SV * event_callback;

    uint64_t buffer_len;
    uint64_t buffer_pos;
    uint64_t buffer_free;

    unsigned int portno;

    struct sockaddr_in serv_addr;
    struct hostent *server;

    int sockfd;
    bool error;
    AMIerr error_code;
} AMIctx;

RingBuffer *ringBufferInit(int64_t size)
{
    RingBuffer *buffer = malloc(sizeof(RingBuffer) + size * sizeof(void*));

    buffer->readPointer = 0;
    buffer->writePointer = 0;
    buffer->size = size;
    memset(buffer->buffer, 1, size * sizeof(void*));
    return buffer;
}

int ringBufferAdd(RingBuffer *buffer, void *value)
{
    uint64_t readPointer;
    uint64_t writePointer;
    uint64_t realPointer;
    void *oldValue;

    while (1)
    {
	readPointer = __atomic_load_n(&buffer->readPointer, __ATOMIC_SEQ_CST);
	writePointer = __atomic_load_n(&buffer->writePointer, __ATOMIC_SEQ_CST);
	if (writePointer - readPointer >= buffer->size)
	{
	    return 0;
	}

	realPointer = writePointer % buffer->size;
	oldValue = buffer->buffer[realPointer];
	if (!oldValue || !__atomic_compare_exchange_n(&buffer->buffer[realPointer], &oldValue, 0, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST))
	{
	    continue;
	}

	if (__atomic_compare_exchange_n(&buffer->writePointer, &writePointer, writePointer + 1, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST))
	{
	    break;
	}

	void *allocValue = NULL;
	__atomic_compare_exchange_n(&buffer->buffer[realPointer], &allocValue, oldValue, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
    }

    buffer->buffer[realPointer] = value;
    return 1;
}

void * ringBufferGet(RingBuffer *buffer)
{
    uint64_t readPointer;
    uint64_t writePointer;
    uint64_t realPointer;
    void *result;

    while (1)
    {
	writePointer = __atomic_load_n(&buffer->writePointer, __ATOMIC_SEQ_CST);
	readPointer = __atomic_load_n(&buffer->readPointer, __ATOMIC_SEQ_CST);
	if (readPointer >= writePointer)
	{
	    return NULL;
	}

	realPointer = readPointer % buffer->size;
	result = buffer->buffer[realPointer];
	if (!result)
	{
	    return NULL;
	}

	if (__atomic_compare_exchange_n(&buffer->readPointer, &readPointer, readPointer + 1, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST))
	{
	    break;
	}
    }

    return result;
}

void ringBufferDestroy(RingBuffer *buffer)
{
    free(buffer);
}

AMIctx * ami_ctx_init()
{
  AMIctx * ami_ctx = (AMIctx *) malloc(sizeof(AMIctx));

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

  memset(&ami_ctx->serv_addr, '0', sizeof(ami_ctx->serv_addr));

  ami_ctx->error = false;
  ami_ctx->error_code = EAMI_NONE;

  return ami_ctx;
}

void ami_ctx_set_error(AMIctx * ami_ctx, const AMIerr code, const char *message)
{
  trace("! AMI error: %s, code: %d\n", message, (uint8_t)code);

  if (ami_ctx) {
	ami_ctx->error = true;
	ami_ctx->error_code = code;
  }
}

bool ami_ctx_is_error(AMIctx * ami_ctx)
{
  if (ami_ctx) {
	return ami_ctx->error;
  }
  return true;
}


int ami_ctx_host(AMIctx * ami_ctx, const char * host, const char * port)
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

uint64_t ami_ctx_scan_packet_end( AMIctx * ami_ctx )
{
  if (ami_ctx != NULL) {
    register const char *cursor = ami_ctx->buffer_head;
    register uint64_t i = 0;
    register bool found = false;
    for (register uint64_t i = 0; i < ami_ctx->buffer_len; i++) {
	trace("scan i: %d\n", i);
	found = (bool)((*cursor == '\n') && (*(cursor + 1) == '\r'));
	if (found) {
	    trace("scan found i: %d\n", i);
	    return (i + 3);
	}
	cursor++;
    }
  }
  return 0;
}

void ami_ctx_invoke_event_callback(AMIctx * ami_ctx)
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
    PUSHs(sv_2mortal(newSViv(index)));
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

void ami_ctx_set_event_callback(AMIctx * ami_ctx, SV * event_callback)
{
  if (ami_ctx != NULL) {
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

int ami_ctx_stop_events(AMIctx * ami_ctx)
{
  if (ami_ctx) {
	trace("ami_ctx_stop_events begin ctx: %p\n", ami_ctx);
	trace("ami_ctx_stop_events destroy read_ev_io: %p\n", ami_ctx->read_ev_io);
	if (ami_ctx->read_ev_io) {
		trace("ami_ctx_stop_events destroy defined read_ev_io: %p\n", ami_ctx->read_ev_io);
		ami_ctx->read_ev_io->data = NULL;

		if (ev_is_active(ami_ctx->read_ev_io)) {
			trace("ami_ctx_stop_events stop read_ev_io\n");
			ev_io_stop(ami_ctx->loop, ami_ctx->read_ev_io);
		}
		trace("ami_ctx_stop_events free read_ev_io\n");
		free(ami_ctx->read_ev_io);
		ami_ctx->read_ev_io = NULL;
	}
  }
  trace("ami_ctx_stop_events end\n");
  return 0;
}


int ami_ctx_disconnect(AMIctx * ami_ctx)
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


static void
ami_ctx_ev_read_cb (struct ev_loop *loop, ev_io *w, int revents)
{
    AMIctx * ami_ctx = (AMIctx *)w->data;

    if (ami_ctx) {
	if (revents & EV_ERROR && !(revents & EV_READ)) {
		trace("EV error on read, fd=%d revents=0x%08x\n", ami_ctx->sockfd, revents);
		(void)ami_ctx_stop_events(ami_ctx);
		(void)ami_ctx_disconnect(ami_ctx);
		return;
	}

	size_t n = 0;

//	memset(ami_ctx->buffer, '\0', BUFFER_SIZE);

	l_read:
	n = read(ami_ctx->sockfd, ami_ctx->buffer_cursor, ami_ctx->buffer_free);

	if (n <= 0) {
		if (n == 0) {
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
	else if (n > 0) {
	    trace("read AMI data fd %d, len: %d\n", ami_ctx->sockfd, n);

	    char *read_data = strndup(ami_ctx->buffer_cursor, n);
	    trace("read AMI data:\n|%s|\n", read_data);
	    free(read_data);

	    ami_ctx->buffer_len += n;
	    ami_ctx->buffer_cursor = ami_ctx->buffer_head + ami_ctx->buffer_len;
	    ami_ctx->buffer_pos = (int)(ami_ctx->buffer_cursor - ami_ctx->buffer_head);
	    ami_ctx->buffer_free = BUFFER_SIZE - ami_ctx->buffer_pos;

	    trace("new AMI buffer len: %d\n", ami_ctx->buffer_len);

	    uint64_t found = 0;

	    while((found = ami_ctx_scan_packet_end(ami_ctx))) {
		trace("found AMI packet end at: %d\n", found);

		char *found_packet = strndup(ami_ctx->buffer_head, found);
		trace("found AMI packet: %s\n", found_packet);

//		ami_ctx_invoke_event_callback(ami_ctx);

		free(found_packet);

		if (ami_ctx->buffer_len > found) { // residual data
			trace("residual AMI buffer len: %d\n", ami_ctx->buffer_len);

			memmove(ami_ctx->buffer_head, ami_ctx->buffer_head + found, ami_ctx->buffer_len - found);

			ami_ctx->buffer_len -= found;
			ami_ctx->buffer_cursor = ami_ctx->buffer_head + ami_ctx->buffer_len;
			ami_ctx->buffer_pos = (int)(ami_ctx->buffer_cursor - ami_ctx->buffer_head);
			ami_ctx->buffer_free = BUFFER_SIZE - ami_ctx->buffer_pos;
		} else {
			trace("no residual AMI data. clear buffer\n");

			ami_ctx->buffer_len = 0;
			ami_ctx->buffer_cursor = ami_ctx->buffer_head;
			ami_ctx->buffer_pos = 0;
			ami_ctx->buffer_free = BUFFER_SIZE;
		}
	    }
	}
    }

//    trace("done reading from socket\n");
}

int ami_ctx_setup_events(AMIctx * ami_ctx)
{
  if (ami_ctx != NULL) {
	if (ami_ctx->sockfd > 0) {
		if (ami_ctx->read_ev_io == NULL) {
			ami_ctx->read_ev_io = (struct ev_io *)malloc(sizeof(struct ev_io));
			ev_io_init(ami_ctx->read_ev_io, ami_ctx_ev_read_cb, ami_ctx->sockfd, EV_READ);
			ami_ctx->read_ev_io->data = (void *)ami_ctx;
			ev_io_start(ami_ctx->loop, ami_ctx->read_ev_io);
		}
	} else {
	    return -1;
	}
  }
  return 0;
}

int ami_ctx_connect(AMIctx * ami_ctx)
{
  if (ami_ctx != NULL) {
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

	char *banner = (char *)malloc(255); // "Asterisk Call Manager/2.10.4\r\n"

	int n = -1;

	memset(banner, '\0', 255);

	n = read(ami_ctx->sockfd, banner, 254);

	trace("read AMI data len: %d\n", n);

	trace("read AMI banner: %s\n", banner);

	free(banner);

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

int ami_ctx_fd(AMIctx * ami_ctx)
{
  if (ami_ctx != NULL) {
	return ami_ctx->sockfd;
  }
  return -1;
}

int ami_ctx_write(AMIctx * ami_ctx, const char * packet)
{
  if (ami_ctx != NULL) {
    if (ami_ctx->sockfd > 0) {
	int n = 0;
	n = write(ami_ctx->sockfd, packet, strlen(packet));
	return n;
    }
  }
  return 0;
}

struct ev_loop * ami_ctx_loop(AMIctx * ami_ctx, struct ev_loop * loop)
{
  if (ami_ctx != NULL) {
	if (loop != NULL) {
	    ami_ctx->loop = loop;
	}

	return ami_ctx->loop;
  }

  return NULL;
}

void ami_ctx_destroy (AMIctx * ami_ctx)
{
  if (ami_ctx) {
    trace("ami_ctx_destroy begin\n");

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
    trace("ami_ctx_destroy main free\n");
    ami_ctx->error = true;
    ami_ctx->error_code = EAMI_DESTROY;

    free(ami_ctx);
    ami_ctx = NULL;
  }
  trace("ami_ctx_destroy done\n");
}

int mk_connect(const char * host, const char * port, SV * cb)
{
    int index = 42;

    dTHX;
    dSP;

    if (cb != NULL) {

    trace("mk_connect callback cb=%p\n", cb);

    ENTER;
    SAVETMPS;
    PUSHMARK(SP);
    PUSHs(sv_2mortal(newSViv(index)));
    PUTBACK;

    call_sv(cb, G_DISCARD|G_EVAL|G_VOID);

    SPAGAIN;

    trace("page size: %d\n", sysconf(_SC_PAGESIZE));
    trace("called mk_connect callback, errsv? %d\n", SvTRUE(ERRSV) ? 1 : 0);

    PUTBACK;
    FREETMPS;
    LEAVE;
    }

	int ret = 0;
	int sockfd, portno, n;

	struct sockaddr_in serv_addr;
	struct hostent *server;

	char buffer[256];

	portno = atoi(port);
	sockfd = socket(AF_INET, SOCK_STREAM, 0);

	if (sockfd < 0)
		fprintf(stderr,"ERROR opening socket\n");

	server = gethostbyname(host);
	if (server == NULL) {
		fprintf(stderr,"ERROR, no such host\n");
	}

	trace("AMI conn fd=%d\n", sockfd);

	bzero((char *) &serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	bcopy((char *)server->h_addr,
		 (char *)&(serv_addr.sin_addr.s_addr),
		 server->h_length);
	serv_addr.sin_port = htons(portno);
	if (connect(sockfd,(struct sockaddr *)&serv_addr,sizeof(serv_addr)) < 0)
		fprintf(stderr,"ERROR connecting\n");

	memset(buffer, '\0', sizeof(buffer));

	strcpy(buffer, "Action: Login\r\nActionID: 1\r\nUsername: manager-wwbprv\r\nSecret: tASofV5vlU4m\r\n\r\n");

	n = write(sockfd,buffer,strlen(buffer));

	if (n < 0)
		fprintf(stderr,"ERROR writing to socket\n");

	memset(buffer, '\0', sizeof(buffer));

	n = read(sockfd,buffer,sizeof(buffer)-1);

	if (n < 0)
		 fprintf(stderr,"ERROR reading from socket\n");

	ret = shutdown(sockfd, SHUT_RDWR);
	if (ret == -1) {
		return -1;
	}

	ret = close(sockfd);
	if (ret == -1) {
		return -1;
	}

	trace("recv: %s\n", buffer);


	return 0;
}

/*!
 * AMI header structure.
 */
typedef struct __attribute__((__packed__)) AMIHeader_ {
  size_t name_size;   /*!< Name field size */
  char *name;         /*!< AMI header name as string. */
  size_t value_size;  /*!< Value field size */
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


AMIPacket *amipack_init()
{
  AMIPacket *pack = (AMIPacket*) malloc(sizeof(AMIPacket));
  pack->size = 0;
  pack->length = 0;
  pack->head = NULL;
  pack->tail = NULL;

  return pack;
}


void amiheader_destroy (AMIHeader *hdr)
{
  if (hdr) {
    if (hdr->name) free(hdr->name);
    if (hdr->value) free(hdr->value);
    free(hdr);
  }
  hdr = NULL;
}


AMIHeader *amiheader_create(char *name, size_t name_size, char *value, size_t value_size)
{
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


int amipack_list_append(AMIPacket *pack, AMIHeader *header)
{
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

size_t amiheader_find(AMIPacket *pack,
                      char *name,
                      char **val)
{
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

MODULE = AMI		PACKAGE = AMIctxPtr  PREFIX = AMIctx_

void
AMIctx_DESTROY(ami_ctx)
        AMIctx *ami_ctx
	CODE:
		printf("AMIctxPtr::DESTROY\n");
        	ami_ctx_destroy(ami_ctx);
        	ami_ctx = NULL;


MODULE = AMI		PACKAGE = AMI
PROTOTYPES: DISABLE

BOOT:
	{
		I_EV_API("AMI");
        }

int
try_connect(IN host, IN port, IN cb)
	const char * host
	const char * port
	SV * cb
	PREINIT:
		int res = 0;
	CODE:
		res = mk_connect(host, port, newSVsv(cb));
		RETVAL = res;
	OUTPUT:
		RETVAL

AMIctx * 
ami_connect(IN loop, IN host, IN port, IN event_callback)
	struct ev_loop * loop
	const char * host
	const char * port
	SV * event_callback
	INIT:
		AMIctx * ami_ctx = ami_ctx_init();
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
	AMIctx * ami_ctx
	INIT:
		int fd = -1;
	CODE:
		fd = ami_ctx_fd(ami_ctx);
		RETVAL = fd;
	OUTPUT:
		RETVAL

int
ami_write(IN ami_ctx, IN packet)
	AMIctx * ami_ctx
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
	AMIctx * ami_ctx
	CODE:
		ami_ctx_destroy(ami_ctx);

size_t
fields_count_s(IN packet)
	const char * packet
	INIT:
		register const char *cursor = packet;
		register size_t count = 0;
	CODE:
		while (*cursor) {
			if (*cursor++ == '\n') count++;
		}
		count && count--;
		RETVAL = count;
	OUTPUT:
		RETVAL

size_t
fields_count(IN packet)
	const char * packet
	INIT:
		register const char *cursor = packet;
		register const char *ch = cursor;
		register const char *prev_ch = ch;

		register size_t count = 0;

		register bool process = true;
	CODE:
		while (process) {
			if (*ch == '\r') {
				if (*prev_ch == '\n') {
					process = false;
					break;
				} else {
					count++;
				}
			} else if(*ch == '\0') {
					process = false;
					break;
			}
			prev_ch = ch;
			ch = cursor++;
		}

		RETVAL = count;
	OUTPUT:
		RETVAL

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
to_packet_ooo(IN packet)
	const char * packet
	INIT:
		HV * rh;
	CODE:
		rh = newHV();
		const char *cursor = packet;
		const char *f1, *f2, *v1, *v2;
		const char *yyt1;const char *yyt2;const char *yyt3;

		loop:
		{
			char yych;
			yych = *cursor;
			switch (yych) {
			case '\r':	goto yy4;
			case '-':
			case '.':
			case '0':
			case '1':
			case '2':
			case '3':
			case '4':
			case '5':
			case '6':
			case '7':
			case '8':
			case '9':
			case 'A':
			case 'B':
			case 'C':
			case 'D':
			case 'E':
			case 'F':
			case 'G':
			case 'H':
			case 'I':
			case 'J':
			case 'K':
			case 'L':
			case 'M':
			case 'N':
			case 'O':
			case 'P':
			case 'Q':
			case 'R':
			case 'S':
			case 'T':
			case 'U':
			case 'V':
			case 'W':
			case 'X':
			case 'Y':
			case 'Z':
			case '_':
			case 'a':
			case 'b':
			case 'c':
			case 'd':
			case 'e':
			case 'f':
			case 'g':
			case 'h':
			case 'i':
			case 'j':
			case 'k':
			case 'l':
			case 'm':
			case 'n':
			case 'o':
			case 'p':
			case 'q':
			case 'r':
			case 's':
			case 't':
			case 'u':
			case 'v':
			case 'w':
			case 'x':
			case 'y':
			case 'z':
				yyt1 = cursor;
				goto yy5;
			default:	goto yy2;
			}
		yy2:
			++cursor;
		yy3:
			{
			goto done;
			}
		yy4:
			yych = *++cursor;
			switch (yych) {
			case '\n':	goto yy6;
			default:	goto yy3;
			}
		yy5:
			yych = *(packet = ++cursor);
			switch (yych) {
			case '\t':
			case ' ':
			case '-':
			case '.':
			case '0':
			case '1':
			case '2':
			case '3':
			case '4':
			case '5':
			case '6':
			case '7':
			case '8':
			case '9':
			case ':':
			case 'A':
			case 'B':
			case 'C':
			case 'D':
			case 'E':
			case 'F':
			case 'G':
			case 'H':
			case 'I':
			case 'J':
			case 'K':
			case 'L':
			case 'M':
			case 'N':
			case 'O':
			case 'P':
			case 'Q':
			case 'R':
			case 'S':
			case 'T':
			case 'U':
			case 'V':
			case 'W':
			case 'X':
			case 'Y':
			case 'Z':
			case '_':
			case 'a':
			case 'b':
			case 'c':
			case 'd':
			case 'e':
			case 'f':
			case 'g':
			case 'h':
			case 'i':
			case 'j':
			case 'k':
			case 'l':
			case 'm':
			case 'n':
			case 'o':
			case 'p':
			case 'q':
			case 'r':
			case 's':
			case 't':
			case 'u':
			case 'v':
			case 'w':
			case 'x':
			case 'y':
			case 'z':	goto yy12;
			default:	goto yy3;
			}
		yy6:
			++cursor;
			{ goto done; }
		yy8:
			yych = *++cursor;
			switch (yych) {
			case '\t':
			case ' ':	goto yy8;
			case ':':	goto yy13;
			default:	goto yy10;
			}
		yy10:
			cursor = packet;
			goto yy3;
		yy11:
			yych = *++cursor;
		yy12:
			switch (yych) {
			case '\t':
			case ' ':
				yyt2 = cursor;
				goto yy8;
			case '-':
			case '.':
			case '0':
			case '1':
			case '2':
			case '3':
			case '4':
			case '5':
			case '6':
			case '7':
			case '8':
			case '9':
			case 'A':
			case 'B':
			case 'C':
			case 'D':
			case 'E':
			case 'F':
			case 'G':
			case 'H':
			case 'I':
			case 'J':
			case 'K':
			case 'L':
			case 'M':
			case 'N':
			case 'O':
			case 'P':
			case 'Q':
			case 'R':
			case 'S':
			case 'T':
			case 'U':
			case 'V':
			case 'W':
			case 'X':
			case 'Y':
			case 'Z':
			case '_':
			case 'a':
			case 'b':
			case 'c':
			case 'd':
			case 'e':
			case 'f':
			case 'g':
			case 'h':
			case 'i':
			case 'j':
			case 'k':
			case 'l':
			case 'm':
			case 'n':
			case 'o':
			case 'p':
			case 'q':
			case 'r':
			case 's':
			case 't':
			case 'u':
			case 'v':
			case 'w':
			case 'x':
			case 'y':
			case 'z':	goto yy11;
			case ':':
				yyt2 = cursor;
				goto yy13;
			default:	goto yy10;
			}
		yy13:
			yych = *++cursor;
			switch (yych) {
			case '\t':
			case ' ':	goto yy13;
			case '\r':
				yyt3 = cursor;
				goto yy17;
			default:
				yyt3 = cursor;
				goto yy15;
			}
		yy15:
			yych = *++cursor;
			switch (yych) {
			case '\r':	goto yy17;
			default:	goto yy15;
			}
		yy17:
			yych = *++cursor;
			switch (yych) {
			case '\n':	goto yy18;
			default:	goto yy10;
			}
		yy18:
			++cursor;
			f1 = yyt1;
			f2 = yyt2;
			v1 = yyt3;
			v2 = cursor - 2;
			{
			  (void)hv_store(rh, f1, (int)(f2 - f1), newSVpvn(v1, (int)(v2 - v1)), 0);
			  goto loop;
			}
		}
		done:
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
