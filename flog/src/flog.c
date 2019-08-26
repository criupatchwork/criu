#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <stdint.h>

#include <sys/param.h>
#include <sys/mman.h>

#include <ffi.h>

#include "common/compiler.h"

#include "flog.h"

#define BUF_SIZE (1<<20)

static char _mbuf[BUF_SIZE];
static char *mbuf = _mbuf;
static char *fbuf;
static uint64_t fsize;
static uint64_t mbuf_size = sizeof(_mbuf);
static int binlog_fd;

int flog_map_buf(int fdout, flog_ctx_t *flog_ctx)
{
	uint64_t off = 0;
	void *addr;
	
	mbuf_size = 2 * BUF_SIZE;
	
	if (flog_ctx->size==0)	flog_ctx->size=BUF_SIZE;

	/*
	 * Two buffers are mmaped into memory. A new one is mapped when a first
	 * one is completly filled.
	 */
	if (fbuf && (mbuf - fbuf < BUF_SIZE))
		return 0;

	if (fbuf) {
		if (munmap(fbuf, BUF_SIZE * 2)) {
			fprintf(stderr, "Unable to unmap a buffer: %m");
			return 1;
		}
		off = mbuf - fbuf - BUF_SIZE;
		fbuf = NULL;
	}

	if (fsize == 0)
		fsize += BUF_SIZE;
	fsize += BUF_SIZE;

	if (!flog_ctx->readonly) {
		if (ftruncate(fdout, fsize)) {
			fprintf(stderr, "Unable to truncate a file: %m");
			return -1;
		}
	}	
	if (!fbuf) {
		if (!flog_ctx->readonly) {			
			addr = mmap(NULL, BUF_SIZE * 2, PROT_WRITE | PROT_READ,
			    MAP_FILE | MAP_SHARED, fdout, fsize - 2 * BUF_SIZE);
		}
		else {			
			addr = mmap(NULL, flog_ctx->size, PROT_READ,
			    MAP_FILE | MAP_SHARED, fdout, 0);
			mbuf_size = flog_ctx->size;
		}
	}
	else {
		addr = mremap(fbuf + BUF_SIZE, BUF_SIZE,
				BUF_SIZE * 2, MREMAP_FIXED, fbuf);
	}
	if (addr == MAP_FAILED) {
		fprintf(stderr, "Unable to map a buffer: %m");
		return -1;
	}
	
	fbuf = addr;
	mbuf = fbuf + off;

	binlog_fd=fdout;
	flog_init(flog_ctx);
	return 0;
}

int flog_init(flog_ctx_t *ctx)
{
	ctx->size = ctx->left = mbuf_size; 
	ctx->pos = ctx->buf = mbuf;
	if (!ctx->buf)
		return -ENOMEM;
	
	return 0;
}

void flog_fini(flog_ctx_t *ctx)
{
	if (mbuf == _mbuf)
		return;
	munmap(ctx->buf, BUF_SIZE * 2);
	ctx->size=(size_t) (ctx->pos - ctx->buf);
	if (!ctx->readonly) {
		if (ftruncate(binlog_fd, ctx->size)) {
			fprintf(stderr, "Unable to truncate a file: %m");
		}
	}
	
}

int flog_decode_msg(flog_msg_t *ro_m, int fdout)
{
	ffi_type *args[34] = {
		[0]		= &ffi_type_sint,
		[1]		= &ffi_type_pointer,
		[2 ... 33]	= &ffi_type_slong
	};
	void *values[34];
	ffi_cif cif;
	ffi_arg rc;
	flog_msg_t *m;
	size_t i, ret = 0;
	char *fmt;

	m=malloc(ro_m->size);
	memcpy(m, ro_m, ro_m->size);
	values[0] = (void *)&fdout;
	if (m->magic != FLOG_MAGIC) {
		return -EINVAL;
	}
	if (m->version != FLOG_VERSION)	{
		return -EINVAL;
	}

	fmt = (void *)m + m->fmt;
	values[1] = &fmt;
	
	for (i = 0; i < m->nargs; i++) {		
		values[i + 2] = (void *)&m->args[i];
		if (m->mask & (1u << i)) {
			m->args[i] = (long)((void *)m + m->args[i]);
		}	
		
	}
	
	int sdf=ffi_prep_cif(&cif, FFI_DEFAULT_ABI, m->nargs + 2,
			 &ffi_type_sint, args);
	if ( sdf == FFI_OK) {
		ffi_call(&cif, FFI_FN(dprintf), &rc, values);
	} else
		ret = -1;
	
	free(m);
	return ret;
}

void flog_decode_all(flog_ctx_t *ctx, int fdout)
{
	flog_msg_t *m;
	char *pos;
	printf("log size is %ld\n", ctx->size);
	if (ctx->size == 0)
		return;
	if (ctx->readonly) ctx->pos=ctx->buf + ctx->size;
	for (pos = ctx->buf; pos < ctx->pos; ) {
		m = (void *)pos;
		flog_decode_msg(m ,fdout);
		pos += m->size;
	}
}

int flog_encode_msg(flog_ctx_t *ctx, unsigned int nargs, unsigned int mask, const char *format, ...)
{	
	if (ctx->readonly) {		
		return 0;
	}
	flog_msg_t *m = (void *)ctx->pos;
	char *str_start, *p;
	va_list argptr;
	size_t i;

	m->nargs = nargs;
	m->mask = mask;

	str_start = (void *)m->args + sizeof(m->args[0]) * nargs;
	p = memccpy(str_start, format, 0, ctx->left - (str_start - ctx->pos));
	if (!p)
		return -ENOMEM;

	m->fmt = str_start - ctx->pos;
	str_start = p;
	va_start(argptr, format);
	for (i = 0; i < nargs; i++) {
		m->args[i] = (long)va_arg(argptr, long);
		/*
		 * If we got a string, we should either
		 * reference it when in rodata, or make
		 * a copy (FIXME implement rodata refs).
		 */
		if (mask & (1u << i)) {
			p = memccpy(str_start, (void *)m->args[i], 0, ctx->left - (str_start - ctx->pos));
			if (!p)
				return -ENOMEM;
			m->args[i] = str_start - ctx->pos;
			str_start = p;
		}
	}
	va_end(argptr);
	m->size = str_start - ctx->pos;

	/*
	 * A magic is required to know where we stop writing into a log file,
	 * if it was not properly closed.  The file is mapped into memory, so a
	 * space in the file is allocated in advance and at the end it can have
	 * some unused tail.
	 */
	m->magic = FLOG_MAGIC;
	m->version = FLOG_VERSION;

	m->size = round_up(m->size, 8);

	/* Advance position and left bytes in context memory */
	ctx->left -= m->size;
	ctx->pos += m->size;
	return 0;
}
