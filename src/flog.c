#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <stdint.h>

#include <sys/mman.h>

#include <ffi.h>

#include "flog.h"
#include "util.h"

#define MAGIC 0xABCDABCD

#define BUF_SIZE (1<<20)
static char _mbuf[BUF_SIZE];
static char *mbuf = _mbuf;
static char *fbuf;
static uint64_t fsize;
static uint64_t mbuf_size = sizeof(_mbuf);

int flog_decode_all(int fdin, int fdout)
{
	flog_msg_t *m = (void *)mbuf;
	ffi_type *args[34] = {
		[0]		= &ffi_type_sint,
		[1]		= &ffi_type_pointer,
		[2 ... 33]	= &ffi_type_slong
	};
	void *values[34];
	ffi_cif cif;
	ffi_arg rc;
	size_t i, ret;
	char *fmt;

	values[0] = (void *)&fdout;

	while (1) {
		ret = read(fdin, mbuf, sizeof(m));
		if (ret == 0)
			break;
		if (ret < 0) {
			fprintf(stderr, "Unable to read a message: %m");
			return -1;
		}
		if (m->magic != MAGIC)
			break;
		ret = m->size - sizeof(m);
		if (m->size > mbuf_size) {
			fprintf(stderr, "The buffer is too small");
			return -1;
		}
		if (read(fdin, mbuf + sizeof(m), ret) != ret) {
			fprintf(stderr, "Unable to read a message: %m");
			return -1;
		}

		fmt = mbuf + m->fmt;
		values[1] = &fmt;

		for (i = 0; i < m->nargs; i++) {
			values[i + 2] = (void *)&m->args[i];
			if (m->mask & (1u << i)) {
				m->args[i] = (long)(mbuf + m->args[i]);
			}
		}

		if (ffi_prep_cif(&cif, FFI_DEFAULT_ABI, m->nargs + 2,
				 &ffi_type_sint, args) == FFI_OK)
			ffi_call(&cif, FFI_FN(dprintf), &rc, values);
	}
	return 0;
}

static int flog_enqueue(flog_msg_t *m)
{
	if (write(1, m, m->size) != m->size) {
		fprintf(stderr, "Unable to write a message\n");
		return -1;
	}
	return 0;
}

extern char *rodata_start;
extern char *rodata_end;

int flog_map_buf(int fdout)
{
	uint64_t off = 0;

	if (fbuf && (mbuf - fbuf < BUF_SIZE))
		return 0;

	if (fbuf) {
		munmap(fbuf, BUF_SIZE * 2);
		off = mbuf - fbuf - BUF_SIZE;
	}

	if (fsize == 0)
		fsize += BUF_SIZE;
	fsize += BUF_SIZE;

	ftruncate(fdout, fsize);

	fbuf = mmap(NULL, BUF_SIZE * 2, PROT_WRITE | PROT_READ, MAP_FILE | MAP_SHARED, fdout, fsize - 2 * BUF_SIZE);
	if (fbuf == MAP_FAILED)
		return -1;

	mbuf = fbuf + off;
	mbuf_size = 2 * BUF_SIZE;

	return 0;
}

void flog_encode_msg(int fdout, unsigned int nargs, unsigned int mask, const char *format, ...)
{
	flog_msg_t *m;
	va_list argptr;
	char *str_start;
	size_t i, n;

	if (flog_map_buf(fdout))
		return;

	m = (void *) mbuf;

	m->nargs = nargs;
	m->mask = mask;

	str_start = (void *)m->args + sizeof(m->args[0]) * nargs;
	n = strlen(format) + 1;
	if (mbuf_size < (str_start + n + 1 - mbuf)) {
		fprintf(stderr, "No memory for string argument\n");
		return;
	}
	memcpy(str_start, format, n);
	m->fmt = str_start - mbuf;
	str_start += n;

	va_start(argptr, format);
	for (i = 0; i < nargs; i++) {
		m->args[i] = (long)va_arg(argptr, long);
		/*
		 * If we got a string, we should either
		 * reference it when in rodata, or make
		 * a copy (FIXME implement rodata refs).
		 */
		if (mask & (1u << i)) {
			n = strlen((void *)m->args[i]);

			if (mbuf_size > (str_start + n + 1 - mbuf)) {
				memcpy(str_start, (void *)m->args[i], n + 1);
				m->args[i] = str_start - mbuf;
				str_start += n + 1;
			} else {
				fprintf(stderr, "No memory for string argument\n");
				return;
			}
		}
	}
	va_end(argptr);
	m->size = str_start - mbuf;
	m->magic = MAGIC;

	m->size = (m->size + 7) / 8 * 8;
	if (mbuf == _mbuf)
		flog_enqueue(m);
	else {
		mbuf += m->size;
		mbuf_size -= m->size;
	}
}
