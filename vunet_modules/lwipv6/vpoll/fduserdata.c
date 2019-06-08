/*
 *   Associate user defined data to file descriptors. (thread-safe).
 *
 *   Copyright (C) 2018  Renzo Davoli <renzo@cs.unibo.it> VirtualSquare team.
 *
 *   This library is free software; you can redistribute it and/or modify it
 *   under the terms of the GNU Lesser General Public License as published by
 *   the Free Software Foundation; either version 2.1 of the License, or (at
 *   your option) any later version.
 *
 *   You should have received a copy of the GNU Lesser General Public License
 *   along with this library; if not, write to the Free Software Foundation,
 *   Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stddef.h>
#include <pthread.h>

#define DEFAULT_MASK 0x3f // 63

#ifndef container_of
#define container_of(ptr, type, member) ({ \
    const typeof( ((type *)0)->member ) *__mptr = (ptr); \
    (type *)( (char *)__mptr - offsetof(type,member) );})
#endif

struct fduserdata_table;
typedef struct fduserdata_table FDUSERDATA;

struct fduserdata {
	struct fduserdata *next;
	int fd;
	_Atomic int count;
	pthread_mutex_t mutex;
	char data[];
};

struct fduserdata_table {
	int mask;
	pthread_mutex_t mutex;
	struct fduserdata *table[];
};

static int size2mask(int x) {
	int scan;
	x = x - 1;
	if (x < 0)
		return DEFAULT_MASK;
	else {
		for (scan = -1; scan & x; scan <<= 1)
			;
		return ~scan;
	}
}

FDUSERDATA *fduserdata_create(int size) {
	int mask = size2mask(size);
	struct fduserdata_table *table = calloc(1, sizeof(struct fduserdata_table) + (mask + 1) * sizeof(struct fduserdata *));
	if (table != NULL)
		table->mask = mask;
	pthread_mutex_init(&table->mutex, NULL);
	return table;
}

void fduserdata_release(struct fduserdata *fdud) {
	pthread_mutex_destroy(&fdud->mutex);
	free(fdud);
}

void fduserdata_destroy(FDUSERDATA *fdtable) {
	if (fdtable != NULL) {
		int i;
		pthread_mutex_lock(&fdtable->mutex);
		for (i = 0; i < (fdtable->mask + 1) ; i++) {
			struct fduserdata *fdud = fdtable->table[i];
			while (fdud != NULL) {
				struct fduserdata *this = fdud;
				fdud = this->next;
				fduserdata_release(this);
			}
		}
		pthread_mutex_unlock(&fdtable->mutex);
		pthread_mutex_destroy(&fdtable->mutex);
		free(fdtable);
	}
}

void *fduserdata_set(FDUSERDATA *fdtable, int fd, size_t count) {
	if (fdtable != NULL) {
		struct fduserdata *fdud = malloc(sizeof(struct fduserdata) + count);
		int index;
		if (fdud == NULL)
			return errno = ENOMEM, NULL;
		pthread_mutex_lock(&fdtable->mutex);
		index = fd & fdtable->mask;
		fdud->fd = fd;
		fdud->count = 2;
		fdud->next = fdtable->table[index];
		fdtable->table[index] = fdud;
		pthread_mutex_init(&fdud->mutex, NULL);
		pthread_mutex_unlock(&fdtable->mutex);
		pthread_mutex_lock(&fdud->mutex);
		return fdud->data;
	} else
		return errno = EINVAL, NULL;
}

void *fduserdata_get(FDUSERDATA *fdtable, int fd) {
	if (fdtable != NULL) {
		pthread_mutex_lock(&fdtable->mutex);
		int index = fd & fdtable->mask;
		struct fduserdata *fdud;
		for (fdud = fdtable->table[index]; fdud != NULL && fdud->fd != fd; fdud = fdud->next)
			;
		if (fdud != NULL)
			fdud->count++;
		pthread_mutex_unlock(&fdtable->mutex);
		if (fdud != NULL) {
			pthread_mutex_lock(&fdud->mutex);
			return fdud->data;
		} else
			return errno = EBADF, NULL;
	} else
		return errno = EINVAL, NULL;
}

void fduserdata_put(void *data) {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
	struct fduserdata *fdud = container_of(data, struct fduserdata, data);
#pragma GCC diagnostic pop
	int count = --fdud->count;
	pthread_mutex_unlock(&fdud->mutex);
	if (count == 0)
		fduserdata_release(fdud);
}

int fduserdata_del(FDUSERDATA *fdtable, int fd) {
	if (fdtable != NULL) {
		pthread_mutex_lock(&fdtable->mutex);
		int index = fd & fdtable->mask;
		int count;
		struct fduserdata **fdud;
		for (fdud = &(fdtable->table[index]); *fdud != NULL && (*fdud)->fd != fd; fdud = &((*fdud)->next))
			;
		if (*fdud != NULL) {
			struct fduserdata *this = *fdud;
			count = --this->count;
			*fdud = this->next;
			pthread_mutex_unlock(&fdtable->mutex);
			if (count == 0)
				fduserdata_release(this);
			return 0;
		} else {
			pthread_mutex_unlock(&fdtable->mutex);
			return errno = EBADF, -1;
		}
	} else
		return errno = EINVAL, -1;
}

#if 0
int main(int argc, char *argv[]) {
	FDUSERDATA *fdtable = fduserdata_create(0);
	int *data;
	data = fduserdata_set(fdtable, 1, sizeof(* data));
	if (data) *data = 1;
	if (data) fduserdata_put(data);
	data = fduserdata_set(fdtable, 2, sizeof(* data));
	if (data) if (data) *data = 2;
	fduserdata_put(data);
	data = fduserdata_set(fdtable, 65, sizeof(* data));
	if (data) if (data) *data = 65;
	fduserdata_put(data);
	data = fduserdata_get(fdtable, 1);
	if (data) printf("%d\n",*data);
	if (data) fduserdata_put(data);
	data = fduserdata_get(fdtable, 2);
	if (data) printf("%d\n",*data);
	if (data) fduserdata_put(data);
	data = fduserdata_get(fdtable, 65);
	if (data) printf("%d\n",*data);
	if (data) fduserdata_put(data);
	fduserdata_del(fdtable, 2);
	fduserdata_del(fdtable, 3);
	data = fduserdata_get(fdtable, 2);
	if (data) printf("%d\n",*data); else printf("NULL\n");
	if (data) fduserdata_put(data);
	data = fduserdata_get(fdtable, 1);
	if (data) printf("%d\n",*data); else printf("NULL\n");
	if (data) fduserdata_put(data);
	fduserdata_del(fdtable, 1);
	data = fduserdata_get(fdtable, 1);
	if (data) printf("%d\n",*data); else printf("NULL\n");
	if (data) fduserdata_put(data);
	data = fduserdata_get(fdtable, 65);
	if (data) printf("%d\n",*data); else printf("NULL\n");
	if (data) fduserdata_put(data);
	fduserdata_destroy(fdtable);
}
#endif
