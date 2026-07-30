/*
 * EAP-DID: run one blocking call off the event loop
 * Copyright (c) 2024-2026, Caciano Machado
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "includes.h"

#include <pthread.h>

#include "common.h"
#include "eap_did_async.h"

/*
 * The worker runs libcurl and OpenSSL, and did_jwe_* holds tens of kilobytes in
 * a single frame, so the default thread stack of some platforms is not enough.
 * Ask for a size that is stated rather than inherited.
 */
#define DID_ASYNC_STACK_SIZE (512 * 1024)

struct did_async {
	pthread_t thread;
	pthread_mutex_t lock;

	/* refs: one for the requester, one for the worker */
	unsigned int refs;

	/* The worker writes one octet to notify[1]; eloop watches notify[0] */
	int notify[2];

	bool finished;
	int result;

	int (*fn)(void *ctx);
	void (*ctx_free)(void *ctx);
	void *ctx;
};


static void did_async_free(struct did_async *job)
{
	if (job->ctx_free)
		job->ctx_free(job->ctx);
	if (job->notify[0] >= 0)
		close(job->notify[0]);
	if (job->notify[1] >= 0)
		close(job->notify[1]);
	pthread_mutex_destroy(&job->lock);
	os_free(job);
}


static void did_async_unref(struct did_async *job)
{
	bool last;

	pthread_mutex_lock(&job->lock);
	last = --job->refs == 0;
	pthread_mutex_unlock(&job->lock);

	if (last)
		did_async_free(job);
}


static void * did_async_worker(void *arg)
{
	struct did_async *job = arg;
	int res;
	char done = 'D';

	res = job->fn(job->ctx);

	pthread_mutex_lock(&job->lock);
	job->result = res;
	job->finished = true;
	pthread_mutex_unlock(&job->lock);

	/*
	 * One octet, once. If the requester has already let go the descriptor
	 * is still open — the job owns it until the last reference goes — so
	 * this cannot write into something else's file.
	 */
	if (write(job->notify[1], &done, 1) < 0) {
		/* Nothing to be done about it here; the requester either
		 * collects the result or has already stopped caring. */
	}

	did_async_unref(job);

	return NULL;
}


struct did_async * did_async_start(int (*fn)(void *ctx), void *ctx,
				   void (*ctx_free)(void *ctx))
{
	struct did_async *job;
	pthread_attr_t attr;
	int res;

	if (!fn) {
		if (ctx_free)
			ctx_free(ctx);
		return NULL;
	}

	job = os_zalloc(sizeof(*job));
	if (!job) {
		if (ctx_free)
			ctx_free(ctx);
		return NULL;
	}

	job->notify[0] = -1;
	job->notify[1] = -1;
	job->fn = fn;
	job->ctx = ctx;
	job->ctx_free = ctx_free;
	job->refs = 2;

	if (pthread_mutex_init(&job->lock, NULL) != 0) {
		os_free(job);
		if (ctx_free)
			ctx_free(ctx);
		return NULL;
	}

	if (pipe(job->notify) < 0) {
		job->notify[0] = -1;
		job->notify[1] = -1;
		job->refs = 1;
		did_async_free(job);
		return NULL;
	}

	if (pthread_attr_init(&attr) != 0) {
		job->refs = 1;
		did_async_free(job);
		return NULL;
	}

	/*
	 * Detached: nothing joins the worker, because the requester's release
	 * has to return at once even while a poll is outstanding.
	 */
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	pthread_attr_setstacksize(&attr, DID_ASYNC_STACK_SIZE);

	res = pthread_create(&job->thread, &attr, did_async_worker, job);
	pthread_attr_destroy(&attr);

	if (res != 0) {
		wpa_printf(MSG_ERROR, "EAP-DID: Could not start a worker: %s",
			   strerror(res));
		job->refs = 1;
		did_async_free(job);
		return NULL;
	}

	return job;
}


int did_async_fd(struct did_async *job)
{
	return job ? job->notify[0] : -1;
}


int did_async_collect(struct did_async *job, int *result)
{
	bool finished;

	if (!job)
		return -1;

	pthread_mutex_lock(&job->lock);
	finished = job->finished;
	if (finished && result)
		*result = job->result;
	pthread_mutex_unlock(&job->lock);

	return finished ? 0 : -1;
}


void did_async_release(struct did_async *job)
{
	if (job)
		did_async_unref(job);
}
