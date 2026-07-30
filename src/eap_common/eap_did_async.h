/*
 * EAP-DID: run one blocking call off the event loop
 * Copyright (c) 2024-2026, Caciano Machado
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 *
 * The authenticator has to talk HTTP to the verifier, and libcurl blocks. Doing
 * that from an eloop callback stops hostapd entirely for as long as the
 * verifier takes to answer: no other station authenticates, no timer fires, no
 * control interface command is answered. This runs the call on a thread of its
 * own and makes its completion readable on a file descriptor, which eloop
 * watches like any other.
 *
 * The job outlives whichever side finishes first. A session can be torn down
 * while the verifier is still being polled, and the worker cannot be
 * interrupted safely in the middle of a libcurl call, so both the requester and
 * the worker hold a reference and the last one to let go is the one that frees.
 * The requester's release never blocks.
 */

#ifndef EAP_DID_ASYNC_H
#define EAP_DID_ASYNC_H

struct did_async;

/**
 * did_async_start - Run @fn on a thread of its own
 * @fn: What to run. Its return value is reported by did_async_result()
 * @ctx: Passed to @fn. Owned by the job from here on
 * @ctx_free: Frees @ctx, called once nobody holds the job any more
 * Returns: The job, or %NULL if no thread could be started, in which case
 * @ctx_free has been called on @ctx
 *
 * @fn runs on a thread that shares nothing with the caller but @ctx. It must
 * not touch the session, the eloop, or anything else the main thread owns.
 */
struct did_async * did_async_start(int (*fn)(void *ctx), void *ctx,
				   void (*ctx_free)(void *ctx));

/**
 * did_async_fd - The descriptor that becomes readable when the job finishes
 * @job: Job from did_async_start()
 * Returns: A descriptor to hand to eloop_register_read_sock()
 *
 * One octet is written to it, once. The job owns it; do not close it.
 */
int did_async_fd(struct did_async *job);

/**
 * did_async_collect - Read the outcome of a finished job
 * @job: Job from did_async_start()
 * @result: Set to what @fn returned
 * Returns: 0 once the job has finished, -1 while it is still running
 */
int did_async_collect(struct did_async *job, int *result);

/**
 * did_async_release - Let go of a job
 * @job: Job from did_async_start(), or %NULL
 *
 * Returns immediately whether or not the worker has finished. The job and its
 * context are freed by whichever of the two lets go last.
 */
void did_async_release(struct did_async *job);

#endif /* EAP_DID_ASYNC_H */
