/*
 * Copyright (C) the libgit2 contributors. All rights reserved.
 *
 * This file is part of libgit2, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#ifndef INCLUDE_workerpool_h__
#define INCLUDE_workerpool_h__

#include "git2_util.h"

typedef struct {
	void *pool;
	git_thread thread;
	int index;
} worker;

typedef void *(*worker_fn)(void *arg);

typedef struct worker_job_data {
	worker_fn fn;
	void *data;
	struct worker_job_data *next;
} worker_job_data;

typedef struct {
	void *usr_data;
	void *result;
	int ready;
} workerpool_future;

typedef struct finished_data {
	void *usr_data;
	void *result;
	struct finished_data *next;
} finished_data;

void free_finished_data(finished_data *data);

typedef struct {
    int id;
	int num_workers;
	worker *workers;

	git_atomic32 stopped;
	git_mutex queue_lock;

	git_cond new_job_cond;

	worker_job_data *job_list;
	worker_job_data *job_tail;

	git_mutex finished_lock;
	finished_data *finished_list;
	finished_data *finished_tail;
	git_atomic32 finished_count;

	git_mutex wait_lock;

	git_atomic32 num_queued_jobs;
	git_atomic32 num_running_jobs;
} workerpool;

workerpool* init_workerpool(int num_workers);
void workerpool_enqueue(workerpool *pool, worker_fn fn, void *usr_data);
finished_data* workerpool_poll(workerpool *pool);
int workerpool_is_empty(workerpool *pool);
int wait_workerpool(workerpool *pool);
void close_workerpool(workerpool *pool);

#endif
