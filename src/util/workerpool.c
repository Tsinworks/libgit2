#include "workerpool.h"

#if _WIN32
#include <windows.h>
const DWORD MS_VC_EXCEPTION = 0x406D1388;
#pragma pack(push,8)
typedef struct tagTHREADNAME_INFO
{
    DWORD dwType; // Must be 0x1000.
    LPCSTR szName; // Pointer to name (in user addr space).
    DWORD dwThreadID; // Thread ID (-1=caller thread).
    DWORD dwFlags; // Reserved for future use, must be zero.
} THREADNAME_INFO;
#pragma pack(pop)
void SetThreadName(DWORD dwThreadID, const char* threadName) {
    THREADNAME_INFO info;
    info.dwType = 0x1000;
    info.szName = threadName;
    info.dwThreadID = dwThreadID;
    info.dwFlags = 0;
#pragma warning(push)
#pragma warning(disable: 6320 6322)
    __try{
        RaiseException(MS_VC_EXCEPTION, 0, sizeof(info) / sizeof(ULONG_PTR), (ULONG_PTR*)&info);
    }
    __except (EXCEPTION_EXECUTE_HANDLER){
    }
#pragma warning(pop)
}
#endif

static int g_pool_id = 0;

static void *worker_entry(void *arg)
{
	worker *worker = arg;
	char threadname[16] = {0};
    snprintf(threadname, 16, "Pool(%d)-%d", ((workerpool*)worker->pool)->id, worker->index);
#if _WIN32
    SetThreadName(GetCurrentThreadId(), threadname);
#endif
	workerpool *pool = worker->pool;
	while (git_atomic32_get(&pool->stopped) != 1) {
	    if (git_atomic32_get(&pool->num_queued_jobs) > 0) {
		    // fetch one job
			git_mutex_lock(&pool->queue_lock);
		    worker_job_data *job = pool->job_list;
			if (job) {
			    pool->job_list = job->next;
				job->next = NULL;
			}
			git_mutex_unlock(&pool->queue_lock);
			if (job) {
				git_atomic32_dec(&pool->num_queued_jobs);
				git_atomic32_inc(&pool->num_running_jobs);
				// execute
				void *result = job->fn(job->data);
				git_mutex_lock(&pool->finished_lock);
				finished_data* data = git__calloc(1, sizeof(finished_data));
				data->result = result;
				data->usr_data = job->data;
				if (pool->finished_list == NULL) {
					pool->finished_list = data;
				} else {
					pool->finished_tail->next = data;
				}
				pool->finished_tail = data;
				git_mutex_unlock(&pool->finished_lock);
				git_atomic32_inc(&pool->finished_count);
				git_atomic32_dec(&pool->num_running_jobs);

			    // free job data
				git__free(job);
			}
	    } else {
		    git_mutex_lock(&pool->wait_lock);
		    git_cond_wait(&pool->new_job_cond, &pool->wait_lock);
		    git_mutex_unlock(&pool->wait_lock);
	    }
	}
	return NULL;
}

workerpool *init_workerpool(int num_workers)
{
	workerpool* pool = git__calloc(1, sizeof(workerpool));
	pool->id = g_pool_id;
    git_atomic32_inc((git_atomic32*)&g_pool_id);
	pool->stopped.val = 0;
	pool->num_workers = num_workers;
	git_mutex_init(&pool->queue_lock);
	git_mutex_init(&pool->finished_lock);
	git_mutex_init(&pool->wait_lock);
	git_cond_init2(&pool->new_job_cond);
	if (num_workers > 0) {
		pool->workers = git__calloc(num_workers, sizeof(worker));
		for (int i = 0; i < num_workers; i++) {
			pool->workers[i].index = i;
			pool->workers[i].pool = pool;
			git_thread_create(
			        &pool->workers[i].thread, worker_entry,
			        pool->workers + i);
		}
	}
	return pool;
}

void workerpool_enqueue(workerpool *pool, worker_fn fn, void *usr_data)
{
	git_mutex_lock(&pool->queue_lock);
	worker_job_data *job = git__calloc(1, sizeof(worker_job_data));
	job->fn = fn;
	job->data = usr_data;
	if (pool->job_list == NULL) {
		pool->job_list = job;
	} else {
		pool->job_tail->next = job;
	}
	pool->job_tail = job;
	git_mutex_unlock(&pool->queue_lock);
	git_atomic32_inc(&pool->num_queued_jobs);
	git_cond_broadcast(&pool->new_job_cond);
}

int wait_workerpool(workerpool *pool)
{
	while (git_atomic32_get(&pool->stopped) != 1 &&
	       git_atomic32_get(&pool->num_running_jobs) > 0)
		;
	return 0;
}

int workerpool_is_empty(workerpool *pool)
{
	return pool->job_list == NULL ? 1 : 0;
}

void free_finished_data(finished_data *data)
{
	git__free(data);
}

finished_data *workerpool_poll(workerpool *pool)
{
	finished_data *data = NULL;
	if (pool->finished_list) {
		git_mutex_lock(&pool->finished_lock);
		data = pool->finished_list;
		if (data) {
			pool->finished_list = data->next;
			data->next = NULL;
		}
		git_mutex_unlock(&pool->finished_lock);
	}
	return data;
}

void close_workerpool(workerpool *pool)
{
	git_atomic32_set(&pool->stopped, 1);
	git_cond_broadcast(&pool->new_job_cond);

	for (int i = 0; i < pool->num_workers; i++) {
		git_thread_join(&pool->workers[i].thread, NULL);
	}

	git_cond_free(&pool->new_job_cond);
	git_mutex_free(&pool->queue_lock);
	git_mutex_free(&pool->finished_lock);
	git_mutex_free(&pool->wait_lock);

#if _DEBUG
	int remain = 0;
#endif
	while (pool->finished_list) {
		finished_data *data = pool->finished_list->next;
		git__free(pool->finished_list);
		pool->finished_list = data;
#if _DEBUG
		remain++;
#endif
	}
	
#if _DEBUG
	printf("Pool %d has %d datas.\n", pool->id, remain);
#endif

	pool->finished_tail = NULL;

	while (pool->job_list) {
		worker_job_data *data = pool->job_list->next;
		git__free(pool->job_list);
		pool->job_list = data;
	}

	pool->job_tail = NULL;
	git__free(pool->workers);
	git__free(pool);
}
