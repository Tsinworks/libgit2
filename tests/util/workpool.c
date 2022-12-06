#include "clar_libgit2.h"

#include "workerpool.h"

#include <time.h>
#include <stdlib.h>

void test_workpool__basic(void)
{
    workerpool* pool = init_workerpool(8);
    int ret = workerpool_is_empty(pool);
    cl_assert_equal_i(ret, 1);
    finished_data* data = workerpool_poll(pool);
    cl_assert(data == NULL);
    wait_workerpool(pool);
    close_workerpool(pool);
}

void* entry(void* arg)
{
    int r = 1 + rand() % 4;
#if _WIN32
    Sleep(r * 1000);
#endif
    return arg;
}

void test_workpool__enqueue_many(void)
{
    srand(time(NULL));
    workerpool* pool = init_workerpool(8);
    int ret = workerpool_is_empty(pool);
    cl_assert_equal_i(ret, 1);
    for (int i = 0; i < 100; i++) {
	    int* data = (int*)malloc(sizeof(int));
	    *data = i;
	    workerpool_enqueue(pool, entry, data);
    }
    finished_data* data = NULL;

    int count = 100;
    while (count > 0) {
	    data = workerpool_poll(pool);
	    if (data) {
		    count--;
		    int task_id= *(int*)(data->result);
		    printf("Finished task id : %d\n", task_id);
		    free(data->result);
		    free_finished_data(data);
	    }
    }

    ret = workerpool_is_empty(pool);
    cl_assert_equal_i(ret, 1);
    wait_workerpool(pool);
    close_workerpool(pool);
}
