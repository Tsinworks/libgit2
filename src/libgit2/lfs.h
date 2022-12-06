#ifndef INCLUDE_lfs_h__
#define INCLUDE_lfs_h__

#include "common.h"
#include "git2/sys/filter.h"
#include "workerpool.h"

typedef struct lfs_filter {
	git_filter parent;
	workerpool *pool;
} lfs_filter;

#endif
