#ifndef INCLUDE_lfs_h__
#define INCLUDE_lfs_h__

#include "common.h"
#include "git2/sys/filter.h"
#include "workerpool.h"

typedef struct lfs_auth {
    git_str href;
    git_str hdr;
    unsigned int expires;
} lfs_auth;

typedef struct lfs_filter {
    git_filter parent;
    workerpool* pool;
    lfs_auth* auth;
} lfs_filter;

#endif
