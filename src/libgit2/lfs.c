#include "lfs.h"

#include "filter.h"
#include "str.h"

static int lfs_stream(
        git_writestream **out,
        git_filter *self,
        void **payload,
        const git_filter_source *src,
        git_writestream *next);
static void lfs_begin_sync(git_filter *self);
static void lfs_end_sync(git_filter *self);
static int lfs_init(git_filter *self);
static void lfs_shutdown(git_filter *self);
static int lfs_prefilter(
        git_filter *self,
        void **payload,
        const git_filter_source *src,
        const git_blob *blob,
        const char **attr_values);

git_filter *git_lfs_fetch_filter_new(void)
{
	lfs_filter *f = git__calloc(1, sizeof(lfs_filter));
	if (f == NULL)
		return NULL;

	f->parent.version	 = GIT_FILTER_VERSION;
	f->parent.attributes = "filter=lfs";
	f->parent.initialize = lfs_init;
	f->parent.shutdown   = lfs_shutdown;
	f->parent.stream     = lfs_stream;
	f->parent.pre_filter = lfs_prefilter;
	f->parent.begin_sync = lfs_begin_sync;
	f->parent.end_sync   = lfs_end_sync;

	f->pool = init_workerpool(8);

	return f;
}

int lfs_stream(
        git_writestream **out,
        git_filter *self,
        void **payload,
        const git_filter_source *src,
        git_writestream *next)
{
	lfs_filter *lfs = self;
	return 0;
}

int lfs_prefilter(
        git_filter *self,
        void **payload, /* NULL on entry, may be set */
        const git_filter_source *src,
        const git_blob *blob,
        const char **attr_values)
{
	lfs_filter *lfs = self;
	return 0;
}

void lfs_begin_sync(git_filter *self)
{
	lfs_filter *lfs = self;
}

void lfs_end_sync(git_filter *self)
{
	lfs_filter *lfs = self;
}

int lfs_init(git_filter *self)
{
	lfs_filter *lfs = self;

	return 0;
}

void lfs_shutdown(git_filter *filter)
{
	lfs_filter *lfs = filter;
	wait_workerpool(lfs->pool);
	close_workerpool(lfs->pool);
	lfs->pool = NULL;
}
