/*
 * Copyright (C) the libgit2 contributors. All rights reserved.
 *
 * This file is part of libgit2, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_git_errors_h__
#define INCLUDE_git_errors_h__

#include "common.h"

/**
 * @file git2/errors.h
 * @brief Git error handling routines and variables
 * @ingroup Git
 * @{
 */
GIT_BEGIN_DECL

/** Generic return codes */
typedef enum {
	GIT_OK         =  0,		/**< No error */

	GIT_ERROR      = -1,		/**< Generic error */
	GIT_ENOTFOUND  = -3,		/**< Requested object could not be found */
	GIT_EEXISTS    = -4,		/**< Object exists preventing operation */
	GIT_EAMBIGUOUS = -5,		/**< More than one object matches */
	GIT_EBUFS      = -6,		/**< Output buffer too short to hold data */

	/**
	 * GIT_EUSER is a special error that is never generated by libgit2
	 * code.  You can return it from a callback (e.g to stop an iteration)
	 * to know that it was generated by the callback and not by libgit2.
	 */
	GIT_EUSER      = -7,

	GIT_EBAREREPO       =  -8,	/**< Operation not allowed on bare repository */
	GIT_EUNBORNBRANCH   =  -9,	/**< HEAD refers to branch with no commits */
	GIT_EUNMERGED       = -10,	/**< Merge in progress prevented operation */
	GIT_ENONFASTFORWARD = -11,	/**< Reference was not fast-forwardable */
	GIT_EINVALIDSPEC    = -12,	/**< Name/ref spec was not in a valid format */
	GIT_ECONFLICT       = -13,	/**< Checkout conflicts prevented operation */
	GIT_ELOCKED         = -14,	/**< Lock file prevented operation */
	GIT_EMODIFIED       = -15,	/**< Reference value does not match expected */
	GIT_EAUTH           = -16,	/**< Authentication error */
	GIT_ECERTIFICATE    = -17,	/**< Server certificate is invalid */
	GIT_EAPPLIED        = -18,	/**< Patch/merge has already been applied */
	GIT_EPEEL           = -19,	/**< The requested peel operation is not possible */
	GIT_EEOF            = -20,	/**< Unexpected EOF */
	GIT_EINVALID        = -21,	/**< Invalid operation or input */
	GIT_EUNCOMMITTED    = -22,	/**< Uncommitted changes in index prevented operation */
	GIT_EDIRECTORY      = -23,	/**< The operation is not valid for a directory */
	GIT_EMERGECONFLICT  = -24,	/**< A merge conflict exists and cannot continue */

	GIT_PASSTHROUGH     = -30,	/**< A user-configured callback refused to act */
	GIT_ITEROVER        = -31,	/**< Signals end of iteration with iterator */
	GIT_RETRY           = -32,	/**< Internal only */
	GIT_EMISMATCH       = -33,	/**< Hashsum mismatch in object */
	GIT_EINDEXDIRTY     = -34,	/**< Unsaved changes in the index would be overwritten */
	GIT_EAPPLYFAIL      = -35,	/**< Patch application failed */
	GIT_EOWNER          = -36,	/**< The object is not owned by the current user */
} git_error_code;

/**
 * Structure to store extra details of the last error that occurred.
 *
 * This is kept on a per-thread basis if GIT_THREADS was defined when the
 * library was build, otherwise one is kept globally for the library
 */
typedef struct {
	char *message;
	int klass;
} git_error;

/** Error classes */
typedef enum {
	GIT_ERROR_NONE = 0,
	GIT_ERROR_NOMEMORY,
	GIT_ERROR_OS,
	GIT_ERROR_INVALID,
	GIT_ERROR_REFERENCE,
	GIT_ERROR_ZLIB,
	GIT_ERROR_REPOSITORY,
	GIT_ERROR_CONFIG,
	GIT_ERROR_REGEX,
	GIT_ERROR_ODB,
	GIT_ERROR_INDEX,
	GIT_ERROR_OBJECT,
	GIT_ERROR_NET,
	GIT_ERROR_TAG,
	GIT_ERROR_TREE,
	GIT_ERROR_INDEXER,
	GIT_ERROR_SSL,
	GIT_ERROR_SUBMODULE,
	GIT_ERROR_THREAD,
	GIT_ERROR_STASH,
	GIT_ERROR_CHECKOUT,
	GIT_ERROR_FETCHHEAD,
	GIT_ERROR_MERGE,
	GIT_ERROR_SSH,
	GIT_ERROR_FILTER,
	GIT_ERROR_REVERT,
	GIT_ERROR_CALLBACK,
	GIT_ERROR_CHERRYPICK,
	GIT_ERROR_DESCRIBE,
	GIT_ERROR_REBASE,
	GIT_ERROR_FILESYSTEM,
	GIT_ERROR_PATCH,
	GIT_ERROR_WORKTREE,
	GIT_ERROR_SHA,
	GIT_ERROR_HTTP,
	GIT_ERROR_INTERNAL,
	GIT_ERROR_LFS,
} git_error_t;

/**
 * Return the last `git_error` object that was generated for the
 * current thread.
 *
 * The default behaviour of this function is to return NULL if no previous error has occurred.
 * However, libgit2's error strings are not cleared aggressively, so a prior
 * (unrelated) error may be returned. This can be avoided by only calling
 * this function if the prior call to a libgit2 API returned an error.
 *
 * @return A git_error object.
 */
GIT_EXTERN(const git_error *) git_error_last(void);

/**
 * Clear the last library error that occurred for this thread.
 */
GIT_EXTERN(void) git_error_clear(void);

/**
 * Set the error message string for this thread, using `printf`-style
 * formatting.
 *
 * This function is public so that custom ODB backends and the like can
 * relay an error message through libgit2.  Most regular users of libgit2
 * will never need to call this function -- actually, calling it in most
 * circumstances (for example, calling from within a callback function)
 * will just end up having the value overwritten by libgit2 internals.
 *
 * This error message is stored in thread-local storage and only applies
 * to the particular thread that this libgit2 call is made from.
 *
 * @param error_class One of the `git_error_t` enum above describing the
 *                    general subsystem that is responsible for the error.
 * @param fmt The `printf`-style format string; subsequent arguments must
 *            be the arguments for the format string.
 */
GIT_EXTERN(void) git_error_set(int error_class, const char *fmt, ...)
                 GIT_FORMAT_PRINTF(2, 3);

/**
 * Set the error message string for this thread.  This function is like
 * `git_error_set` but takes a static string instead of a `printf`-style
 * format.
 *
 * @param error_class One of the `git_error_t` enum above describing the
 *                    general subsystem that is responsible for the error.
 * @param string The error message to keep
 * @return 0 on success or -1 on failure
 */
GIT_EXTERN(int) git_error_set_str(int error_class, const char *string);

/**
 * Set the error message to a special value for memory allocation failure.
 *
 * The normal `git_error_set_str()` function attempts to `strdup()` the
 * string that is passed in.  This is not a good idea when the error in
 * question is a memory allocation failure.  That circumstance has a
 * special setter function that sets the error string to a known and
 * statically allocated internal value.
 */
GIT_EXTERN(void) git_error_set_oom(void);

/** @} */
GIT_END_DECL
#endif
