/*  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU LGPLv2.
  See the file COPYING.LIB.
*/

/** @file */

#if !defined(FUSE_H_) && !defined(FUSE_LOWLEVEL_H_)
#error "Never include <fuse_common.h> directly; use <fuse.h> or <fuse_lowlevel.h> instead."
#endif

#ifndef FUSE_COMMON_H_
#define FUSE_COMMON_H_

#include "fuse_opt.h"
#include <stdint.h>
#include <sys/types.h>

/** Major version of FUSE library interface */
#define FUSE_MAJOR_VERSION 3

/** Minor version of FUSE library interface */
#define FUSE_MINOR_VERSION 0

#define FUSE_MAKE_VERSION(maj, min)  ((maj) * 10 + (min))
#define FUSE_VERSION FUSE_MAKE_VERSION(FUSE_MAJOR_VERSION, FUSE_MINOR_VERSION)

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Information about open files
 */
struct fuse_file_info {
	/** Open flags.	 Available in open() and release() */
	int flags;

	/** In case of a write operation indicates if this was caused by a
	    writepage */
	unsigned int writepage : 1;

	/** Can be filled in by open, to use direct I/O on this file. */
	unsigned int direct_io : 1;

	/** Can be filled in by open, to indicate, that cached file data
	    need not be invalidated. */
	unsigned int keep_cache : 1;

	/** Indicates a flush operation.  Set in flush operation, also
	    maybe set in highlevel lock operation and lowlevel release
	    operation. */
	unsigned int flush : 1;

	/** Can be filled in by open, to indicate that the file is not
	    seekable. */
	unsigned int nonseekable : 1;

	/* Indicates that flock locks for this file should be
	   released.  If set, lock_owner shall contain a valid value.
	   May only be set in ->release(). */
	unsigned int flock_release : 1;

	/** Padding.  Do not use*/
	unsigned int padding : 27;

	/** File handle.  May be filled in by filesystem in open().
	    Available in all other file operations */
	uint64_t fh;

	/** Lock owner id.  Available in locking operations and flush */
	uint64_t lock_owner;

	/** Requested poll events.  Available in ->poll.  Only set on kernels
	    which support it.  If unsupported, this field is set to zero. */
	uint32_t poll_events;
};



/**************************************************************************
 * Capability bits for 'fuse_conn_info.capable' and 'fuse_conn_info.want' *
 **************************************************************************/

/**
 * Indicates that the filesystem supports asynchronous read requests.
 *
 * If this capability is not requested/available, the kernel will
 * ensure that there is at most one pending read request per
 * file-handle at any time, and will attempt to order read requests by
 * increasing offset.
 */
#define FUSE_CAP_ASYNC_READ		(1 << 0)

/**
 * Indicates that the filesystem supports "remote" locking.
 */
#define FUSE_CAP_POSIX_LOCKS		(1 << 1)

/**
 * Indicates that the filesystem supports  the O_TRUNC open flag
 */
#define FUSE_CAP_ATOMIC_O_TRUNC		(1 << 3)

/**
 * Indicates that the filesystem supports lookups of "." and "..".
 */
#define FUSE_CAP_EXPORT_SUPPORT		(1 << 4)

/**
 * Indicates that the kernel should not apply the umask to the
 * file mode on create operations.
 */
#define FUSE_CAP_DONT_MASK		(1 << 6)

/**
 * Indicates that libfuse should try to use splice() when writing to
 * the fuse device
 */
#define FUSE_CAP_SPLICE_WRITE		(1 << 7)

/**
 * Indicates that libfuse should try to move pages instead of copying
 * when writing to / reading from the fuse device.
 */
#define FUSE_CAP_SPLICE_MOVE		(1 << 8)

/**
 * Indicates that libfuse should try to use splice() when reading from
 * the fuse device.
 */
#define FUSE_CAP_SPLICE_READ		(1 << 9)

/**
 * If set, the calls to flock(2) will be emulated using POSIX locks and must
 * then be handled by the filesystem's setlock() handler.
 *
 * If not set, flock(2) calls will be handled by the FUSE kernel module
 * internally (so any access that does not go through the kernel cannot be taken
 * into account).
 */
#define FUSE_CAP_FLOCK_LOCKS		(1 << 10)

/**
 * Indicates that the filesystem supports ioctl's on directories.
 */
#define FUSE_CAP_IOCTL_DIR		(1 << 11)

/**
 * Indicates that the filesystem supports automatic invalidation of
 * cached pages.
 */
#define FUSE_CAP_AUTO_INVAL_DATA	(1 << 12)

/**
 * Indicates that the filesystem supports readdirplus
 */
#define FUSE_CAP_READDIRPLUS		(1 << 13)

/**
 * Indicates that the filesystem supports adaptive readdirplus
 */
#define FUSE_CAP_READDIRPLUS_AUTO	(1 << 14)

/**
 * Indicates that the filesystem supports asynchronous direct I/O submission.
 *
 * If this capability is not requested/available, the kernel will
 * ensure that there is at most one pending read and one pending write request per
 * direct I/O file-handle at any time.
 */
#define FUSE_CAP_ASYNC_DIO		(1 << 15)

/**
 * Indicates that writeback caching should be enabled. This means that
 * individual write request may be buffered and merged in the kernel
 * before they are send to the filesystem.
 */
#define FUSE_CAP_WRITEBACK_CACHE	(1 << 16)

/**
 * Indicates that the filesystem supports support zero-message opens.
 */
#define FUSE_CAP_NO_OPEN_SUPPORT	(1 << 17)

/**
 * Ioctl flags
 *
 * FUSE_IOCTL_COMPAT: 32bit compat ioctl on 64bit machine
 * FUSE_IOCTL_UNRESTRICTED: not restricted to well-formed ioctls, retry allowed
 * FUSE_IOCTL_RETRY: retry with new iovecs
 * FUSE_IOCTL_DIR: is a directory
 *
 * FUSE_IOCTL_MAX_IOV: maximum of in_iovecs + out_iovecs
 */
#define FUSE_IOCTL_COMPAT	(1 << 0)
#define FUSE_IOCTL_UNRESTRICTED	(1 << 1)
#define FUSE_IOCTL_RETRY	(1 << 2)
#define FUSE_IOCTL_DIR		(1 << 4)

#define FUSE_IOCTL_MAX_IOV	256

/**
 * Connection information, passed to the ->init() method
 *
 * Some of the elements are read-write, these can be changed to
 * indicate the value requested by the filesystem.  The requested
 * value must usually be smaller than the indicated value.
 */
struct fuse_conn_info {
	/**
	 * Major version of the protocol (read-only)
	 */
	unsigned proto_major;

	/**
	 * Minor version of the protocol (read-only)
	 */
	unsigned proto_minor;

	/**
	 * Maximum size of the write buffer
	 */
	unsigned max_write;

	/**
	 * Maximum size of read requests. A value of zero indicates no
	 * limit. However, even if the filesystem does not specify a
	 * limit, the maximum size of read requests will still be
	 * limited by the kernel.
	 *
	 * NOTE: For the time being, the maximum size of read requests
	 * must be set both here *and* passed to fuse_session_new()
	 * using the ``-o max_read=<n>`` mount option. At some point
	 * in the future, specifying the mount option will no longer
	 * be necessary.
	 */
	unsigned max_read;

	/**
	 * Maximum readahead
	 */
	unsigned max_readahead;

	/**
	 * Capability flags that the kernel supports (read-only)
	 */
	unsigned capable;

	/**
	 * Capability flags that the filesystem wants to enable.
	 *
	 * libfuse attempts to initialize this field with
	 * reasonable default values before calling the init() handler.
	 */
	unsigned want;

	/**
	 * Maximum number of backgrounded requests
	 */
	unsigned max_background;

	/**

	 * Kernel congestion threshold parameter
	 */
	unsigned congestion_threshold;

	/**
	 * When FUSE_CAP_WRITEBACK_CACHE is enabled, the kernel is responsible
	 * for updating mtime and ctime when write requests are received. The
	 * updated values are passed to the filesystem with setattr() requests.
	 * However, if the filesystem does not support the full resolution of
	 * the kernel timestamps (nanoseconds), the mtime and ctime values used
	 * by kernel and filesystem will differ (and result in an apparent
	 * change of times after a cache flush).
	 *
	 * To prevent this problem, this variable can be used to inform the
	 * kernel about the timestamp granularity supported by the file-system.
	 * The value should be power of 10.  A zero (default) value is
	 * equivalent to 1000000000 (1sec).
	 */
	unsigned time_gran;

	/**
	 * For future use.
	 */
	unsigned reserved[22];
};

struct fuse_session;
struct fuse_pollhandle;
struct fuse_conn_info_opts;

/**
 * This function parses several command-line options that can be used
 * to override elements of struct fuse_conn_info. The pointer returned
 * by this function should be passed to the
 * fuse_apply_conn_info_opts() method by the file system's init()
 * handler.
 *
 * Before using this function, think twice if you really want these
 * parameters to be adjustable from the command line. In most cases,
 * they should be determined by the file system internally.
 *
 * The following options are recognized:
 *
 *   -o max_write=N         sets conn->max_write
 *   -o max_readahead=N     sets conn->max_readahead
 *   -o max_background=N    sets conn->max_background
 *   -o congestion_threshold=N  sets conn->congestion_threshold
 *   -o async_read          sets FUSE_CAP_ASYNC_READ in conn->want
 *   -o sync_read           unsets FUSE_CAP_ASYNC_READ in conn->want
 *   -o atomic_o_trunc      sets FUSE_CAP_ATOMIC_O_TRUNC in conn->want
 *   -o no_remote_lock      Equivalent to -o no_remote_flock,no_remote_posix_lock
 *   -o no_remote_flock     Unsets FUSE_CAP_FLOCK_LOCKS in conn->want
 *   -o no_remote_posix_lock  Unsets FUSE_CAP_POSIX_LOCKS in conn->want
 *   -o [no_]splice_write     (un-)sets FUSE_CAP_SPLICE_WRITE in conn->want
 *   -o [no_]splice_move      (un-)sets FUSE_CAP_SPLICE_MOVE in conn->want
 *   -o [no_]splice_read      (un-)sets FUSE_CAP_SPLICE_READ in conn->want
 *   -o [no_]auto_inval_data  (un-)sets FUSE_CAP_AUTO_INVAL_DATA in conn->want
 *   -o readdirplus=no        unsets FUSE_CAP_READDIRPLUS in conn->want
 *   -o readdirplus=yes       sets FUSE_CAP_READDIRPLUS and unsets
 *                            FUSE_CAP_READDIRPLUS_AUTO in conn->want
 *   -o readdirplus=auto      sets FUSE_CAP_READDIRPLUS and
 *                            FUSE_CAP_READDIRPLUS_AUTO in conn->want
 *   -o [no_]async_dio        (un-)sets FUSE_CAP_ASYNC_DIO in conn->want
 *   -o [no_]writeback_cache  (un-)sets FUSE_CAP_WRITEBACK_CACHE in conn->want
 *   -o time_gran=N           sets conn->time_gran
 *
 * Known options will be removed from *args*, unknown options will be
 * passed through unchanged.
 *
 * @param args argument vector (input+output)
 * @return parsed options
 **/
struct fuse_conn_info_opts* fuse_parse_conn_info_opts(struct fuse_args *args);

/**
 * This function applies the (parsed) parameters in *opts* to the
 * *conn* pointer. It may modify the following fields: wants,
 * max_write, max_readahead, congestion_threshold, max_background,
 * time_gran. A field is only set (or unset) if the corresponding
 * option has been explicitly set.
 */
void fuse_apply_conn_info_opts(struct fuse_conn_info_opts *opts,
			  struct fuse_conn_info *conn);

/**
 * Go into the background
 *
 * @param foreground if true, stay in the foreground
 * @return 0 on success, -1 on failure
 */
int fuse_daemonize(int foreground);

/**
 * Get the version of the library
 *
 * @return the version
 */
int fuse_version(void);

/**
 * Get the full package version string of the library
 *
 * @return the package version
 */
const char *fuse_pkgversion(void);

/**
 * Destroy poll handle
 *
 * @param ph the poll handle
 */
void fuse_pollhandle_destroy(struct fuse_pollhandle *ph);

/* ----------------------------------------------------------- *
 * Data buffer						       *
 * ----------------------------------------------------------- */

/**
 * Buffer flags
 */
enum fuse_buf_flags {
	/**
	 * Buffer contains a file descriptor
	 *
	 * If this flag is set, the .fd field is valid, otherwise the
	 * .mem fields is valid.
	 */
	FUSE_BUF_IS_FD		= (1 << 1),

	/**
	 * Seek on the file descriptor
	 *
	 * If this flag is set then the .pos field is valid and is
	 * used to seek to the given offset before performing
	 * operation on file descriptor.
	 */
	FUSE_BUF_FD_SEEK	= (1 << 2),

	/**
	 * Retry operation on file descriptor
	 *
	 * If this flag is set then retry operation on file descriptor
	 * until .size bytes have been copied or an error or EOF is
	 * detected.
	 */
	FUSE_BUF_FD_RETRY	= (1 << 3),
};

/**
 * Buffer copy flags
 */
enum fuse_buf_copy_flags {
	/**
	 * Don't use splice(2)
	 *
	 * Always fall back to using read and write instead of
	 * splice(2) to copy data from one file descriptor to another.
	 *
	 * If this flag is not set, then only fall back if splice is
	 * unavailable.
	 */
	FUSE_BUF_NO_SPLICE	= (1 << 1),

	/**
	 * Force splice
	 *
	 * Always use splice(2) to copy data from one file descriptor
	 * to another.  If splice is not available, return -EINVAL.
	 */
	FUSE_BUF_FORCE_SPLICE	= (1 << 2),

	/**
	 * Try to move data with splice.
	 *
	 * If splice is used, try to move pages from the source to the
	 * destination instead of copying.  See documentation of
	 * SPLICE_F_MOVE in splice(2) man page.
	 */
	FUSE_BUF_SPLICE_MOVE	= (1 << 3),

	/**
	 * Don't block on the pipe when copying data with splice
	 *
	 * Makes the operations on the pipe non-blocking (if the pipe
	 * is full or empty).  See SPLICE_F_NONBLOCK in the splice(2)
	 * man page.
	 */
	FUSE_BUF_SPLICE_NONBLOCK= (1 << 4),
};

/**
 * Single data buffer
 *
 * Generic data buffer for I/O, extended attributes, etc...  Data may
 * be supplied as a memory pointer or as a file descriptor
 */
struct fuse_buf {
	/**
	 * Size of data in bytes
	 */
	size_t size;

	/**
	 * Buffer flags
	 */
	enum fuse_buf_flags flags;

	/**
	 * Memory pointer
	 *
	 * Used unless FUSE_BUF_IS_FD flag is set.
	 */
	void *mem;

	/**
	 * File descriptor
	 *
	 * Used if FUSE_BUF_IS_FD flag is set.
	 */
	int fd;

	/**
	 * File position
	 *
	 * Used if FUSE_BUF_FD_SEEK flag is set.
	 */
	off_t pos;
};

/**
 * Data buffer vector
 *
 * An array of data buffers, each containing a memory pointer or a
 * file descriptor.
 *
 * Allocate dynamically to add more than one buffer.
 */
struct fuse_bufvec {
	/**
	 * Number of buffers in the array
	 */
	size_t count;

	/**
	 * Index of current buffer within the array
	 */
	size_t idx;

	/**
	 * Current offset within the current buffer
	 */
	size_t off;

	/**
	 * Array of buffers
	 */
	struct fuse_buf buf[1];
};

/* Initialize bufvec with a single buffer of given size */
#define FUSE_BUFVEC_INIT(size__)				\
	((struct fuse_bufvec) {					\
		/* .count= */ 1,				\
		/* .idx =  */ 0,				\
		/* .off =  */ 0,				\
		/* .buf =  */ { /* [0] = */ {			\
			/* .size =  */ (size__),		\
			/* .flags = */ (enum fuse_buf_flags) 0,	\
			/* .mem =   */ NULL,			\
			/* .fd =    */ -1,			\
			/* .pos =   */ 0,			\
		} }						\
	} )

/**
 * Get total size of data in a fuse buffer vector
 *
 * @param bufv buffer vector
 * @return size of data
 */
size_t fuse_buf_size(const struct fuse_bufvec *bufv);

/**
 * Copy data from one buffer vector to another
 *
 * @param dst destination buffer vector
 * @param src source buffer vector
 * @param flags flags controlling the copy
 * @return actual number of bytes copied or -errno on error
 */
ssize_t fuse_buf_copy(struct fuse_bufvec *dst, struct fuse_bufvec *src,
		      enum fuse_buf_copy_flags flags);

/* ----------------------------------------------------------- *
 * Signal handling					       *
 * ----------------------------------------------------------- */

/**
 * Exit session on HUP, TERM and INT signals and ignore PIPE signal
 *
 * Stores session in a global variable.	 May only be called once per
 * process until fuse_remove_signal_handlers() is called.
 *
 * Once either of the POSIX signals arrives, the fuse_session_exit()
 * is called.
 *
 * @param se the session to exit
 * @return 0 on success, -1 on failure
 *
 * See also:
 * fuse_remove_signal_handlers()
 */
int fuse_set_signal_handlers(struct fuse_session *se);

/**
 * Restore default signal handlers
 *
 * Resets global session.  After this fuse_set_signal_handlers() may
 * be called again.
 *
 * @param se the same session as given in fuse_set_signal_handlers()
 *
 * See also:
 * fuse_set_signal_handlers()
 */
void fuse_remove_signal_handlers(struct fuse_session *se);

/* ----------------------------------------------------------- *
 * Compatibility stuff					       *
 * ----------------------------------------------------------- */

#if !defined(FUSE_USE_VERSION) || FUSE_USE_VERSION < 30
#  error only API version 30 or greater is supported
#endif

#ifdef __cplusplus
}
#endif


/*
 * This interface uses 64 bit off_t.
 *
 * On 32bit systems please add -D_FILE_OFFSET_BITS=64 to your compile flags!
 */

#if defined(__GNUC__) && (__GNUC__ > 4 || __GNUC__ == 4 && __GNUC_MINOR__ >= 6) && !defined __cplusplus
_Static_assert(sizeof(off_t) == 8, "fuse: off_t must be 64bit");
#else
struct _fuse_off_t_must_be_64bit_dummy_struct \
	{ unsigned _fuse_off_t_must_be_64bit:((sizeof(off_t) == 8) ? 1 : -1); };
#endif

#endif /* FUSE_COMMON_H_ */
