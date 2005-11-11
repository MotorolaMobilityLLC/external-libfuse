/*
    FUSE: Filesystem in Userspace
    Copyright (C) 2001-2005  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU LGPL.
    See the file COPYING.LIB.
*/

#if !defined(_FUSE_H_) && !defined(_FUSE_LOWLEVEL_H_)
#error "Never include <fuse_common.h> directly; use <fuse.h> or <fuse_lowlevel.h instead."
#endif

#ifndef _FUSE_COMMON_H_
#define _FUSE_COMMON_H_

#include <stdint.h>

/** Major version of FUSE library interface */
#define FUSE_MAJOR_VERSION 2

/** Minor version of FUSE library interface */
#define FUSE_MINOR_VERSION 5

#define FUSE_MAKE_VERSION(maj, min)  ((maj) * 10 + (min))
#define FUSE_VERSION FUSE_MAKE_VERSION(FUSE_MAJOR_VERSION, FUSE_MINOR_VERSION)

/* This interface uses 64 bit off_t */
#if _FILE_OFFSET_BITS != 64
#error Please add -D_FILE_OFFSET_BITS=64 to your compile flags!
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Information about open files
 *
 * Changed in version 2.5
 */
struct fuse_file_info {
    /** Open flags.  Available in open() and release() */
    int flags;

    /** Old file handle, don't use */
    unsigned long fh_old;

    /** In case of a write operation indicates if this was caused by a
        writepage */
    int writepage;

    /** Can be filled in by open, to use direct I/O on this file.
        Introduced in version 2.4 */
    unsigned int direct_io : 1;

    /** Can be filled in by open, to indicate, that cached file data
        need not be invalidated.  Introduced in version 2.4 */
    unsigned int keep_cache : 1;

    /** Padding.  Do not use*/
    unsigned int padding : 30;

    /** File handle.  May be filled in by filesystem in open().
        Available in all other file operations */
    uint64_t fh;
};

/*
 * Create a FUSE mountpoint
 *
 * Returns a control file descriptor suitable for passing to
 * fuse_new()
 *
 * @param mountpoint the mount point path
 * @param opts a comma separated list of mount options.  Can be NULL.
 * @return the control file descriptor on success, -1 on failure
 */
int fuse_mount(const char *mountpoint, const char *opts);

/*
 * Umount a FUSE mountpoint
 *
 * @param mountpoint the mount point path
 */
void fuse_unmount(const char *mountpoint);

#ifdef __cplusplus
}
#endif

#endif /* _FUSE_COMMON_H_ */
