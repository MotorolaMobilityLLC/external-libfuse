Unreleased Changes
==================

* The ``fuse_lowlevel_notify_*`` functions now all take a `struct
  fuse_session` parameter instead of a `struct fuse_chan`.

* The channel interface (``fuse_chan_*`` functions) has been
  made private. The `struct fuse_chan_ops` data structure is now
  opaque.

* Added *clone_fd* option.  This creates a separate device file
  descriptor for each processing thread, which might improve
  performance.

* The (high- and low-level) `rename` handlers now takes a *flags*
  parameter (with values corresponding to the *renameat2* system call
  introduced in Linux 3.15).

* The "ulockmgr_server" has been dropped.

* There is a new (low-level) `readdirplus` handler, with a
  corresponding example in ``examples/fuse_lo-plus.c`` and a new
  `fuse_add_direntry_plus` API function.

* The (high-level) `readdir` handler now takes a *flags* argument.

* The (high-level) `filler` function passed to `readdir` now takes an
  additional *flags* argument.

* The (high-level) `getdir` handler has been dropped.

* The *flag_nullpath_ok* and *flag_utime_omit_ok* flags have been
  dropped.

* The (high-level) *utime* handler has been dropped.

* The `fuse_invalidate` function has been removed.

* The `fuse_is_lib_option` function has been removed.

* The *fh_old* member of `struct fuse_file_info` has been dropped.

* The type of the *writepage* member of `struct fuse_file_info` was
  changed from *int* to *unsigned int*.

* The `struct fuse_file_info` gained a new *poll_events* member.

* There is a new `fuse_pkgversion` function.

* The *fuse_off_t* and *fuse_ino_t* changed from *unsigned long* to
  *uint64_t*, i.e. they are now 64 bits also on 32-bit systems.

* The type of the *generation* member of `struct fuse_entry_param*
  changed from *unsigned* to *uint64_t*.

* The (low-level) `setattr` handler gained a *FUSE_SET_ATTR_CTIME* bit
  *for its *to_set* parameter.

* The `struct fuse_session_ops` data structure has been dropped.

* The documentation has been clarified and improved in many places.


FUSE 2.9.7 (2016-06-20)
=======================

* Added SELinux support.
* Fixed race-condition when session is terminated right after starting
  a FUSE file system.

FUSE 2.9.6 (2016-04-23)
=======================

* Tarball now includes documentation.
* Shared-object version has now been bumped correctly.

FUSE 2.9.5 (2016-01-14)
=======================

* New maintainer: Nikolaus Rath <Nikolaus@rath.org>. Many thanks to
  Miklos Szeredi <miklos@szeredi.hu> for bringing FUSE to where it is
  now!

* fix warning in mount.c:receive_fd().  Reported by Albert Berger

* fix possible memory leak.  Reported by Jose R. Guzman

FUSE 2.9.4 (2015-05-22)
=======================

* fix exec environment for mount and umount.  Found by Tavis Ormandy
  (CVE-2015-3202).

* fix fuse_remove_signal_handlers() to properly restore the default
  signal handler.  Reported by: Chris Johnson

* highlevel API: fix directory file handle passed to ioctl() method.
  Reported by Eric Biggers

* libfuse: document deadlock avoidance for fuse_notify_inval_entry()
  and fuse_notify_delete()

* fusermount, libfuse: send value as unsigned in "user_id=" and
  "group_id=" options.  Uids/gids larger than 2147483647 would result
  in EINVAL when mounting the filesystem.  This also needs a fix in
  the kernel.

* Initilaize stat buffer passed to ->getattr() and ->fgetattr() to
  zero in all cases.  Reported by Daniel Iwan

* libfuse: Add missing includes.  This allows compiling fuse with
  musl.  Patch by Daniel Thau


Older Versions (before 2013-01-01)
==================================

Please see Git history, e.g. at
https://github.com/libfuse/libfuse/blob/fuse_2_9_3/ChangeLog.
