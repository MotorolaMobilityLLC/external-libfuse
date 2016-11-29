libfuse
=======

Warning: unresolved security issue
----------------------------------

Be aware that FUSE has an unresolved security bug
([bug #15](https://github.com/libfuse/libfuse/issues/15)): if the
`default_permissions` mount option is not used, the results of the
first permission check performed by the file system for a directory
entry will be re-used for subsequent accesses as long as the inode of
the accessed entry is present in the kernel cache - even if the
permissions have since changed, and even if the subsequent access is
made by a different user.

This bug needs to be fixed in the Linux kernel and has been known
since 2006 but unfortunately no fix has been applied yet. If you
depend on correct permission handling for FUSE file systems, the only
workaround is to use `default_permissions` (which does not currently
support ACLs), or to completely disable caching of directory entry
attributes. Alternatively, the severity of the bug can be somewhat
reduced by not using the `allow_other` mount option.


About
-----

FUSE (Filesystem in Userspace) is an interface for userspace programs
to export a filesystem to the Linux kernel. The FUSE project consists
of two components: the *fuse* kernel module (maintained in the regular
kernel repositories) and the *libfuse* userspace library (maintained
in this repository). libfuse provides the reference implementation
for communicating with the FUSE kernel module.

A FUSE file system is typically implemented as a standalone
application that links with libfuse. libfuse provides functions to
mount the file system, unmount it, read requests from the kernel, and
send responses back. libfuse offers two APIs: a "high-level",
synchronous API, and a "low-level" asynchronous API. In both cases,
incoming requests from the kernel are passed to the main program using
callbacks. When using the high-level API, the callbacks may work with
file names and paths instead of inodes, and processing of a request
finishes when the callback function returns. When using the low-level
API, the callbacks must work with inodes and responses must be sent
explicitly using a separate set of API functions.


Installation
------------

You can download libfuse from
https://github.com/libfuse/libfuse/releases. After extracting the
tarball, build and install with

    ./configure
    make -j8
    make install

To run some self tests, you need a Python 3 environment with the
[py.test](http://www.pytest.org/) module installed. To run the tests,
execute

    python3 -m pytest test/

You may also need to add `/usr/local/lib` to `/etc/ld.so.conf` and/or
run *ldconfig*. If you're building from the git repository (instead of
using a release tarball), you also need to run `./makeconf.sh` to
create the `configure` script.

You'll also need a fuse kernel module (Linux kernels 2.6.14 or later
contain FUSE support).

Security implications
---------------------

If you run `make install`, the *fusermount3* program is installed
set-user-id to root.  This is done to allow normal users to mount
their own filesystem implementations.

There must however be some limitations, in order to prevent Bad User from
doing nasty things.  Currently those limitations are:

  - The user can only mount on a mountpoint, for which it has write
    permission

  - The mountpoint is not a sticky directory which isn't owned by the
    user (like /tmp usually is)

  - No other user (including root) can access the contents of the
    mounted filesystem (though this can be relaxed by allowing the use
    of the `allow_other` and `allow_root` mount options in `fuse.conf`)


Building your own filesystem
------------------------------

FUSE comes with several example file systems in the `examples`
directory. For example, the *passthrough* examples mirror the contents
of the root directory under the mountpoint. Start from there and adapt
the code!

The documentation of the API functions and necessary callbacks is
mostly contained in the files `include/fuse.h` (for the high-level
API) and `include/fuse_lowlevel.h` (for the low-level API). An
autogenerated html version of the API is available in the `doc/html`
directory and at http://libfuse.github.io/doxygen.


Getting Help
------------

If you need help, please ask on the <fuse-devel@lists.sourceforge.net>
mailing list (subscribe at
https://lists.sourceforge.net/lists/listinfo/fuse-devel).

Please report any bugs on the GitHub issue tracker at
https://github.com/libfuse/libfuse/issues.
