#! /bin/sh

destdir=$1

if test ! -d "$destdir"; then
    printf "Usage: %s destination_directory\n" $0
    exit 1
fi
if test "$destdir" = "."; then
    echo "Not overwriting contents of original directory"
    exit 1
fi

for f in dev.c dir.c file.c inode.c util.c fuse_i.h; do
    unifdef -DKERNEL_2_6 -DKERNEL_2_6_6_PLUS -DKERNEL_2_6_10_PLUS -DHAVE_KERNEL_XATTR -DFS_SAFE -DMAX_LFS_FILESIZE -DFUSE_MAINLINE -DBUG_ON -DHAVE_FS_SUBSYS -D__user -DMODULE_LICENSE $f > $destdir/$f
done
