#include <linux/ioctl.h>

/* IOCTL definitions */
#define AMFS_IOCTL_MAGIC_NUMBER		0xFE
#define AMFS_IOCTL_LIST_PATTERNS	_IOR(AMFS_IOCTL_MAGIC_NUMBER, 0, char*)
#define AMFS_IOCTL_ADD_PATTERN		_IOW(AMFS_IOCTL_MAGIC_NUMBER, 1, char*)
#define AMFS_IOCTL_DELETE_PATTERN	_IOW(AMFS_IOCTL_MAGIC_NUMBER, 2, char*)

#define PATTERN_DOES_NOT_EXIST	0x1000
#define PATTERN_IS_DUPLICATE	0x1001

#define TOTAL_PATTERN_SIZE 4096