#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "amfsctl.h"
#include <sys/ioctl.h>
#include <fcntl.h>
#include <errno.h>

//ToDo change display_usage
void display_usage()
{
    printf("Name:amfctl\n");
    printf("Mandatory args:\n");
    printf("mount point, \t\tThe mount point of the new file system\n");
    printf("Optional args:\n");
    printf("-h, \t\tto display this help message\n");
	printf("-a ARG \t\tthe pattern to add\n");
	printf("-r ARG \t\tthe pattern to be removed\n");
	printf("-l \t\tList the patterns\n");
}

int main(int argc, char **argv)
{
	char *pattern = NULL;
	int fd = -1, c, err;
	printf("Mount point is: %s\n", argv[argc-1]);
	fd = open(argv[argc-1], O_RDONLY);

    if(argc <3 && argc >4)
    {
        errno = EINVAL;
        perror("Incorrect number of arguments passed, please see help below");
        display_usage();
        return -1;
    }
    while ((c = getopt (argc, argv, "la:r:")) != -1)
    {
        switch (c)
        {
            case 'l':
				printf("Listing patterns\n");
				pattern = (char*)malloc(TOTAL_PATTERN_SIZE);
				if(ioctl(fd, AMFS_IOCTL_LIST_PATTERNS, pattern) == 0)
					printf("%s", pattern);
                break;
            case 'a':
				pattern = optarg;
				printf("Adding pattern: %s\n", pattern);
				err = ioctl(fd, AMFS_IOCTL_ADD_PATTERN, pattern);
				if(err < 0)
				{
					perror("Pattern already exists");
					errno = EINVAL;
				}
                break;
            case 'r':
                pattern = optarg;
				printf("Removing pattern: %s\n", pattern);
				err = ioctl(fd, AMFS_IOCTL_DELETE_PATTERN, pattern);
				if(err < 0)
				{
                    perror("Pattern does not exist");
					errno = EINVAL;
				}
                break;
            case 'h':
                display_usage();
                break;
            case '?':
                errno = EINVAL;
                if (optopt == 'a')
                    perror("Option -a requires an argument");
                else if(optopt == 'r')
                    perror("Option -r requires an argument");
                else
                    perror("Unknown option character");
				display_usage();
                return -1;
            default:
				break;
        }
    }
	return 0;
}
