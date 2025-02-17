#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

#define PROC_FILE_PATH "/proc/uptime/status"

int write_pid_to_mp1_status_proc(int pid) {

    char pid_buff[16];
    int pid_len;
    int write_status;
    int fd; // file descriptor

    fd = open(PROC_FILE_PATH, O_WRONLY, 0666);

    if (fd == -1) {
        perror("Error opening file for writing");
        return EXIT_FAILURE;
    }

    pid_len = sprintf(pid_buff, "%d", pid);

    write_status = write(fd, pid_buff, pid_len);

    if (write_status == -1) {
        perror("Error writing to file");
        close(fd);
        return EXIT_FAILURE;
    }

    close(fd);

    return 0;
}

int read_from_mp1_status_proc() {
    char read_buff[3900];
    int pid_len;
    int read_status;

    int fd; // file descriptor

    memset(read_buff, 0, sizeof(read_buff));

    fd = open(PROC_FILE_PATH, O_RDONLY);

    if (fd == -1) {
        perror("Error opening file for reading");
        return EXIT_FAILURE;
    }


    read_status = read(fd, read_buff, sizeof(read_buff) - 1);

    if (read_status == -1) {
        perror("Error reading form file");
        return EXIT_FAILURE;
    }

    for (int i = 0; i < read_status; i++) {
        printf("%c", read_buff[i]);
    }

    close(fd);

    return 0;
}

int main(void)
{
    // Please tweak the iteration counts to make this calculation run long enough

    pid_t pid = getpid();

    if (write_pid_to_mp1_status_proc(pid)) {
        return 1;
    }

    volatile long long unsigned int sum = 0;
    for (int i = 0; i < 100000000; i++) {
        volatile long long unsigned int fac = 1;
        for (int j = 1; j <= 50; j++) {
            fac *= j;
        }
        sum += fac;
    }

    if (read_from_mp1_status_proc()) {
        return 1;
    }
    
    return 0;
}
