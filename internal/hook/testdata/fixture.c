#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#define CHECK(condition) do { if (!(condition)) { perror(#condition); return 99; } } while (0)

static void *thread_calls(void *unused) {
    (void)unused;
    for (int i = 0; i < 32; i++) {
        int fd = open("/dev/null", O_WRONLY);
        if (fd < 0) return (void *)1;
        errno = EBUSY;
        if (write(fd, "", 0) != 0 || errno != EBUSY) return (void *)1;
        if (close(fd) != 0) return (void *)1;
    }
    return NULL;
}

int main(int argc, char **argv) {
    printf("pid=%d ppid=%d\n", getpid(), getppid());
    for (int i = 0; i < argc; i++) printf("arg%d=%zu:%s\n", i, strlen(argv[i]), argv[i]);
    fflush(stdout);
    if (argc > 1 && strcmp(argv[1], "signal") == 0) {
        raise(SIGTERM);
        return 98;
    }
    char input[64];
    ssize_t size = read(STDIN_FILENO, input, sizeof(input));
    CHECK(size > 0);
    CHECK(write(STDOUT_FILENO, input, (size_t)size) == size);
    CHECK(write(STDERR_FILENO, "target stderr\n", 14) == 14);

    int fd = open("fixture file.txt", O_CREAT | O_TRUNC | O_RDWR, 0600);
    CHECK(fd >= 0);
    CHECK(write(fd, "hello", 5) == 5);
    CHECK(lseek(fd, 0, SEEK_SET) == 0);
    char data[8] = {0};
    CHECK(read(fd, data, 5) == 5);
    CHECK(strcmp(data, "hello") == 0);
    struct stat st;
    CHECK(fstat(fd, &st) == 0);
    CHECK((st.st_mode & 0777) == 0600);
    errno = EBUSY;
    CHECK(write(fd, "", 0) == 0);
    CHECK(errno == EBUSY);
    CHECK(close(fd) == 0);
    fd = openat(AT_FDCWD, "fixture file.txt", O_RDONLY);
    CHECK(fd >= 0);
    CHECK(close(fd) == 0);
    fd = openat(AT_FDCWD, "created at.txt", O_CREAT | O_WRONLY, 0640);
    CHECK(fd >= 0);
    CHECK(close(fd) == 0);
    CHECK(open("missing-file", O_RDONLY) == -1 && errno == ENOENT);
    CHECK(write(-1, "", 0) == -1 && errno == EBADF);
    CHECK(open((const char *)(uintptr_t)1, O_RDONLY) == -1 && errno == EFAULT);
    CHECK(rename("fixture file.txt", "renamed.txt") == 0);
    CHECK(unlink("renamed.txt") == 0);
    CHECK(unlink("created at.txt") == 0);

    void *memory = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    CHECK(memory != MAP_FAILED);
    CHECK(mprotect(memory, 4096, PROT_READ) == 0);
    CHECK(munmap(memory, 4096) == 0);

    int server = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(server >= 0);
    struct sockaddr_in address = {.sin_len = sizeof(address), .sin_family = AF_INET};
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    CHECK(bind(server, (const struct sockaddr *)&address, sizeof(address)) == 0);
    CHECK(listen(server, 1) == 0);
    socklen_t address_size = sizeof(address);
    CHECK(getsockname(server, (struct sockaddr *)&address, &address_size) == 0);
    int client = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(client >= 0);
    CHECK(connect(client, (const struct sockaddr *)&address, sizeof(address)) == 0);
    int peer = accept(server, NULL, NULL);
    CHECK(peer >= 0);
    CHECK(send(client, "test", 4, 0) == 4);
    CHECK(recv(peer, data, sizeof(data), 0) == 4);
    CHECK(close(peer) == 0);
    CHECK(close(client) == 0);
    CHECK(close(server) == 0);
    pthread_t threads[4];
    for (int i = 0; i < 4; i++) CHECK(pthread_create(&threads[i], NULL, thread_calls, NULL) == 0);
    for (int i = 0; i < 4; i++) {
        void *result = NULL;
        CHECK(pthread_join(threads[i], &result) == 0 && result == NULL);
    }
    return 23;
}
