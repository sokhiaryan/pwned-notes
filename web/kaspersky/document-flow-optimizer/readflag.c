#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    if (argc != 2 || strcmp(argv[1], "please") != 0) {
        fprintf(stderr, "Usage: /readflag please\n");
        return 1;
    }

    setuid(0);
    setgid(0);

    FILE *f = fopen("/flag.txt", "r");
    if (!f) {
        perror("fopen");
        return 1;
    }

    char buf[4096];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    buf[n] = '\0';
    fclose(f);

    printf("%s\n", buf);
    return 0;
}
