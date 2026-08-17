#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void handle_request(char *input) {
    char *buf = malloc(64);
    if (!buf) return;
    strcpy(buf, input);
    printf("handled: %s\n", buf);
    free(buf);
}

int main(void) {
    char *line = NULL;
    size_t cap = 0;
    ssize_t n = getline(&line, &cap, stdin);
    if (n > 0) {
        handle_request(line);
    }
    free(line);
    return 0;
}
