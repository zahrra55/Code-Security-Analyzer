#include <stdio.h>
#include <string.h>

void vulnerable_function(char *input) {
    char buffer[10];
    strcpy(buffer, input);
    printf("Buffer content: %s\n", buffer);
}

int main() {
    char input[100];
    printf("Enter some text: ");
    gets(input);
    vulnerable_function(input);
    return 0;
}