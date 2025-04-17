#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#pragma warning(disable : 4996) // Disable the security warning for strcpy.  THIS IS UNSAFE.

int main() {
    // Vulnerable buffer:  size is 10, but we'll write more.
    char buffer[10];
    // Large input string, designed to overflow 'buffer'
    char* input = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    printf("Starting program\n");

    // The vulnerability: strcpy does not check the size of the input
    // and will write past the end of 'buffer'.  THIS IS THE PROBLEM.
    strcpy(buffer, input);

    printf("Copied string: %s\n", buffer); // This might crash, or print garbage.

    printf("Program finished\n");
    return 0;
}