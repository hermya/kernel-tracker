#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

int main(int argc, char *argv[]) {
    // Check if a file name was passed as an argument
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <file_name>\n", argv[0]);
        return 1;
    }

    // Open the file
    FILE *file = fopen(argv[1], "r");
    if (file == NULL) {
        perror("Error opening file");
        return 1;
    }

    // Initialize the sum variable
    unsigned long sum = 0;
    unsigned long time_start, y, z, a;
    unsigned long time_end;
    bool started = false;

    // Read each line and process it
    while (fscanf(file, "%lu %lu %lu %lu", &time_end, &y, &z, &a) == 4) {
        // Add the value of A to the sum
        if (!started) {
            started = true;
            time_start = time_end;
        }
        sum += a;
    }

    // Close the file
    fclose(file);

    // Output the total sum of A values
    printf("The total cpu util = %lu\n", sum);
    printf("The total wall time = %lu\n", time_end - time_start);

    return 0;
}