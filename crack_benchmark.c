/* crack_benchmark.c
 *
 * A fake DES-cracking program to measure the performance of the DES encryption
 * code.  Measures the performance for 10 seconds, then outputs performance
 * data as well as an estimate for how long it would take to brute-force crack
 * a 56-bit encryption key.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/time.h>
#include <unistd.h>
#include <pthread.h>
#include <math.h>

#include "des.h"

#define NUM_THREADS 8
#define KEYS_PER_THREAD 0x01000000
#define CIPHER 0xF908CE9176A1B7D2ll
#define PLAIN  0x9AB80F3E45C37D25ll 

typedef struct crack_state {
    pthread_t thread_id;
    uint64_t start_key;
    uint64_t end_key;
    uint64_t cipher;
    uint64_t plain;
    uint64_t attempts;
    int stop;
} CrackState;

void *crack_thread(void *in)
{
    CrackState *state = (CrackState *)in;
    uint64_t keyval;
    DES_Key key;

    for (keyval = state->start_key; !state->stop && keyval != state->end_key; keyval++) {
        DES_InitKey(&key, keyval);
        if (DES_Decrypt(&key, state->cipher) == state->plain) {
            printf("Found Key: %016lld\n", keyval);
        }
        state->attempts++;
    }

    return 0;
}

int main(void)
{
    CrackState threads[NUM_THREADS];

    int i, j;
    struct timeval tv_start, tv_last, tv_end;
    int total_keys, last_keys = 0, cur_keys = 0;
    double t_diff, rate;
    double est_seconds;
    double est_days;
    int est_years;

    for (i = 0; i < NUM_THREADS; i++) {
        threads[i].start_key = i * KEYS_PER_THREAD;
        threads[i].end_key = (i + 1) * KEYS_PER_THREAD;
        threads[i].cipher = CIPHER;
        threads[i].plain = PLAIN;
        threads[i].attempts = 0;
        threads[i].stop = 0;
    }

    gettimeofday(&tv_start, NULL);
    tv_last = tv_start;

    for (i = 0; i < NUM_THREADS; i++) {
        if (pthread_create(&threads[i].thread_id, NULL, crack_thread, &threads[i])) {
            fprintf(stderr, "Failed to start thread %d\n", i+1);
        }
    }

    for (i = 0; i < 10; i++) {
        sleep(1);

        total_keys = 0;
        for (j = 0; j < NUM_THREADS; j++) {
            total_keys += threads[j].attempts;
        }
        
        gettimeofday(&tv_end, NULL);

        t_diff = tv_end.tv_sec - tv_last.tv_sec + (double)(tv_end.tv_usec - tv_last.tv_usec) / 1000000.0;
        cur_keys = total_keys - last_keys;
        rate = cur_keys / t_diff;
        printf("%d keys in %.3lf seconds: %.2lf keys/sec\n", cur_keys, t_diff, rate);

        tv_last = tv_end;
        last_keys = total_keys;
    }

    t_diff = tv_end.tv_sec - tv_start.tv_sec + (double)(tv_end.tv_usec - tv_start.tv_usec) / 1000000.0;
    rate = total_keys / t_diff;

    est_seconds = pow(2.0, 56.0) / rate;
    est_days = est_seconds / (24 * 60 * 60);
    est_years = (int)(est_days / 365.0);
    est_days = fmod(est_days, 365.0);

    printf("AVERAGE: %d keys in %.3lf seconds: %.2lf keys/sec\n", total_keys, t_diff, rate);
    printf("(Estimated time to crack 56-bit key: %d years, %.3f days.)\n", est_years, est_days);

    for (i = 0; i < NUM_THREADS; i++) {
        threads[i].stop = 1;
        pthread_join(threads[i].thread_id, NULL);
    }

    return EXIT_SUCCESS;
}
