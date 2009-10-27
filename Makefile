# vim: smarttab noexpandtab tabstop=4 shiftwidth=4

CFLAGS=-O3
LDFLAGS=-lm -lpthread
CC=cc
LD=cc

libs=des_key.o des_crypt.o
crack_libs=$(libs) crack_benchmark.o
test_libs=$(libs) test.o

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@

all: crack_benchmark test

crack_benchmark: $(crack_libs)
	$(LD) $(LDFLAGS) $^ -o $@

test: $(test_libs)
	$(LD) $(LDFLAGS) $^ -o $@

des_key.o: des_key.c des.h
des_crypt.o: des_crypt.c des.h
crack_benchmark.o: crack_benchmark.c des.h

clean:
	rm -f *.o
	rm -f crack_benchmark
	rm -f test
