#!/bin/bash

threads='1 2 4 8 16 32 64 128 256 512 1024'
nvcc --device-c main.cu md5.cu
nvcc main.o md5.o
for thread in $threads
do
    echo -e $thread threads:
    time ./a.out aaaa00 'hashes 1e5.txt' $thread
    echo -e '\n---------------------------------\n'
done