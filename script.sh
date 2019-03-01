#Put flag in true to run that version
SEC_FLAG=tru
OMP_FLAG=tru
CUDA_FLAG=tru
MPI_FLAG=tru
OCL_FLAG=true

TIMEFORMAT=%R
ITER=5
format=aaaaa
threads1='1 2 4 8 16 32 64'
threads2='1 2 4 8 16 32 64 128 256 512 1024 2048 4096 8192'
blocks='13 26 39 52 65 78 91'
workgroups='32 64 96 128 160'
#################### Secuencial ######################
if [ $SEC_FLAG = true ]; then
    echo "Running sequential version ..."
    > secuencial_output
    cd Secuencial
    g++ main.cpp md5.cpp -o a
    for((i=0;i<ITER;++i)); do
        { time ./a $format hashes\ 1e5.txt; } 2>> ../secuencial_output 1> ../tempout
    done
    cd ..
fi
###################### OpenMP ########################
if [ $OMP_FLAG = true ]; then
    echo "Running OpenMP version ..."
    > openmp_output
    cd OpenMP
    g++ main.cpp md5.cpp -o a -fopenmp
    for thread in $threads1; do
        echo "Running with $thread thread(s) ..."
        echo "Number: $thread" >> ../openmp_output
        for((i=0;i<ITER;++i)); do
            #{ time ./a $format hashes\ 1e5.txt $thread; } 2>> ../openmp_output 1> ../tempout
            time ./a $format hashes\ 1e5.txt $thread
        done
    done
    cd ..
fi
###################### MPI ########################
if [ $MPI_FLAG = true ]; then
    echo "Running MPI version ..."
    > mpi_output
    cd MPI
    mpic++ -o a main.cpp md5.cpp
    for thread in $threads1; do
        echo "Running with $thread process(es) ..."
        echo "Number: $thread" >> ../mpi_output
        for((i=0;i<ITER;++i)); do
            { time mpirun --allow-run-as-root -np $thread a $format hashes\ 1e5.txt; } 2>> ../mpi_output 1> ../tempout
        done
    done
    cd ..
fi
###################### OpenCL ########################
if [ $OCL_FLAG = true ]; then
    echo "Running OpenCL version ..."
    > ocl_output
    cd OpenCL
    #g++ main.cpp -o a -l OpenCL
    for wg in $workgroups; do
        for thread in $threads2; do
            echo "Running with $thread work item(s) ..."
            echo "Number: $thread Groups: $wg" >> ../ocl_output
            for((i=0;i<ITER;++i)); do
                { time ./a $format hashes\ 1e5.txt $thread $wg; } 2>> ../ocl_output 1> ../tempout 1> ../tempout
            done
        done
    done
    cd ..
fi
###################### CUDA ########################
if [ $CUDA_FLAG = true ]; then
    echo "Running CUDA version ..."
    > cuda_output
    cd CUDA
    nvcc --device-c main.cu md5.cu
    nvcc main.o md5.o
    for block in $blocks; do
      for thread in $threads2; do
          echo "Running with $block block(s) and $thread total thread(s) ..."
          echo "Number: $thread Blocks: $block" >> ../cuda_output
          for((i=0;i<ITER;++i)); do
              { time ./a.out $format 'hashes 1e5.txt' $thread $block; } 2>> ../cuda_output 1> ../tempout
          done
      done
    done
    cd ..
fi

#Get Graphics
#mkdir Graphics
#python2 GraphicsGenerator.py