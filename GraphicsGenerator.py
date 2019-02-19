import os
import matplotlib.pyplot as plt

def getGraphic(toolName, timesFile, xAxisName, secTime):
    numbers = []
    times = []
    file = open(timesFile)
    acc = cnt = 0
    for line in file:
        if line[0] == "N":
            if cnt != 0:
                times.append(acc/cnt)
            numbers.append( int(line.split()[1]) )
            acc = cnt = 0
        else:
            acc += float(line)
            cnt += 1
    times.append(acc/cnt)
    #Time graphic
    plt.xticks( numbers )
    plt.ylabel( "Time (s)" )
    plt.xlabel( xAxisName )
    plt.title( "Execution time (" + toolName + ")" )
    plt.plot( numbers, times )
    #plt.show()
    plt.savefig( "Graphics/"+toolName+"Time" )
    plt.clf()
    #Speedup graphic
    speedup = map(lambda x: secTime/x, times)
    plt.xticks( numbers )
    plt.xlabel( xAxisName )
    plt.title( "Speedup (" + toolName + ")" )
    plt.plot( numbers, speedup )
    #plt.show()
    plt.savefig( "Graphics/"+toolName+"Speedup" )
    plt.clf()
    
    

if not os.path.isfile("secuencial_output"):
    print "Not secuential time found"
    exit()
file = open( "secuencial_output", "r" )
secTime = float(file.readline())

if os.path.isfile("openmp_output"):
    getGraphic("OpenMP", "openmp_output", "Threads", secTime)
if os.path.isfile("cuda_output"):
    getGraphic("CUDA", "cuda_output", "Threads", secTime)
if os.path.isfile("mpi_output"):
    getGraphic("MPI", "mpi_output", "Processes", secTime)
if os.path.isfile("ocl_output"):
    getGraphic("OpenCL", "ocl_output", "Work Items", secTime)