import os
import matplotlib.pyplot as plt

def getGraphic(toolName, timesFile, xAxisName, secTime, legendName=""):
    numbers = []
    blocks = []
    times = []
    file = open(timesFile)
    acc = cnt = 0
    prevBlock = -1
    for line in file:
        if line[0] == "N":
            lineArr = line.split()
            if len(lineArr) == 2:
                if cnt != 0:
                    times.append(acc/cnt)
                numbers.append( int(lineArr[1]) )
                acc = cnt = 0
            else:
                th = int(lineArr[1])
                bl = int(lineArr[3])
                if cnt != 0:
                    times[-1].append(acc/cnt)
                if bl != prevBlock:
                    blocks.append(bl)
                    numbers.append([])
                    times.append([])
                    prevBlock = bl
                numbers[-1].append(th)
                acc = cnt = 0
        else:
            acc += float(line)
            cnt += 1
    if len(blocks) == 0:
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
    else:
        #Time graphic
        times[-1].append(acc/cnt)
        #plt.xticks( [256,1024,2048,4096,8192] )
        plt.xticks( numbers[0] )
        plt.ylabel( "Time (s)" )
        plt.xlabel( xAxisName )
        plt.title( "Execution time (" + toolName + ")" )
        for i in range(len(blocks)):
            plt.plot(numbers[i], times[i], label=str(blocks[i]) + " " + legendName)
        plt.legend()
        #plt.show()
        plt.savefig( "Graphics/"+toolName+"Time" )
        plt.clf()
        #Speedup graphic
        speedup = []
        for time in times:
            speedup.append([])
            speedup[-1] = map(lambda x: secTime/x, time)
        #plt.xticks( [256, 1024, 2048, 4096, 8192] )
        plt.xticks( numbers[0] )
        plt.xlabel( xAxisName )
        plt.title( "Speedup (" + toolName + ")" )
        for i in range(len(blocks)):
            plt.plot(numbers[i], speedup[i], label=str(blocks[i]) + " " + legendName)
        plt.legend()
        #plt.show()
        plt.savefig( "Graphics/"+toolName+"Speedup" )
        plt.clf()
    

if not os.path.isfile("secuencial_output"):
    print "Not secuential time found"
    exit()
file = open( "secuencial_output", "r" )
secTime = float(file.readline())

'''if os.path.isfile("openmp_output"):
    getGraphic("OpenMP", "openmp_output", "Threads", secTime)'''
'''if os.path.isfile("cuda_output"):
    getGraphic("CUDA", "cuda_output", "Total threads", secTime, "blocks")'''
'''if os.path.isfile("mpi_output"):
    getGraphic("MPI", "mpi_output", "Processes", secTime)'''
if os.path.isfile("ocl_output"):
    getGraphic("OpenCL", "ocl_output", "Total work Items", secTime, "work groups")