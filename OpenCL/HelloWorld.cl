__kernel void HelloWorld(__global int* data, __global int* outData){
    outdata[get_global_id(0)] = data[get_global_id(0)] * 2;
}