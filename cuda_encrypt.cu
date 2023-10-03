#include <cuda.h>
#include "cuda_runtime.h"
#include "device_launch_parameters.h"

__global__ void encrypt_kernel(const uchar* plaintext, uchar* ciphertext, 
                                uint8_t* key, int length) {

  int i = blockIdx.x * blockDim.x + threadIdx.x;

  if (i < length) {
    ciphertext[i] = plaintext[i] ^ key[i]; 
  }

}

void encrypt(uchar* plaintext, uchar* ciphertext, uint8_t* key, int length) {

  uchar* device_plaintext;
  uchar* device_ciphertext;
  uint8_t* device_key;
  
  // Allocate GPU memory
  cudaMalloc(&device_plaintext, length);
  cudaMalloc(&device_ciphertext, length);
  cudaMalloc(&device_key, length);

  // Copy data to GPU
  cudaMemcpy(device_plaintext, plaintext, length, 
             cudaMemcpyHostToDevice);
  cudaMemcpy(device_key, key, length, 
             cudaMemcpyHostToDevice);
             
  // Launch encryption kernel
  dim3 threads(256);
  dim3 blocks((length + threads.x - 1) / threads.x);
  encrypt_kernel<<<blocks, threads>>>(device_plaintext, device_ciphertext, 
                                      device_key, length);

  // Copy encrypted data back to CPU
  cudaMemcpy(ciphertext, device_ciphertext, length, 
             cudaMemcpyDeviceToHost);

  // Free GPU memory
  cudaFree(device_plaintext);
  cudaFree(device_ciphertext);
  cudaFree(device_key);

}