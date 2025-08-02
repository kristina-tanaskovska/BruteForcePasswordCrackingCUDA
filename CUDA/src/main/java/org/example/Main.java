package org.example;

import jcuda.driver.JCudaDriver;
public class Main {
    public static void main(String[] args) {
        JCudaDriver.setExceptionsEnabled(true);
        JCudaDriver.cuInit(0);
        System.out.println("JCuda initialized successfully!");
    }
}