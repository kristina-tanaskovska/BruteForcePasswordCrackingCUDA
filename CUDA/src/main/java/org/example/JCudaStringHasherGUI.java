package org.example;

import javax.swing.*;
import java.awt.GridBagLayout;
import java.awt.GridBagConstraints;
import java.awt.Insets;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import jcuda.Pointer;
import jcuda.Sizeof;
import jcuda.driver.CUcontext;
import jcuda.driver.CUdevice;
import jcuda.driver.CUdevice_attribute;
import jcuda.driver.CUdeviceptr;
import jcuda.driver.CUfunction;
import jcuda.driver.CUmodule;
import jcuda.driver.JCudaDriver;
import jcuda.nvrtc.JNvrtc;
import jcuda.nvrtc.nvrtcProgram;
import static jcuda.driver.JCudaDriver.*;
import static jcuda.nvrtc.JNvrtc.*;
import static jcuda.nvrtc.nvrtcResult.NVRTC_SUCCESS;

public class JCudaStringHasherGUI {
    private static String targetHash = "";

    public static void main(String[] args) {
        SwingUtilities.invokeLater(JCudaStringHasherGUI::createAndShowGUI);
    }

    static void createAndShowGUI() {
        JFrame frame = new JFrame("JCuda String Hasher");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setLayout(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5,5,5,5);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        // File chooser
        gbc.gridx = 0; gbc.gridy = 0;
        JTextField fileField = new JTextField(20);
        fileField.setEditable(false);
        gbc.gridx = 1;
        frame.add(fileField, gbc);
        JButton browseBtn = new JButton("Browse for dictionary");
        gbc.gridx = 2;
        frame.add(browseBtn, gbc);
        browseBtn.addActionListener(e -> {
            JFileChooser chooser = new JFileChooser();
            if (chooser.showOpenDialog(frame) == JFileChooser.APPROVE_OPTION) {
                fileField.setText(chooser.getSelectedFile().getAbsolutePath());
            }
        });

        // Target hash
        gbc.gridx = 0; gbc.gridy = 1;
        frame.add(new JLabel("Target Hash (hex):"), gbc);
        JTextField hashField = new JTextField(64);
        gbc.gridx = 1; gbc.gridwidth = 2;
        frame.add(hashField, gbc);
        gbc.gridwidth = 1;

        // Type of hash chooser
        gbc.gridx = 0; gbc.gridy = 2;
        frame.add(new JLabel("Algorithm:"), gbc);
        JRadioButton shaBtn = new JRadioButton("SHA256", true);
        JRadioButton md5Btn = new JRadioButton("MD5");
        ButtonGroup group = new ButtonGroup();
        group.add(shaBtn);
        group.add(md5Btn);
        JPanel algPanel = new JPanel();
        algPanel.add(shaBtn);
        algPanel.add(md5Btn);
        gbc.gridx = 1; gbc.gridwidth = 2;
        frame.add(algPanel, gbc);
        gbc.gridwidth = 1;

        JButton bruteBtn = new JButton("Brute Force");
        gbc.gridx = 0; gbc.gridy = 3; gbc.gridwidth = 3;
        frame.add(bruteBtn, gbc);

        bruteBtn.addActionListener(a->{

            JCuda.createAndShowGUI();
            frame.setVisible(false);
        });



        // Start button
        JButton startBtn = new JButton("Start Hashing");
        gbc.gridx = 0; gbc.gridy = 4; gbc.gridwidth = 3;
        frame.add(startBtn, gbc);

        startBtn.addActionListener(e -> {
            long start = System.currentTimeMillis();
            String path = fileField.getText().trim();
            targetHash = hashField.getText().trim();
            boolean useSha = shaBtn.isSelected();
            if (path.isEmpty() || targetHash.isEmpty()) {
                JOptionPane.showMessageDialog(frame, "Please select a file and enter the target hash.", "Error", JOptionPane.ERROR_MESSAGE);
                return;
            }
            startBtn.setEnabled(false);
            new Thread(() -> {
                try {

                    String found = processFile(path, useSha);
                    String msg ;
                    if(found != null){
                        long end = System.currentTimeMillis();
                        msg = "Match found: " + found
                        + "\nTime taken: " + (end - start) + " ms";
                    }else{
                       msg = "No match found in file.";
                    }

                    SwingUtilities.invokeLater(() -> JOptionPane.showMessageDialog(frame, msg));
                } catch (Exception ex) {
                    ex.printStackTrace();
                    SwingUtilities.invokeLater(() -> JOptionPane.showMessageDialog(frame, "Error: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE));
                } finally {
                    SwingUtilities.invokeLater(() -> startBtn.setEnabled(true));
                }
            }).start();
        });

        frame.pack();
        frame.setLocationRelativeTo(null);
        frame.setVisible(true);
    }

    private static String processFile(String filePath, boolean useSha) throws Exception {
        List<String> lines = Files.readAllLines(Paths.get(filePath), StandardCharsets.UTF_8);
        if (lines.isEmpty()) return null;

        // Initialize CUDA
        JCudaDriver.setExceptionsEnabled(true);
        JNvrtc.setExceptionsEnabled(true);
        cuInit(0);
        CUdevice dev = new CUdevice(); cuDeviceGet(dev, 0);
        CUcontext ctx = new CUcontext(); cuCtxCreate(ctx, 0, dev);

        // device code + kernel
        String cudaSrc = (useSha ? KernelSources.shaSource() : KernelSources.md5Source())
                + KernelSources.hashStringsKernelSource(useSha ? "sha256" : "md5_single_block", useSha ? 32 : 16);
        String ptx = compilePTX(cudaSrc);

        CUmodule module = new CUmodule(); cuModuleLoadData(module, ptx);
        CUfunction func = new CUfunction(); cuModuleGetFunction(func, module, "hashStringsKernel");

        // flatten lines into one byte buffer + offsets/lengths
        List<byte[]> utf8 = new ArrayList<>();
        long totalBytes = 0;
        for (String s : lines) {
            byte[] b = s.getBytes(StandardCharsets.UTF_8);
            utf8.add(b);
            totalBytes += b.length;
        }
        byte[] allData = new byte[(int) totalBytes];
        long[] offsets = new long[lines.size()];
        int[] lengths = new int[lines.size()];
        long pos = 0;
        for (int i = 0; i < utf8.size(); i++) {
            byte[] b = utf8.get(i);
            System.arraycopy(b, 0, allData, (int) pos, b.length);
            offsets[i] = pos;
            lengths[i] = b.length;
            pos += b.length;
        }

        // allocate GPU buffers
        CUdeviceptr dData   = new CUdeviceptr(); cuMemAlloc(dData, allData.length);
        CUdeviceptr dOff    = new CUdeviceptr(); cuMemAlloc(dOff, offsets.length * Sizeof.LONG);
        CUdeviceptr dLenArr = new CUdeviceptr(); cuMemAlloc(dLenArr, lengths.length * Sizeof.INT);
        CUdeviceptr dOut    = new CUdeviceptr(); cuMemAlloc(dOut, lines.size() * (useSha ? 32 : 16));

        cuMemcpyHtoD(dData, Pointer.to(allData), allData.length);
        cuMemcpyHtoD(dOff, Pointer.to(offsets), offsets.length * Sizeof.LONG);
        cuMemcpyHtoD(dLenArr, Pointer.to(lengths), lengths.length * Sizeof.INT);

        // Launch kernel
        int blockSize = 256;
        int gridSize  = (lines.size() + blockSize - 1) / blockSize;
        Pointer kernelParams = Pointer.to(
                Pointer.to(dData),
                Pointer.to(dOff),
                Pointer.to(dLenArr),
                Pointer.to(new int[]{lines.size()}),
                Pointer.to(dOut)
        );
        cuLaunchKernel(func, gridSize,1,1, blockSize,1,1, 0,null, kernelParams,null);
        cuCtxSynchronize();

        // Retrieve results
        byte[] allDigests = new byte[lines.size() * (useSha ? 32 : 16)];
        cuMemcpyDtoH(Pointer.to(allDigests), dOut, allDigests.length);

        // Cleanup
        cuMemFree(dData);
        cuMemFree(dOff);
        cuMemFree(dLenArr);
        cuMemFree(dOut);
        cuModuleUnload(module);
        cuCtxDestroy(ctx);

        // compare and return match
        int digestSize = useSha ? 32 : 16;
        for (int i = 0; i < lines.size(); i++) {
            byte[] dg = Arrays.copyOfRange(allDigests, i * digestSize, i * digestSize + digestSize);
            if (Utils.toHex(dg).equalsIgnoreCase(targetHash)) {
                return lines.get(i);
            }
        }
        return null;
    }

    private static String compilePTX(String cudaSource) {
        nvrtcProgram prog = new nvrtcProgram();
        nvrtcCreateProgram(prog, cudaSource, null, 0, null, null);

        CUdevice dev = new CUdevice(); cuDeviceGet(dev, 0);
        int[] major = new int[1], minor = new int[1];
        cuDeviceGetAttribute(major, CUdevice_attribute.CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MAJOR, dev);
        cuDeviceGetAttribute(minor, CUdevice_attribute.CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MINOR, dev);
        int maj = major[0], min = minor[0];
        if (maj >= 8) min = 0;
        String arch = String.format("compute_%d%d", maj, min);
        List<String> valid = Arrays.asList(
                "compute_30","compute_32","compute_35","compute_37",
                "compute_50","compute_52","compute_53",
                "compute_60","compute_61","compute_62",
                "compute_70","compute_72","compute_75",
                "compute_80","compute_86"
        );
        if (!valid.contains(arch)) arch = "compute_75";
        String[] options = new String[]{"--gpu-architecture", arch};

        int res = nvrtcCompileProgram(prog, options.length, options);
        String[] log = new String[1]; nvrtcGetProgramLog(prog, log);
        if (res != NVRTC_SUCCESS) {
            nvrtcDestroyProgram(prog);
            throw new RuntimeException("NVRTC compilation failed:\n" + log[0]);
        }else {

        }

        String[] ptx = new String[1]; nvrtcGetPTX(prog, ptx);
        nvrtcDestroyProgram(prog);
        if (ptx[0] == null || ptx[0].trim().isEmpty()) {
            throw new RuntimeException("Generated PTX is empty.");
        }
        return ptx[0];
    }
}

class Utils {
    static String toHex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format("%02x", x & 0xFF));
        return sb.toString();
    }
}

class KernelSources {
    static String shaSource() {
        // helper macros & constants and sha256 device function
        return // helper macros & constants
                "typedef unsigned int uint;\n" +
                        "__device__ uint rotr(uint x, uint r) { return (x >> r) | (x << (32 - r)); }\n" +
                        "__device__ uint Ch(uint x, uint y, uint z) { return (x & y) ^ (~x & z); }\n" +
                        "__device__ uint Maj(uint x, uint y, uint z) { return (x & y) ^ (x & z) ^ (y & z); }\n" +
                        "__device__ uint Sigma0(uint x) { return rotr(x,2) ^ rotr(x,13) ^ rotr(x,22); }\n" +
                        "__device__ uint Sigma1(uint x) { return rotr(x,6) ^ rotr(x,11) ^ rotr(x,25); }\n" +
                        "__device__ uint sigma0(uint x) { return rotr(x,7) ^ rotr(x,18) ^ (x >> 3); }\n" +
                        "__device__ uint sigma1(uint x) { return rotr(x,17) ^ rotr(x,19) ^ (x >> 10); }\n" +
                        "__constant__ uint K[64] = {\n" +
                        "  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,\n" +
                        "  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,\n" +
                        "  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,\n" +
                        "  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,\n" +
                        "  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,\n" +
                        "  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,\n" +
                        "  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,\n" +
                        "  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2\n" +
                        "};\n" +

                        // single‑block SHA‑256 (len≤64)
                        "extern \"C\" __device__ void sha256(const unsigned char *msg, int len, unsigned char *digest) {\n" +
                        "    uint h[8] = {\n" +
                        "        0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,\n" +
                        "        0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19\n" +
                        "    };\n" +
                        "    unsigned char block[64] = {0};\n" +
                        "    for (int i = 0; i < len; i++) block[i] = msg[i];\n" +
                        "    block[len] = 0x80;\n" +
                        "    unsigned long long bitLen = (unsigned long long)len * 8;\n" +
                        "    for (int i = 0; i < 8; i++)\n" +
                        "        block[63 - i] = (bitLen >> (8 * i)) & 0xFF;\n" +
                        "    uint w[64];\n" +
                        "    for (int t = 0; t < 16; t++) {\n" +
                        "        int j = t * 4;\n" +
                        "        w[t] = ((uint)block[j] << 24) | ((uint)block[j+1] << 16)\n" +
                        "             | ((uint)block[j+2] <<  8) | ((uint)block[j+3]);\n" +
                        "    }\n" +
                        "    for (int t = 16; t < 64; t++) {\n" +
                        "        w[t] = sigma1(w[t-2]) + w[t-7] + sigma0(w[t-15]) + w[t-16];\n" +
                        "    }\n" +
                        "    uint a = h[0], b = h[1], c = h[2], d = h[3];\n" +
                        "    uint e = h[4], f = h[5], g = h[6], h0 = h[7];\n" +
                        "    for (int t = 0; t < 64; t++) {\n" +
                        "        uint T1 = h0 + Sigma1(e) + Ch(e,f,g) + K[t] + w[t];\n" +
                        "        uint T2 = Sigma0(a) + Maj(a,b,c);\n" +
                        "        h0 = g; g = f; f = e; e = d + T1;\n" +
                        "        d = c; c = b; b = a; a = T1 + T2;\n" +
                        "    }\n" +
                        "    h[0] += a; h[1] += b; h[2] += c; h[3] += d;\n" +
                        "    h[4] += e; h[5] += f; h[6] += g; h[7] += h0;\n" +
                        "    for (int i = 0; i < 8; i++) {\n" +
                        "        digest[4*i  ] = (h[i] >> 24) & 0xFF;\n" +
                        "        digest[4*i+1] = (h[i] >> 16) & 0xFF;\n" +
                        "        digest[4*i+2] = (h[i] >>  8) & 0xFF;\n" +
                        "        digest[4*i+3] =  h[i]        & 0xFF;\n" +
                        "    }\n" +
                        "}\n" +

                        // global kernel (chunked)
                        "extern \"C\" __global__ void hashKernel(\n" +
                        "    const char *charSet, int charsetLen,\n" +
                        "    int strLen, unsigned long long totalCombos,\n" +
                        "    unsigned long long offset,\n" +
                        "    unsigned long long batchCount,\n" +
                        "    unsigned char *outHashes) {\n" +
                        "    unsigned long long idx    = blockIdx.x * blockDim.x + threadIdx.x;\n" +
                        "    unsigned long long stride = blockDim.x * gridDim.x;\n" +
                        "    char s[16]; unsigned char digest[32];\n" +
                        "    for (unsigned long long i = idx; i < batchCount; i += stride) {\n" +
                        "        unsigned long long globalIdx = offset + i;\n" +
                        "        unsigned long long x = globalIdx;\n" +
                        "        for (int pos = strLen - 1; pos >= 0; pos--) {\n" +
                        "            int d = x % charsetLen;\n" +
                        "            s[pos] = charSet[d];\n" +
                        "            x /= charsetLen;\n" +
                        "        }\n" +
                        "        sha256((unsigned char*)s, strLen, digest);\n" +
                        "        unsigned long long base = i * 32ULL;\n" +
                        "        for (int j = 0; j < 32; j++) {\n" +
                        "            outHashes[base + j] = digest[j];\n" +
                        "        }\n" +
                        "    }\n" +
                        "}\n";
    }
    static String md5Source() {
        // helper macros & constants and md5_single_block device function
        return  "typedef unsigned int uint;\n" +
                "\n" +
                "// per-round shift amounts\n" +
                "__constant__ int S[64] = {\n" +
                "   7,12,17,22, 7,12,17,22, 7,12,17,22, 7,12,17,22,\n" +
                "   5, 9,14,20, 5, 9,14,20, 5, 9,14,20, 5, 9,14,20,\n" +
                "   4,11,16,23, 4,11,16,23, 4,11,16,23, 4,11,16,23,\n" +
                "   6,10,15,21, 6,10,15,21, 6,10,15,21, 6,10,15,21\n" +
                "};\n" +
                "\n" +
                "// sine-based constants\n" +
                "__constant__ uint MD5_K[64] = {\n" +
                " 0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,\n" +
                " 0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,\n" +
                " 0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,\n" +
                " 0x6b901122,0xfd987193,0xa679438e,0x49b40821,\n" +
                " 0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,\n" +
                " 0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,\n" +
                " 0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,\n" +
                " 0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,\n" +
                " 0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,\n" +
                " 0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,\n" +
                " 0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,\n" +
                " 0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,\n" +
                " 0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,\n" +
                " 0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,\n" +
                " 0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,\n" +
                " 0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391\n" +
                "};\n" +
                "\n" +
                "// MD5 single-block helper\n" +
                "extern \"C\" __device__ void md5_single_block(const unsigned char *msg, int len, unsigned char *digest) {\n" +
                "    uint a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;\n" +
                "    unsigned char block[64] = {0};\n" +
                "    for (int i = 0; i < len; i++) block[i] = msg[i];\n" +
                "    block[len] = 0x80;\n" +
                "    // 64-bit little-endian bit length\n" +
                "    unsigned long long bitLen = (unsigned long long)len * 8ULL;\n" +
                "    for (int i = 0; i < 8; i++) {\n" +
                "        block[56 + i] = (bitLen >> (8 * i)) & 0xFF;\n" +
                "    }\n" +
                "    uint M[16];\n" +
                "    for (int i = 0; i < 16; i++) {\n" +
                "        int j = 4*i;\n" +
                "        M[i] = ((uint)block[j])        |\n" +
                "               ((uint)block[j+1] <<  8) |\n" +
                "               ((uint)block[j+2] << 16) |\n" +
                "               ((uint)block[j+3] << 24);\n" +
                "    }\n" +
                "    uint A = a0, B = b0, C = c0, D = d0;\n" +
                "    for (int i = 0; i < 64; i++) {\n" +
                "        uint F, g;\n" +
                "        if      (i < 16) { F = (B & C) | ((~B) & D); g = i; }\n" +
                "        else if (i < 32) { F = (D & B) | ((~D) & C); g = (5*i + 1) & 15; }\n" +
                "        else if (i < 48) { F = B ^ C ^ D;           g = (3*i + 5) & 15; }\n" +
                "        else              { F = C ^ (B | (~D));     g = (7*i)     & 15; }\n" +
                "        uint tmp = D;\n" +
                "        D = C;\n" +
                "        C = B;\n" +
                "        uint rotated = ((A + F + MD5_K[i] + M[g]) << S[i]) | ((A + F + MD5_K[i] + M[g]) >> (32 - S[i]));\n" +
                "        B = B + rotated;\n" +
                "        A = tmp;\n" +
                "    }\n" +
                "    a0 += A; b0 += B; c0 += C; d0 += D;\n" +
                "    ((uint*)digest)[0] = a0;\n" +
                "    ((uint*)digest)[1] = b0;\n" +
                "    ((uint*)digest)[2] = c0;\n" +
                "    ((uint*)digest)[3] = d0;\n" +
                "}\n" +
                "\n" +
                "// global MD5 kernel\n" +
                "extern \"C\" __global__ void hashKernelMd5(\n" +
                "    const char *charSet, int charsetLen,\n" +
                "    int strLen, unsigned long long totalCombos,\n" +
                "    unsigned long long offset,\n" +
                "    unsigned long long batchCount,\n" +
                "    unsigned char *outHashes\n" +
                ") {\n" +
                "    unsigned long long idx    = blockIdx.x * blockDim.x + threadIdx.x;\n" +
                "    unsigned long long stride = blockDim.x * gridDim.x;\n" +
                "    char s[16]; unsigned char digest[16];\n" +
                "    for (unsigned long long i = idx; i < batchCount; i += stride) {\n" +
                "        unsigned long long globalIdx = offset + i;\n" +
                "        unsigned long long x = globalIdx;\n" +
                "        for (int pos = strLen - 1; pos >= 0; pos--) {\n" +
                "            int d = x % charsetLen;\n" +
                "            s[pos] = charSet[d];\n" +
                "            x /= charsetLen;\n" +
                "        }\n" +
                "        md5_single_block((unsigned char*)s, strLen, digest);\n" +
                "        unsigned long long base = i * 16ULL;\n" +
                "        for (int j = 0; j < 16; j++) {\n" +
                "            outHashes[base + j] = digest[j];\n" +
                "        }\n" +
                "    }\n" +
                "}\n";
    }
    static String hashStringsKernelSource(String hashFn, int digestSize) {
        return
                "extern \"C\" __global__ void hashStringsKernel(\n" +
                        "    const unsigned char *data,\n" +
                        "    const unsigned long long *offsets,\n" +
                        "    const int *lengths,\n" +
                        "    int nStrings,\n" +
                        "    unsigned char *outDigests)\n" +
                        "{\n" +
                        "    int idx = blockIdx.x * blockDim.x + threadIdx.x;\n" +
                        "    if (idx >= nStrings) return;\n" +
                        "    unsigned long long off = offsets[idx];\n" +
                        "    int len = lengths[idx];\n" +
                        "    unsigned char digest[" + digestSize + "];\n" +
                        "    " + hashFn + "(data + off, len, digest);\n" +
                        "    int base = idx * " + digestSize + ";\n" +
                        "    for (int j = 0; j < " + digestSize + "; j++)\n" +
                        "        outDigests[base + j] = digest[j];\n" +
                        "}\n";
    }
}
