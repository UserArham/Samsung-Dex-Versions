const fs = require('fs');
const path = require('path');
const factory = require('./scanner.js');

// Initialize the standalone WebAssembly Module instance
factory().then((Module) => {
    // Specify the path to the local APK or file you want to test
    const targetFilePath = path.join(__dirname, 'test_target_file.apk');

    if (!fs.existsSync(targetFilePath)) {
        console.error(`[ERROR] File not found at: ${targetFilePath}`);
        process.exit(1);
    }

    // Read the binary file directly from your machine's hard drive
    const fileBuffer = fs.readFileSync(targetFilePath);
    const fileName = path.basename(targetFilePath);
    const numBytes = fileBuffer.length;

    // Allocate memory blocks directly inside the WASM linear memory heap
    const dataPtr = Module._malloc(numBytes);

    // Write the raw file bits directly into the allocated memory space
    const dataOnHeap = new Uint8Array(Module.HEAPU8.buffer, dataPtr, numBytes);
    dataOnHeap.set(new Uint8Array(fileBuffer));

    try {
        // Execute the fast C++ compiled evaluation logic loop
        const result = Module.analyze_binary(fileName, dataPtr, numBytes);

        console.log("==================================================");
        console.log("      SAMSUNG DEX SECURITY WASM ANALYSIS WORKER   ");
        console.log("==================================================");
        console.log(`Target File  : ${fileName}`);
        console.log(`Detected Arch: ${result.architecture}`);
        
        if (result.is_safe) {
            console.log("\x1b[32m%s\x1b[0m", `[PASS] STATUS: SAFE`);
            console.log(`Details      : ${result.message}`);
        } else {
            console.log("\x1b[31m%s\x1b[0m", `[BLOCK] STATUS: MALWARE DETECTED`);
            console.log(`Threat Group : ${result.threat_detected}`);
            console.log(`Alert Details: ${result.message}`);
        }
        console.log("==================================================");

    } catch (error) {
        console.error("[CRITICAL] WASM validation worker failed to execute execution tree:", error);
    } finally {
        // Always clean up heap space allocation memory immediately
        Module._free(dataPtr);
    }
});
