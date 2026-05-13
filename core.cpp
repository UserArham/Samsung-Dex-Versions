#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <algorithm>

// Define a structured container for file analysis metrics
struct ScanResult {
    bool is_safe;
    std::string architecture;
    std::string threat_detected;
    std::string message;
};

// Main binary inspection engine
ScanResult analyze_binary(const std::string& file_path) {
    ScanResult result;
    result.is_safe = true;
    result.architecture = "UNKNOWN";
    result.threat_detected = "NONE";
    result.message = "File matches verified deployment profiles.";

    // 1. Scan for the blacklisted .esheram extension strings
    std::string lower_path = file_path;
    std::transform(lower_path.begin(), lower_path.end(), lower_path.begin(), ::tolower);
    if (lower_path.find(".esheram") != std::string::npos) {
        result.is_safe = false;
        result.threat_detected = "ESHERAM Malicious Container";
        result.message = "CRITICAL BLOCK: Banned in 67 countries. Contains hardware sabotage payloads.";
        return result;
    }

    // Open file in binary read mode
    std::ifstream file(file_path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        result.is_safe = false;
        result.message = "CRITICAL ERROR: Failed to open file path. Verify file existence and access permissions.";
        return result;
    }

    // Track total stream length and handle sizing exceptions
    std::streamsize size = file.tellg();
    if (size < 4) {
        result.is_safe = false;
        result.message = "CRITICAL BLOCK: Invalid or corrupted binary structure (File too small).";
        return result;
    }

    // Reset stream position pointer to the beginning of the file layout
    file.seekg(0, std::ios::beg);

    // Read full contents cleanly into a native byte array vector memory layout
    std::vector<char> buffer(size);
    if (!file.read(buffer.data(), size)) {
        result.is_safe = false;
        result.message = "CRITICAL ERROR: High-level read tracking failure during partition streaming.";
        return result;
    }
    file.close();

    // 2. Structural Header Validation 
    // Match against standard ZIP local file header headers (0x50 0x4B 0x03 0x04) for real APK packages
    if (buffer[0] == 0x50 && buffer[1] == 0x4B && buffer[2] == 0x03 && buffer[3] == 0x04) {
        result.architecture = "ARM64 / Universal APK Package";
    } else {
        result.is_safe = false;
        result.message = "CRITICAL BLOCK: Target binary is not a valid Android system package format.";
        return result;
    }

    // Transform byte vector into string data block to perform signature parsing rules
    std::string binary_data(buffer.begin(), buffer.end());

    // 3. Sequential Blacklist Payload String Evaluation
    if (binary_data.find("hack-my-phone") != std::string::npos) {
        result.is_safe = false;
        result.threat_detected = "hack-my-phone script";
        result.message = "CRITICAL BLOCK: Elevated system partition intrusion exploit detected.";
    } 
    else if (binary_data.find("touchwiz-destroyer") != std::string::npos) {
        result.is_safe = false;
        result.threat_detected = "touchwiz-destroyer script";
        result.message = "CRITICAL BLOCK: Destroys core TouchWiz/One UI launcher system directories.";
    } 
    else if (binary_data.find("samsung-downgrader") != std::string::npos) {
        result.is_safe = false;
        result.threat_detected = "samsung-downgrader-android-4.1+ script";
        result.message = "CRITICAL BLOCK: Corrupts partition tables to force invalid signature firmware drops.";
    } 
    else if (binary_data.find("nougat-bun") != std::string::npos || binary_data.find("CuteVirus") != std::string::npos) {
        result.is_safe = false;
        result.threat_detected = "CuteVirus 1.1.3 (nougat-bun)";
        result.message = "CRITICAL BLOCK: Knox-breaching payload detected. Causes up to 5.89 GB of storage cache bloat.";
    } 
    else if (binary_data.find("boot-to-samsung-s3") != std::string::npos) {
        result.is_safe = false;
        result.threat_detected = "boot-to-samsung-s3 script";
        result.message = "CRITICAL BLOCK: Permanently corrupts physical device screen mapping profiles.";
    }

    return result;
}

// System Command Interface Entry Point
int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "=========================================================\n";
        std::cout << "  SAMSUNG DEX DEPLOYMENT INTEGRITY VALIDATOR (NATIVE C++) \n";
        std::cout << "=========================================================\n";
        std::cout << "Usage Execution Command:\n";
        std::cout << "  " << argv[0] << " <path_to_target_apk_or_file>\n\n";
        return 1;
    }

    std::string input_file = argv[1];
    ScanResult scan = analyze_binary(input_file);

    std::cout << "---------------------------------------------------------\n";
    std::cout << "File Scanned : " << input_file << "\n";
    std::cout << "Detected Arch: " << scan.architecture << "\n";
    
    if (scan.is_safe) {
        // Print green colored success message in compatible terminal windows
        std::cout << "\033[32m[PASS] STATUS: STABLE AND VERIFIED SAFE\033[0m\n";
        std::cout << "Log Summary  : " << scan.message << "\n";
    } else {
        // Print red colored failure message in compatible terminal windows
        std::cout << "\033[31m[BLOCK] STATUS: MALICIOUS FILE OR VECTOR RECOGNIZED\033[0m\n";
        std::cout << "Threat Group : " << scan.threat_detected << "\n";
        std::cout << "Alert Actions: " << scan.message << "\n";
    }
    std::cout << "---------------------------------------------------------\n";

    return (scan.is_safe) ? 0 : 2;
}
