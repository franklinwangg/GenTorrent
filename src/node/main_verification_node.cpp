#include <iostream>
#include <string>
#include <thread>
#include <chrono>
#include <csignal>
#include <atomic>
#include "verification_node.hpp"

// Global flag for program termination
std::atomic<bool> shouldExit(false);

// Signal handler for clean termination
void signalHandler(int signal) {
    std::cout << "Received signal " << signal << ", shutting down..." << std::endl;
    shouldExit = true;
}

int main(int argc, char* argv[]) {
    // Register signal handlers for graceful shutdown
    std::signal(SIGINT, signalHandler);
    std::signal(SIGTERM, signalHandler);
    
    std::cout << "Starting Verification Node..." << std::endl;
    
    try {
        // Create a verification node
        node::VerificationNode* verificationNode = new node::VerificationNode();
        
        // Initialize the node
        verificationNode->initialize();
        
        std::cout << "Verification Node started. Press Ctrl+C to exit." << std::endl;
        
        // Load model if specified
        if (argc > 1) {
            std::string modelPath = argv[1];
            std::cout << "Loading model from: " << modelPath << std::endl;
            if (verificationNode->loadModel(modelPath)) {
                std::cout << "Model loaded successfully." << std::endl;
            } else {
                std::cerr << "Failed to load model." << std::endl;
            }
        }
        
        // Keep the node running until termination signal
        while (!shouldExit) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            
            // Could perform periodic tasks here like health checks
            // or checking for pending verifications
        }
        
        std::cout << "Shutting down verification node..." << std::endl;
        delete verificationNode;
        std::cout << "Verification node terminated." << std::endl;
        
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
} 