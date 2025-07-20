#ifndef LLAMA_WRAPPER_HPP
#define LLAMA_WRAPPER_HPP

#include <string>
#include <vector>
#include <mutex>
#include "../../deps/llama.cpp/include/llama.h"

namespace llm {

class LlamaWrapper {
public:
    LlamaWrapper();
    ~LlamaWrapper();

    // Initialize the library
    bool initialize();

    // Load model from a file
    bool loadModel(const std::string& modelPath, int contextSize = 2048, int threads = 0, bool useGpu = false);

    // Generate text completion
    std::string generate(const std::string& prompt, int maxTokens = 512, float temperature = 0.7f, bool useGpu = false);

    // Check if a model is loaded
    bool isModelLoaded() const;

    // Free resources
    void cleanup();

private:
    llama_model* model = nullptr;
    llama_context* ctx = nullptr;
    std::mutex mtx;  // For thread safety
    bool initialized = false;

    // Reset the KV cache
    void resetContext();

    // Tokenize input text
    std::vector<llama_token> tokenize(const std::string& text);
};

} // namespace llm

#endif // LLAMA_WRAPPER_HPP 