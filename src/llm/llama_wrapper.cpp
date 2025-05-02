#include "llama_wrapper.hpp"
#include <iostream>
#include <algorithm>
#include <thread>

namespace llm {

LlamaWrapper::LlamaWrapper() {
    std::cout << "Creating LlamaWrapper" << std::endl;
}

LlamaWrapper::~LlamaWrapper() {
    cleanup();
}

bool LlamaWrapper::initialize() {
    std::lock_guard<std::mutex> lock(mtx);
    
    if (initialized) {
        return true;
    }
    
    // Initialize llama.cpp backend
    llama_backend_init();
    
    initialized = true;
    std::cout << "Initialized llama backend" << std::endl;
    return true;
}

bool LlamaWrapper::loadModel(const std::string& modelPath, int contextSize, int threads, bool useGpu) {
    std::lock_guard<std::mutex> lock(mtx);
    
    if (!initialized) {
        if (!initialize()) {
            return false;
        }
    }
    
    // Clean up existing model if any
    if (ctx) {
        llama_free(ctx);
        ctx = nullptr;
    }
    
    if (model) {
        llama_model_free(model);
        model = nullptr;
    }
    
    // Set model parameters
    llama_model_params model_params = llama_model_default_params();
    
    // Set GPU layers if requested
    if (useGpu) {
        model_params.n_gpu_layers = -1;  // Use all GPU layers if available
        std::cout << "GPU acceleration enabled for model" << std::endl;
    }
    
    // Load the model
    model = llama_model_load_from_file(modelPath.c_str(), model_params);
    if (!model) {
        std::cerr << "Failed to load model from: " << modelPath << std::endl;
        return false;
    }
    
    // Set context parameters
    llama_context_params ctx_params = llama_context_default_params();
    ctx_params.n_ctx = contextSize;
    ctx_params.n_batch = 512;  // Batch size for prompt processing
    
    // Set number of threads
    if (threads <= 0) {
        ctx_params.n_threads = std::min(8, static_cast<int>(std::thread::hardware_concurrency()));
    } else {
        ctx_params.n_threads = threads;
    }
    
    // Create context
    ctx = llama_init_from_model(model, ctx_params);
    if (!ctx) {
        std::cerr << "Failed to create context for model" << std::endl;
        llama_model_free(model);
        model = nullptr;
        return false;
    }
    
    std::cout << "Successfully loaded model from: " << modelPath << std::endl;
    std::cout << "  Context size: " << contextSize << std::endl;
    std::cout << "  Threads: " << ctx_params.n_threads << std::endl;
    std::cout << "  GPU acceleration: " << (useGpu ? "Yes" : "No") << std::endl;
    
    return true;
}

std::string LlamaWrapper::generate(const std::string& prompt, int maxTokens, float temperature, bool useGpu) {
    std::lock_guard<std::mutex> lock(mtx);
    
    if (!ctx || !model) {
        std::cerr << "Model not loaded" << std::endl;
        return "Error: Model not loaded";
    }
    
    // Reset context
    resetContext();
    
    // Tokenize the prompt
    std::vector<llama_token> tokens = tokenize(prompt);
    if (tokens.empty()) {
        std::cerr << "Failed to tokenize prompt" << std::endl;
        return "Error: Failed to tokenize prompt";
    }
    
    // Feed the prompt to the model
    llama_batch batch = llama_batch_get_one(tokens.data(), tokens.size());
    if (llama_decode(ctx, batch) != 0) {
        std::cerr << "Failed to process prompt" << std::endl;
        return "Error: Failed to process prompt";
    }
    
    // Generate completion
    std::string result;
    llama_token id = 0;
    
    // Initialize sampler
    auto sparams = llama_sampler_chain_default_params();
    llama_sampler* smpl = llama_sampler_chain_init(sparams);
    llama_sampler_chain_add(smpl, llama_sampler_init_temp(temperature));
    llama_sampler_chain_add(smpl, llama_sampler_init_dist(LLAMA_DEFAULT_SEED));
    
    for (int i = 0; i < maxTokens; ++i) {
        // Sample the next token
        id = llama_sampler_sample(smpl, ctx, -1);
        
        // Check for end of sequence
        if (id == llama_vocab_eos(llama_model_get_vocab(model))) {
            break;
        }
        
        // Decode the token to text
        const char* token_str = llama_vocab_get_text(llama_model_get_vocab(model), id);
        if (token_str) {
            result += token_str;
        }
        
        // Feed the token back for the next prediction
        batch = llama_batch_get_one(&id, 1);
        if (llama_decode(ctx, batch) != 0) {
            break;
        }
    }
    
    // Clean up sampler
    llama_sampler_free(smpl);
    
    return result;
}

bool LlamaWrapper::isModelLoaded() const {
    return (model != nullptr && ctx != nullptr);
}

void LlamaWrapper::cleanup() {
    std::lock_guard<std::mutex> lock(mtx);
    
    if (ctx) {
        llama_free(ctx);
        ctx = nullptr;
    }
    
    if (model) {
        llama_model_free(model);
        model = nullptr;
    }
    
    if (initialized) {
        llama_backend_free();
        initialized = false;
    }
}

void LlamaWrapper::resetContext() {
    if (ctx) {
        llama_kv_cache_clear(ctx);
    }
}

std::vector<llama_token> LlamaWrapper::tokenize(const std::string& text) {
    if (!ctx) {
        return {};
    }
    
    const llama_vocab* vocab = llama_model_get_vocab(model);
    std::vector<llama_token> tokens(text.length() + 1);
    int n_tokens = llama_tokenize(vocab, text.c_str(), text.length(), tokens.data(), tokens.size(), true, true);
    if (n_tokens < 0) {
        tokens.resize(-n_tokens);
        llama_tokenize(vocab, text.c_str(), text.length(), tokens.data(), tokens.size(), true, true);
    } else {
        tokens.resize(n_tokens);
    }
    return tokens;
}

} // namespace llm 