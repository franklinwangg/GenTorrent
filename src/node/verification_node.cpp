#include "verification_node.hpp"
#include <iostream>
#include <fstream>
#include <sstream>
#include <random>
#include <chrono>
#include <cmath>        
#include <algorithm>  
#include <mutex>


using json = nlohmann::json;

namespace node {

// Base64 encoding/decoding helpers
static const std::string base64_chars = 
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";

static inline bool is_base64(unsigned char c) {
    return (isalnum(c) || (c == '+') || (c == '/'));
}

std::string base64_encode(const std::vector<unsigned char>& data) {
    std::string ret;
    int i = 0;
    int j = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];

    for (unsigned char b : data) {
        char_array_3[i++] = b;
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for(i = 0; i < 4; i++)
                ret += base64_chars[char_array_4[i]];
            i = 0;
        }
    }

    if (i) {
        for(j = i; j < 3; j++)
            char_array_3[j] = '\0';

        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);

        for (j = 0; j < i + 1; j++)
            ret += base64_chars[char_array_4[j]];

        while((i++ < 3))
            ret += '=';
    }

    return ret;
}

std::vector<unsigned char> base64_decode(const std::string& encoded_string) {
    size_t in_len = encoded_string.size();
    int i = 0;
    int j = 0;
    int in_ = 0;
    unsigned char char_array_4[4], char_array_3[3];
    std::vector<unsigned char> ret;

    while (in_len-- && (encoded_string[in_] != '=') && is_base64(encoded_string[in_])) {
        char_array_4[i++] = encoded_string[in_]; in_++;
        if (i == 4) {
            for (i = 0; i < 4; i++)
                char_array_4[i] = base64_chars.find(char_array_4[i]);

            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

            for (i = 0; i < 3; i++)
                ret.push_back(char_array_3[i]);
            i = 0;
        }
    }

    if (i) {
        for (j = 0; j < i; j++)
            char_array_4[j] = base64_chars.find(char_array_4[j]);

        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
        char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);

        for (j = 0; j < i - 1; j++)
            ret.push_back(char_array_3[j]);
    }

    return ret;
}

static size_t WriteCallback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t totalSize = size * nmemb;
    std::string* response = static_cast<std::string*>(userp);
    response->append(static_cast<char*>(contents), totalSize);
    return totalSize;
}

VerificationNode::VerificationNode() : llm(new llm::LlamaWrapper()) {
    // Constructor implementation
    std::cout << "[VerificationNode] Created new verification node" << std::endl;
}

VerificationNode::~VerificationNode() {
    // Destructor implementation
    std::cout << "[VerificationNode] Destroyed" << std::endl;
}

void VerificationNode::initialize() {
    std::cout << "VerificationNode initializing..." << std::endl;
    
    // Load challenge dataset for model evaluation
    loadChallengeDataset("../../datasets/challenge_dataset.json");
    
    // Setup HTTP server to handle registration requests

    for (const auto& node : GlobalModelNodesList) {
        modelCredibilityScores[std::get<0>(node)] = 0.5;
    }
    
    // Check if Tendermint is accessible
    json healthCheck = checkLlamaHealth();
    if (!healthCheck["healthy"].get<bool>()) {
        std::cerr << "Warning: LLama server is not accessible: " << healthCheck["message"].get<std::string>() << std::endl;
    }
    
    // Check Tendermint connection
    try {
        std::string tendermintHealth = tendermintRequest("/health", "GET");
        std::cout << "Tendermint connection successful" << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Warning: Tendermint not accessible: " << e.what() << std::endl;
    }

    // Initialize llama.cpp backend
    if (!llm->initialize()) {
        std::cerr << "[VerificationNode] Failed to initialize LLM backend" << std::endl;
    } else {
        std::cout << "[VerificationNode] LLM backend initialized successfully" << std::endl;
        
        // remenver to change
        const std::string defaultModelPath = "../models/Llama-3.2-1B-Instruct-Q4_K_S.gguf";
        if (loadModel(defaultModelPath)) {
            std::cout << "[VerificationNode] Loaded default model: " << defaultModelPath << std::endl;
        } else {
            std::cerr << "[VerificationNode] Failed to load default model, will need to load manually" << std::endl;
        }
    }
}

bool VerificationNode::loadModel(const std::string &modelPath) {
    if (!llm->loadModel(modelPath, 2048)) {
        std::cerr << "[VerificationNode] Failed to load model from: " << modelPath << std::endl;
        return false;
    }
    
    std::cout << "[VerificationNode] Successfully loaded model from: " << modelPath << std::endl;
    return true;
}

std::string VerificationNode::runLocalLLM(const std::string &prompt, int maxTokens, float temperature) {
    if (!llm) {
        std::cerr << "[VerificationNode] LLM model not initialized" << std::endl;
        return "ERROR: Model not initialized";
    }
    
    try {
        std::string response = llm->generate(prompt, maxTokens, temperature);
        return response;
    } catch (const std::exception& e) {
        std::cerr << "[VerificationNode] Error generating response: " << e.what() << std::endl;
        return "ERROR: " + std::string(e.what());
    }
}

void VerificationNode::loadChallengeDataset(const std::string &filePath) {
    std::cout << "[VerificationNode] Loading challenge dataset from: " << filePath << std::endl;
    
    try {
        std::ifstream file(filePath);
        if (!file.is_open()) {
            std::cerr << "[VerificationNode] Failed to open challenge dataset file: " << filePath << std::endl;
            return;
        }
        
        json jsonData;
        file >> jsonData;
        
        if (!jsonData.is_array()) {
            std::cerr << "[VerificationNode] Challenge dataset must be a JSON array" << std::endl;
            return;
        }
        
        challengeDataset.clear();
        
        for (const auto& item : jsonData) {
            QAItem qaItem;
            
            if (item.contains("question") && item["question"].is_string()) {
                qaItem.question = item["question"].get<std::string>();
            } else {
                std::cerr << "[VerificationNode] Item missing required 'question' field" << std::endl;
                continue;
            }
            
            if (item.contains("context") && item["context"].is_string()) {
                qaItem.context = item["context"].get<std::string>();
            }
            
            if (item.contains("answer") && item["answer"].is_string()) {
                qaItem.answer = item["answer"].get<std::string>();
            } else if (item.contains("answers") && item["answers"].is_array()) {
                // Join multiple answers with a separator
                std::string combinedAnswers;
                for (const auto& answer : item["answers"]) {
                    if (answer.is_string()) {
                        if (!combinedAnswers.empty()) {
                            combinedAnswers += " | ";
                        }
                        combinedAnswers += answer.get<std::string>();
                    }
                }
                qaItem.answer = combinedAnswers;
            } else {
                std::cerr << "[VerificationNode] Item missing required 'answer' or 'answers' field" << std::endl;
                continue;
            }
            
            challengeDataset.push_back(qaItem);
        }
        
        std::cout << "[VerificationNode] Loaded " << challengeDataset.size() << " challenge items" << std::endl;
    } catch (const std::exception &e) {
        std::cerr << "[VerificationNode] Error loading challenge dataset: " << e.what() << std::endl;
    }
}

bool VerificationNode::registerUserNode(const std::string &ipAddress, const int PORT, const std::string &rsaPublicKey) {
    // Check if the node is already registered
    for (const auto& node : GlobalUserNodesList) {
        if (std::get<0>(node) == ipAddress && std::get<1>(node) == PORT) {
            std::cout << "Node with IP " << ipAddress <<":"<< PORT << " is already registered" << std::endl;
            // Update the public key if it has changed
            if (std::get<2>(node) != rsaPublicKey) {
                // Remove the old entry
                GlobalUserNodesList.erase(
                    std::remove(GlobalUserNodesList.begin(), GlobalUserNodesList.end(), node),
                    GlobalUserNodesList.end()
                );
                // Add the new entry
                GlobalUserNodesList.push_back(std::make_tuple(ipAddress, PORT, rsaPublicKey));
                std::cout << "Updated RSA public key for node " << ipAddress << std::endl;
            }
            return true;
        }
    }
    
    // Add the new node to the list
    GlobalUserNodesList.push_back(std::make_tuple(ipAddress, PORT, rsaPublicKey));
    std::cout << "Registered new user node with IP " << ipAddress << std::endl;
    return true;
}

std::string VerificationNode::httpPost(const std::string &url, const std::string &jsonPayload) {
    CURL *curl = curl_easy_init();
    std::string responseString;
    
    if (curl) {
        struct curl_slist *headers = nullptr;
        headers = curl_slist_append(headers, "Content-Type: application/json");
        
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, jsonPayload.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &responseString);
        
        CURLcode res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            std::cerr << "[VerificationNode] curl_easy_perform() failed: " << curl_easy_strerror(res) << std::endl;
        }
        
        curl_easy_cleanup(curl);
        curl_slist_free_all(headers);
    }
    
    return responseString;
}

json VerificationNode::handleRegistrationRequest(const std::string &requestBody) {
    json response;
    
    try {
        json request = json::parse(requestBody);
        
        if (request.contains("ip_address") && request.contains("port") && request.contains("rsa_public_key")) {
            std::string ipAddress = request["ip_address"];
            int port = request["port"];
            std::string rsaPublicKey = request["rsa_public_key"];
            
            bool success = registerUserNode(ipAddress, port, rsaPublicKey);
            
            if (success) {
                // Convert GlobalUserNodesList to JSON format
                json userNodes = json::array();
                for (const auto& node : GlobalUserNodesList) {
                    userNodes.push_back({
                        {"ip_address", std::get<0>(node)},
                        {"port", std::get<1>(node)},
                        {"rsa_public_key", std::get<2>(node)}
                    });
                }
                
                // Convert GlobalModelNodesList to JSON format
                json modelNodes = json::array();
                for (const auto& node : GlobalModelNodesList) {
                    modelNodes.push_back(node);
                }
                
                response["status"] = "success";
                response["message"] = "Registration successful";
                response["user_nodes"] = userNodes;
                response["model_nodes"] = modelNodes;
            } else {
                response["status"] = "error";
                response["message"] = "Registration failed";
            }
        } else {
            response["status"] = "error";
            response["message"] = "Missing required fields in request";
        }
    } catch (const std::exception& e) {
        response["status"] = "error";
        response["message"] = std::string("Error processing request: ") + e.what();
    }
    
    return response;
}

void VerificationNode::updateGlobalUserNodesList(std::vector<std::tuple<std::string, int, std::string>> &userNodesList) {
    GlobalUserNodesList = userNodesList;
}

void VerificationNode::updateGlobalModelNodesList(std::vector<std::tuple<std::string, int, std::string>> &modelNodesList) {
    GlobalModelNodesList = modelNodesList;
}

// Helper methods for credibility calculation
std::vector<json> VerificationNode::tokenizeText(const std::string &text, const std::string &tokenizeUrl) {
    json requestData = {
        {"content", text},
        {"with_pieces", true}
    };
    
    std::string requestStr = requestData.dump();
    std::string responseStr = httpPost(tokenizeUrl, requestStr);
    
    try {
        json responseJson = json::parse(responseStr);
        if (responseJson.contains("tokens") && responseJson["tokens"].is_array()) {
            return responseJson["tokens"].get<std::vector<json>>();
        }
    } catch (const std::exception &e) {
        std::cerr << "[VerificationNode] Error parsing tokenize response: " << e.what() << std::endl;
    }
    
    return {};
}

double VerificationNode::calculatePPL(const std::vector<double> &probabilities, double eps) {
    if (probabilities.empty()) {
        return 0.0;
    }
    
    // Calculate the geometric mean using logarithms for numerical stability
    double sumLogProbs = 0.0;
    for (double prob : probabilities) {
        if (prob < eps) {
            prob = eps; // Prevent log(0)
        }
        sumLogProbs += std::log(prob);
    }
    
    double avgNegLogp = -sumLogProbs / probabilities.size();
    double perplexity = std::exp(avgNegLogp);
    return 1.0 / perplexity; // Credibility score
}

std::vector<std::vector<json>> VerificationNode::groupTokensIntoWords(const std::vector<json> &tokens) {
    std::vector<std::vector<json>> words;
    std::vector<json> currentWord;
    
    for (const auto &token : tokens) {
        std::string piece = token["piece"].get<std::string>();
        
        // Check if this token starts a new word
        if (piece.find(" ") == 0 || piece == "\n" || piece == "." || 
            piece == "," || piece == "!" || piece == "?" || piece == ":") {
            if (!currentWord.empty()) {
                words.push_back(currentWord);
                currentWord.clear();
            }
            if (!piece.empty() && piece != " ") { 
                words.push_back({token});
            }
        } else {
            currentWord.push_back(token);
        }
    }
    
    // Add the last word if any
    if (!currentWord.empty()) {
        words.push_back(currentWord);
    }
    
    return words;
}


json VerificationNode::sendCompletion(const std::string &prompt, int maxTokens, float temperature, const std::string &url) {
    json requestData = {
        {"prompt", prompt},
        {"max_tokens", maxTokens},
        {"temperature", temperature},
        {"logprobs", 5}
    };
    
    std::string requestStr = requestData.dump();
    std::string responseStr = httpPost(url, requestStr);
    
    try {
        return json::parse(responseStr);
    } catch (const std::exception &e) {
        std::cerr << "[VerificationNode] Error parsing completion response: " << e.what() << std::endl;
        return {{"error", std::string("Request failed: ") + e.what()}};
    }
}

double VerificationNode::checkCredibility(const std::string &prompt, const std::string &output,
                                      const std::string &tokenizeUrl, const std::string &completionUrl,
                                      float eps) {
    try {
        // First, tokenize the output
        std::vector<json> tokens = tokenizeText(output, tokenizeUrl);
        if (tokens.empty()) {
            std::cerr << "[VerificationNode] No tokens received from tokenizer" << std::endl;
            return 0.0;
        }
        
        // Initialize variables for tracking probabilities
        std::vector<double> totalProb;
        int tokenCount = 0;
        
        // For each token, get the logprobs of the next token
        std::string currentText = prompt;
        
        for (size_t i = 0; i < tokens.size() - 1; i++) {
            json completionResponse = sendCompletion(currentText, 1, 0, completionUrl);
            
            if (completionResponse.contains("error")) {
                std::cerr << "[VerificationNode] Error in completion: " 
                          << completionResponse["error"].get<std::string>() << std::endl;
                continue;
            }
            
            // Get logprobs for the next token
            json logprobs = completionResponse["choices"][0]["logprobs"]["content"][0]["top_logprobs"];
            int nextToken = tokens[i]["id"].get<int>();
            
            // Find matching logprob entry
            bool found = false;
            for (const auto &logprobEntry : logprobs) {
                if (logprobEntry["id"].get<int>() == nextToken) {
                    double logprob = logprobEntry["logprob"].get<double>();
                    tokenCount++;
                    totalProb.push_back(std::exp(logprob));
                    found = true;
                    break;
                }
            }
            
            if (!found) {
                totalProb.push_back(eps);
            }
            
            // Update current_text for next iteration
            currentText += tokens[i]["piece"].get<std::string>();
        }
        
        // Calculate credibility score based on perplexity
        if (tokenCount == 0) {
            return 0.0;
        }
        
        return calculatePPL(totalProb, eps);
        
    } catch (const std::exception &e) {
        std::cerr << "[VerificationNode] Error in checkCredibility: " << e.what() << std::endl;
        return 0.0;
    }
}


json VerificationNode::checkLlamaHealth(const std::string &url) {
    CURL *curl = curl_easy_init();
    std::string responseString;
    
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &responseString);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
        
        CURLcode res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        
        if (res == CURLE_OK) {
            try {
                json responseJson = json::parse(responseString);
                if (responseJson.contains("status") && responseJson["status"] == "ok") {
                    return {{"healthy", true}, {"message", "Server ready"}};
                }
                if (responseJson.contains("error") && responseJson["error"].contains("message")) {
                    std::string errorMessage = responseJson["error"]["message"];
                    return {{"healthy", false}, {"message", "Server loading: " + errorMessage}};
                }
                return {{"healthy", false}, {"message", "Unexpected response"}};
            } catch (const std::exception &e) {
                return {{"healthy", false}, {"message", std::string("Error parsing response: ") + e.what()}};
            }
        } else if (res == CURLE_OPERATION_TIMEDOUT) {
            return {{"healthy", false}, {"message", "Server not responding (timeout)"}};
        } else {
            return {{"healthy", false}, {"message", std::string("CURL error: ") + curl_easy_strerror(res)}};
        }
    }
    
    return {{"healthy", false}, {"message", "Could not initialize CURL"}};
}

bool VerificationNode::submitModelResponse(const std::string &modelIp, const std::string &prompt, 
                                        const std::string &output, const std::string &signature) {
    // First, verify the model's response using our credibility checking methods
    double credibilityScore;
    try {
        // Use improved check credibility if possible
        credibilityScore = improvedCheckCredibility(prompt, output);
        std::cout << "[VerificationNode] Improved credibility score for " << modelIp << ": " << credibilityScore << std::endl;
    } catch (const std::exception& e) {
        // Fall back to basic check if improved fails
        try {
            credibilityScore = checkCredibility(prompt, output);
            std::cout << "[VerificationNode] Basic credibility score for " << modelIp << ": " << credibilityScore << std::endl;
        } catch (const std::exception& e2) {
            std::cerr << "[VerificationNode] Failed to check credibility: " << e2.what() << std::endl;
            credibilityScore = 0.5; // Default neutral score
        }
    }
    
    // Update the model's reputation based on the credibility score
    UpdateModelReputation(modelIp, credibilityScore);
    
    // Create the transaction to be broadcasted
    json tx = {
        {"type", "response"},
        {"model_ip", modelIp},
        {"prompt", prompt},
        {"output", output},
        {"digest", signature},
        {"credibility_score", credibilityScore},
        {"reputation_score", modelReputationScores[modelIp]},
        {"timestamp", std::to_string(std::chrono::system_clock::now().time_since_epoch().count())}
    };
    
    try {
        broadcastTransaction(tx);
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Error submitting model response: " << e.what() << std::endl;
        return false;
    }
}

void VerificationNode::UpdateModelReputation(const std::string& modelId, double score) {
    std::lock_guard<std::mutex> lock(reputationMutex);
    modelReputationScores[modelId] = score;
}

std::string VerificationNode::tendermintRequest(const std::string &endpoint, const std::string &method, 
                                              const json &params) {
    std::string url = TENDERMINT_URL + endpoint;
    CURL *curl = curl_easy_init();
    std::string responseString;
    
    if (curl) {
        struct curl_slist *headers = nullptr;
        headers = curl_slist_append(headers, "Content-Type: application/json");
        
        // Prepare request body for POST requests
        std::string requestBody;
        if (method == "POST") {
            json requestJson = {
                {"jsonrpc", "2.0"},
                {"id", 1},
                {"method", endpoint.substr(1)}, // Remove leading '/'
                {"params", params}
            };
            requestBody = requestJson.dump();
        }
        
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        
        if (method == "POST") {
            curl_easy_setopt(curl, CURLOPT_POST, 1L);
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, requestBody.c_str());
        }
        
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &responseString);
        
        CURLcode res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            std::cerr << "[VerificationNode] curl_easy_perform() failed: " << curl_easy_strerror(res) << std::endl;
            throw std::runtime_error(std::string("Tendermint request failed: ") + curl_easy_strerror(res));
        }
        
        curl_easy_cleanup(curl);
        curl_slist_free_all(headers);
    } else {
        throw std::runtime_error("Could not initialize CURL");
    }
    
    return responseString;
}

void VerificationNode::broadcastTransaction(const json &tx) {
    // First, encode the transaction as base64
    std::string txJson = tx.dump();
    std::vector<unsigned char> txBytes(txJson.begin(), txJson.end());
    
    // Base64 encode using our custom function
    std::string base64Tx = base64_encode(txBytes);
    
    // Prepare parameters
    json params = {
        {"tx", base64Tx}
    };
    
    try {
        std::string response = tendermintRequest("/broadcast_tx_sync", "POST", params);
        
        json responseJson = json::parse(response);
        
        // Check for errors
        if (responseJson.contains("error")) {
            std::cerr << "[VerificationNode] Broadcast error: " << responseJson["error"] << std::endl;
            throw std::runtime_error("Broadcast transaction failed: " + responseJson["error"].dump());
        }
        
        // Check result
        if (responseJson.contains("result")) {
            json result = responseJson["result"];
            if (result.contains("code") && result["code"].get<int>() != 0) {
                std::cerr << "[VerificationNode] Transaction error: " << result["log"].get<std::string>() << std::endl;
                throw std::runtime_error("Transaction error: " + result["log"].get<std::string>());
            }
            
            std::cout << "[VerificationNode] Transaction broadcasted: " << result["hash"].get<std::string>() << std::endl;
        }
    } catch (const std::exception &e) {
        std::cerr << "[VerificationNode] Error broadcasting transaction: " << e.what() << std::endl;
        throw;
    }
}

bool VerificationNode::submitChallenge(const std::string &prompt) {
    json tx = {
        {"type", "challenge"},
        {"prompt", prompt},
        {"timestamp", std::to_string(std::chrono::system_clock::now().time_since_epoch().count())}
    };
    
    try {
        broadcastTransaction(tx);
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Error submitting challenge: " << e.what() << std::endl;
        return false;
    }
}

bool VerificationNode::submitEvaluation(const std::string &modelIp, double score) {
    json tx = {
        {"type", "evaluation"},
        {"model_ip", modelIp},
        {"score", score},
        {"timestamp", std::to_string(std::chrono::system_clock::now().time_since_epoch().count())}
    };
    
    try {
        broadcastTransaction(tx);
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Error submitting evaluation: " << e.what() << std::endl;
        return false;
    }
}

json VerificationNode::queryState() {
    try {
        std::string response = tendermintRequest("/abci_query?path=\"/state\"", "GET");
        json responseJson = json::parse(response);
        
        if (responseJson.contains("result") && 
            responseJson["result"].contains("response") && 
            responseJson["result"]["response"].contains("value")) {
            
            std::string base64Value = responseJson["result"]["response"]["value"];
            // Decode base64 using our custom function
            auto valueBytes = base64_decode(base64Value);
            std::string valueStr(valueBytes.begin(), valueBytes.end());
            
            return json::parse(valueStr);
        }
    } catch (const std::exception& e) {
        std::cerr << "Error querying state: " << e.what() << std::endl;
    }
    
    return {};
}

json VerificationNode::queryModelScores() {
    try {
        std::string response = tendermintRequest("/abci_query?path=\"/models/scores\"", "GET");
        json responseJson = json::parse(response);
        
        if (responseJson.contains("result") && 
            responseJson["result"].contains("response") && 
            responseJson["result"]["response"].contains("value")) {
            
            std::string base64Value = responseJson["result"]["response"]["value"];
            // Decode base64 using our custom function
            auto valueBytes = base64_decode(base64Value);
            std::string valueStr(valueBytes.begin(), valueBytes.end());
            
            return json::parse(valueStr);
        }
    } catch (const std::exception& e) {
        std::cerr << "Error querying model scores: " << e.what() << std::endl;
    }
    
    return {};
}

json VerificationNode::queryModelScore(const std::string &modelIp) {
    try {
        std::string response = tendermintRequest("/abci_query?path=\"/models/score/" + modelIp + "\"", "GET");
        json responseJson = json::parse(response);
        
        if (responseJson.contains("result") && 
            responseJson["result"].contains("response") && 
            responseJson["result"]["response"].contains("value")) {
            
            std::string base64Value = responseJson["result"]["response"]["value"];
            // Decode base64 using our custom function
            auto valueBytes = base64_decode(base64Value);
            std::string valueStr(valueBytes.begin(), valueBytes.end());
            
            return json::parse(valueStr);
        }
    } catch (const std::exception& e) {
        std::cerr << "Error querying model score: " << e.what() << std::endl;
    }
    
    return {};
}

double VerificationNode::CalculateReputationScore(std::string &IP_ADDRESS) {
    // Fetch the model's current score from our local map
    if (modelReputationScores.find(IP_ADDRESS) != modelReputationScores.end()) {
        return modelReputationScores[IP_ADDRESS];
    }
    
    // Try to get the score from Tendermint if it's not in our local map
    json scoreData = queryModelScore(IP_ADDRESS);
    if (!scoreData.empty() && scoreData.contains("score")) {
        double score = scoreData["score"].get<double>();
        modelReputationScores[IP_ADDRESS] = score;
        return score;
    }
    
    // If no score is found, initialize with a neutral score
    modelReputationScores[IP_ADDRESS] = 0.5;
    return 0.5;
}

double VerificationNode::getModelReputationScore(const std::string &modelIp) {
    std::lock_guard<std::mutex> lock(reputationMutex);
    
    // If we have the score in our local cache, return it
    if (modelReputationScores.find(modelIp) != modelReputationScores.end()) {
        return modelReputationScores[modelIp];
    }
    
    // Otherwise try to get it from the blockchain
    try {
        json scoreData = queryModelScore(modelIp);
        if (!scoreData.empty() && scoreData.contains("score")) {
            double score = scoreData["score"].get<double>();
            modelReputationScores[modelIp] = score; // Update local cache
            return score;
        }
    } catch (const std::exception& e) {
        std::cerr << "[VerificationNode] Error querying model score: " << e.what() << std::endl;
    }
    
    // Default score for new or unknown models
    return 0.5;
}


} // namespace node
