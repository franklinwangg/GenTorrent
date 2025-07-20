#ifndef VERIFICATION_NODE_HPP
#define VERIFICATION_NODE_HPP

#include <string>
#include "../encrypt_p2p/network_handler.hpp"
#include "../encrypt_p2p/key_generation.hpp"
#include "../encrypt_p2p/crypto_utils.hpp"
#include <iostream>
#include <string>
#include <vector>
#include <cmath>
#include <curl/curl.h>
#include <nlohmann/json.hpp>
#include <boost/math/distributions/chi_squared.hpp>
#include <map>
#include "../llm/llama_wrapper.hpp"
#include <memory>
#include <mutex>

namespace node {
class VerificationNode {
    // TODO: add the blockchain part
    friend class UserNode;
    
    public:
        VerificationNode();
        ~VerificationNode();

        void initialize();
        
        // Load a model using llama.cpp
        bool loadModel(const std::string &modelPath);
        
        // Run a model with a prompt and get the response
        std::string runLocalLLM(const std::string &prompt, int maxTokens = 512, float temperature = 0.7f);
        
        // Health check for LLama server
        nlohmann::json checkLlamaHealth(const std::string &url = "http://localhost:8080/health");
        
        // Get the current reputation score for a model
        double getModelReputationScore(const std::string &modelIp);
        
        // Set custom Tendermint URL (for connecting to the Java implementation)
        void setTendermintURL(const std::string &url) { TENDERMINT_URL = url; }
        
        // For testing purposes - expose these protected
    #ifdef TESTING
        // These would normally be private but are exposed for testing
        std::string IP_ADDRESS;
        std::string PORT;
        std::string TENDERMINT_PORT = "26657"; // Default Tendermint RPC port
        std::string TENDERMINT_URL = "http://localhost:" + TENDERMINT_PORT; // Will connect to the Java implementation
        std::string LLAMA_SERVER_URL = "http://localhost:8080"; // Default llama.cpp server URL
        
        std::vector<std::tuple<std::string, int, std::string>> GlobalUserNodesList; // <IP_ADDRESS, port, RSA_PUBLIC_KEY> for all nodes in same region
        std::vector<std::tuple<std::string, int, std::string>> GlobalModelNodesList; // <IP_ADDRESS, port, RSA_PUBLIC_KEY> of model node list 

        // For storing model credibility scores
        std::map<std::string, double> modelCredibilityScores; // <IP_ADDRESS, score>
        
        // LLM model for running verification
        std::unique_ptr<llm::LlamaWrapper> llm;
        
        struct QAItem {
        std::string question;
        std::string context;
        std::string answer;    // Possibly the first gold answer or a joined set of them
        };
        
        std::vector<QAItem> challengeDataset;

        std::map<std::string, double> modelReputationScores;
        std::mutex reputationMutex;

        void loadChallengeDataset(const std::string &filePath);

        // calculate reputation score of a model node based on the result of the model
        double CalculateReputationScore(std::string &IP_ADDRESS);

        void updateGlobalUserNodesList(std::vector<std::tuple<std::string, int, std::string>> &userNodesList);
        void updateGlobalModelNodesList(std::vector<std::tuple<std::string, int, std::string>> &modelNodesList);

        // request functions same as user node, pretend to be a user node

        // New functions for user node registration
        bool registerUserNode(const std::string &ipAddress, const int PORT, const std::string &rsaPublicKey);
        std::string httpPost(const std::string &url, const std::string &jsonPayload);
        nlohmann::json handleRegistrationRequest(const std::string &requestBody);

        // New verification methods based on verify.py
        double checkCredibility(const std::string &prompt, const std::string &output,
                             const std::string &tokenizeUrl = "http://localhost:8080/tokenize",
                             const std::string &completionUrl = "http://localhost:8080/v1/completions",
                             float eps = 0.00001);

        // Improved credibility checking with more advanced tokenization
        double improvedCheckCredibility(const std::string &prompt, const std::string &output,
                                     const std::string &tokenizeUrl = "http://localhost:8080/tokenize",
                                     const std::string &completionUrl = "http://localhost:8080/v1/completions",
                                     float eps = 0.00001);

        nlohmann::json sendCompletion(const std::string &prompt, int maxTokens = 7, 
                                 float temperature = 0, 
                                 const std::string &url = "http://localhost:8080/v1/completions");

        // Tendermint integration methods - connects to Java implementation in verification_tendermint/
        bool submitChallenge(const std::string &prompt);
        bool submitModelResponse(const std::string &modelIp, const std::string &prompt, 
                               const std::string &output, const std::string &signature);
        bool submitEvaluation(const std::string &modelIp, double score);
        
        std::string tendermintRequest(const std::string &endpoint, const std::string &method, 
                                   const nlohmann::json &params = nlohmann::json());
        
        void broadcastTransaction(const nlohmann::json &tx);
        
        // Query methods for Tendermint state (implemented in verification_tendermint)
        nlohmann::json queryState();
        nlohmann::json queryModelScores();
        nlohmann::json queryModelScore(const std::string &modelIp);

        void UpdateModelReputation(const std::string& modelId, double score);
        
        // Helper methods for credibility calculation
        std::vector<nlohmann::json> tokenizeText(const std::string &text, const std::string &tokenizeUrl);
        double calculatePPL(const std::vector<double> &probabilities, double eps = 0.00001);
        std::vector<std::vector<nlohmann::json>> groupTokensIntoWords(const std::vector<nlohmann::json> &tokens);
        double applyLaplaceSmoothing(int vocabSize);
    #else
    private:
        std::string IP_ADDRESS;
        std::string PORT;
        std::string TENDERMINT_PORT = "26657"; // Default Tendermint RPC port
        std::string TENDERMINT_URL = "http://localhost:" + TENDERMINT_PORT; // Will connect to the Java implementation
        std::string LLAMA_SERVER_URL = "http://localhost:8080"; // Default llama.cpp server URL
        
        std::vector<std::tuple<std::string, int, std::string>> GlobalUserNodesList; // <IP_ADDRESS, port, RSA_PUBLIC_KEY> for all nodes in same region
        std::vector<std::tuple<std::string, int, std::string>> GlobalModelNodesList; // <IP_ADDRESS, port, RSA_PUBLIC_KEY> of model node list 

        // For storing model credibility scores
        std::map<std::string, double> modelCredibilityScores; // <IP_ADDRESS, score>
        
        // LLM model for running verification
        std::unique_ptr<llm::LlamaWrapper> llm;
        
        struct QAItem {
        std::string question;
        std::string context;
        std::string answer;    // Possibly the first gold answer or a joined set of them
        };
        
        std::vector<QAItem> challengeDataset;

        std::map<std::string, double> modelReputationScores;
        std::mutex reputationMutex;

        void loadChallengeDataset(const std::string &filePath);

        // calculate reputation score of a model node based on the result of the model
        double CalculateReputationScore(std::string &IP_ADDRESS);

        void updateGlobalUserNodesList(std::vector<std::tuple<std::string, int, std::string>> &userNodesList);
        void updateGlobalModelNodesList(std::vector<std::tuple<std::string, int, std::string>> &modelNodesList);

        // request functions same as user node, pretend to be a user node

        // New functions for user node registration
        bool registerUserNode(const std::string &ipAddress, const int PORT, const std::string &rsaPublicKey);
        std::string httpPost(const std::string &url, const std::string &jsonPayload);
        nlohmann::json handleRegistrationRequest(const std::string &requestBody);

        // New verification methods based on verify.py
        double checkCredibility(const std::string &prompt, const std::string &output,
                             const std::string &tokenizeUrl = "http://localhost:8080/tokenize",
                             const std::string &completionUrl = "http://localhost:8080/v1/completions",
                             float eps = 0.00001);

        nlohmann::json sendCompletion(const std::string &prompt, int maxTokens = 7, 
                                 float temperature = 0, 
                                 const std::string &url = "http://localhost:8080/v1/completions");

        // Tendermint integration methods - connects to Java implementation in verification_tendermint/
        bool submitChallenge(const std::string &prompt);
        bool submitModelResponse(const std::string &modelIp, const std::string &prompt, 
                               const std::string &output, const std::string &signature);
        bool submitEvaluation(const std::string &modelIp, double score);
        
        std::string tendermintRequest(const std::string &endpoint, const std::string &method, 
                                   const nlohmann::json &params = nlohmann::json());
        
        void broadcastTransaction(const nlohmann::json &tx);
        
        // Query methods for Tendermint state (implemented in verification_tendermint)
        nlohmann::json queryState();
        nlohmann::json queryModelScores();
        nlohmann::json queryModelScore(const std::string &modelIp);

        void UpdateModelReputation(const std::string& modelId, double score);
        
        // Helper methods for credibility calculation
        std::vector<nlohmann::json> tokenizeText(const std::string &text, const std::string &tokenizeUrl);
        double calculatePPL(const std::vector<double> &probabilities, double eps = 0.00001);
        std::vector<std::vector<nlohmann::json>> groupTokensIntoWords(const std::vector<nlohmann::json> &tokens);
    #endif
};   
}

#endif 