package io.planetllm;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.Base64;
import java.util.Properties;
import java.util.logging.Logger;
import java.util.logging.Level;
import java.nio.file.Paths;
import java.nio.file.Files;

/**
 * A simplified version of the ABCI application for PlanetLLM credibility checking
 */
public class CredibilityApp {
    private static final Logger LOGGER = Logger.getLogger(CredibilityApp.class.getName());
    private final Map<String, String> storage = new ConcurrentHashMap<>();
    private final ObjectMapper objectMapper;
    
    // Current epoch data structures
    private Map<String, String> currentChallenges = new HashMap<>();
    private Map<String, ModelResponse> modelResponses = new HashMap<>();
    private Map<String, Double> credibilityScores = new HashMap<>(); // modelIP -> score
    
    // Known model nodes and their public keys
    private final Map<String, String> knownModelNodes = new HashMap<>(); // modelIP -> publicKey
    
    // Ground truth model responses for comparison
    private final Map<String, String> groundTruthResponses = new HashMap<>(); // prompt -> expectedResponse
    
    // Current leader
    private String currentLeader;
    
    // ABCI States
    private static final String CHALLENGE_STATE = "CHALLENGE";
    private static final String RESPONSE_STATE = "RESPONSE";
    private static final String EVALUATION_STATE = "EVALUATION";
    private String currentState = CHALLENGE_STATE;

    // Threshold for score updates
    private static final double SCORE_THRESHOLD = 0.4;
    private static final double SCORE_INCREMENT = 0.1;
    
    // New: Verification node wrapper for C++ integration
    private VerificationNodeWrapper verificationNodeWrapper;
    
    // Model settings
    private static final String DEFAULT_MODEL_PATH = "../models/Llama-3.2-1B-Instruct-Q4_K_S.gguf";
    
    // Add configuration defaults
    private static final String DEFAULT_VERIFICATION_NODE_PATH = "/home/fang/Documents/lab/GenTorrent/build/verification_node";
    
    private final Properties config = new Properties();
    
    /**
     * Represents a model's response with its signed digest
     */
    private static class ModelResponse {
        String modelIp;
        String prompt;
        String output;
        String digest;
        String timestamp;
        
        ModelResponse(String modelIp, String prompt, String output, String digest, String timestamp) {
            this.modelIp = modelIp;
            this.prompt = prompt;
            this.output = output;
            this.digest = digest;
            this.timestamp = timestamp;
        }
    }
    
    public CredibilityApp() {
        this.objectMapper = new ObjectMapper();
        
        // Initialize with some example ground truth responses
        groundTruthResponses.put("What is climate change?", 
            "Climate change refers to long-term shifts in temperatures and weather patterns, mainly caused by human activities, especially the burning of fossil fuels.");
        
        groundTruthResponses.put("The United States Congress", 
            "is a bicameral legislature of the federal government of the United States consisting of the Senate and the House of Representatives.");
        
        // Initialize with example model nodes
        knownModelNodes.put("172.16.1.10", "public_key_1");
        knownModelNodes.put("172.16.1.11", "public_key_2");
        knownModelNodes.put("172.16.1.12", "public_key_3");
        
        // Initialize model scores to 0.5
        for (String modelIp : knownModelNodes.keySet()) {
            credibilityScores.put(modelIp, 0.5);
        }
        
        try {
            // Load configuration
            loadConfig();
            
            // Initialize verification node wrapper
            initializeVerificationNode();
            
            // Set up HTTP server and other components
            setupServer();
            
            System.out.println("PlanetLLM Credibility Application started successfully");
        } catch (Exception e) {
            System.err.println("Failed to initialize credibility app: " + e.getMessage());
            e.printStackTrace();
            throw new RuntimeException("Failed to initialize credibility app", e);
        }
    }
    
    private void loadConfig() {
        // Set default configuration values
        config.setProperty("verification.node.path", DEFAULT_VERIFICATION_NODE_PATH);
        
        try {
            // Try to load from config file if it exists
            if (Files.exists(Paths.get("config.properties"))) {
                config.load(Files.newInputStream(Paths.get("config.properties")));
                LOGGER.info("Loaded configuration from config.properties");
            }
        } catch (IOException e) {
            LOGGER.log(Level.WARNING, "Failed to load configuration file", e);
        }
        
        // Override with system properties
        config.putAll(System.getProperties());
    }
    
    private void initializeVerificationNode() {
        try {
            // Check if verification node binary exists at configured path
            String nodePath = config.getProperty("verification.node.path");
            if (nodePath != null && !Files.exists(Paths.get(nodePath))) {
                LOGGER.warning("Verification node executable not found at configured path: " + nodePath);
                LOGGER.warning("Please ensure the verification_node executable is built and the path is correctly configured");
                
                // Try to find the executable at common locations
                if (Files.exists(Paths.get(DEFAULT_VERIFICATION_NODE_PATH))) {
                    LOGGER.info("Found verification_node at default path: " + DEFAULT_VERIFICATION_NODE_PATH);
                    nodePath = DEFAULT_VERIFICATION_NODE_PATH;
                    config.setProperty("verification.node.path", nodePath);
                }
            }
            
            // Create and initialize the wrapper
            verificationNodeWrapper = new VerificationNodeWrapper();
            
            // Configure the wrapper if we have a specific path
            if (nodePath != null && Files.exists(Paths.get(nodePath))) {
                verificationNodeWrapper.setVerificationNodePath(nodePath);
            }
            
            // Initialize the wrapper
            verificationNodeWrapper.initialize();
            
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Failed to initialize verification node wrapper", e);
            throw new RuntimeException("Failed to initialize verification node wrapper", e);
        }
    }
    
    private void setupServer() {
        // Your existing server setup code
        System.out.println("HTTP server started on port 26658");
        System.out.println("Server started successfully on port 26658");
        System.out.println("Press Ctrl+C to stop the server");
    }
    
    /**
     * Attempts to load the model from the default path or a custom path
     */
    private void tryLoadModel() {
        if (verificationNodeWrapper != null) {
            // First try the default model path
            String result = verificationNodeWrapper.loadModel(DEFAULT_MODEL_PATH);
            System.out.println("Loading model result: " + result);
            
            // If the default fails, we could try alternative paths
            if (!verificationNodeWrapper.isModelLoaded()) {
                // Try some alternative model paths
                String[] alternatePaths = {
                    "../models/llama2-7b.gguf",
                    "../models/Llama-3.2-3B-Instruct-Q4_K_M.gguf",
                    "/opt/models/Llama-3.2-1B-Instruct-Q4_K_S.gguf"
                };
                
                for (String path : alternatePaths) {
                    result = verificationNodeWrapper.loadModel(path);
                    System.out.println("Loading alternate model " + path + " result: " + result);
                    if (verificationNodeWrapper.isModelLoaded()) {
                        break;
                    }
                }
            }
            
            if (!verificationNodeWrapper.isModelLoaded()) {
                System.err.println("Failed to load any model");
            }
        }
    }
    
    /**
     * Runs the loaded model with a prompt
     * @param prompt The prompt to send to the model
     * @return The model's response
     */
    public String runModel(String prompt) {
        if (verificationNodeWrapper != null) {
            if (!verificationNodeWrapper.isModelLoaded()) {
                tryLoadModel();
            }
            
            return verificationNodeWrapper.runModel(prompt, 512, 0.7f);
        }
        return "Model not available";
    }

    /**
     * Process transactions submitted to the application
     * 
     * @param txData The transaction data as a byte array (usually JSON)
     * @return A response message
     */
    public String deliverTx(byte[] txData) {
        try {
            // Parse transaction
            Map<String, Object> tx = objectMapper.readValue(txData, Map.class);
            String type = (String) tx.get("type");
            
            if (type == null) {
                return "Invalid transaction format: missing type";
            }
            
            switch (type) {
                case "challenge":
                    if (!processChallenge(tx)) {
                        return "Failed to process challenge";
                    }
                    break;
                case "response":
                    if (!processResponse(tx)) {
                        return "Failed to process response";
                    }
                    break;
                case "evaluation":
                    if (!processEvaluation(tx)) {
                        return "Failed to process evaluation";
                    }
                    break;
                case "run_model":
                    String prompt = (String) tx.get("prompt");
                    if (prompt != null) {
                        // Run the model and return the result directly
                        return runModel(prompt);
                    } else {
                        return "Missing prompt in run_model transaction";
                    }
                default:
                    return "Unknown transaction type: " + type;
            }
            
            return "OK";
            
        } catch (Exception e) {
            return "Error processing transaction: " + e.getMessage();
        }
    }

    /**
     * Commit the current state to storage
     */
    public byte[] commit() {
        try {
            // Save current state to storage
            storage.put("challenges", objectMapper.writeValueAsString(currentChallenges));
            storage.put("responses", objectMapper.writeValueAsString(modelResponses));
            storage.put("scores", objectMapper.writeValueAsString(credibilityScores));
            storage.put("current_state", currentState);
            
            // Create a hash of the application state
            String appStateStr = objectMapper.writeValueAsString(storage);
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(appStateStr.getBytes(StandardCharsets.UTF_8));
            return Arrays.copyOf(hash, 8); // Return first 8 bytes of hash
            
        } catch (Exception e) {
            System.err.println("Error committing state: " + e.getMessage());
            return new byte[8]; // Return empty hash on error
        }
    }

    /**
     * Handle queries to the application state
     * 
     * @param path The query path
     * @param queryData The query data
     * @return The query result
     */
    public String query(String path, byte[] queryData) {
        try {
            // Parse the query
            Map<String, Object> queryParams = queryData != null && queryData.length > 0 ?
                    objectMapper.readValue(queryData, Map.class) : new HashMap<>();
            
            if ("state".equals(path)) {
                return "Current state: " + currentState;
            } else if ("challenges".equals(path)) {
                return objectMapper.writeValueAsString(currentChallenges);
            } else if ("responses".equals(path)) {
                return objectMapper.writeValueAsString(modelResponses);
            } else if ("scores".equals(path)) {
                return objectMapper.writeValueAsString(credibilityScores);
            } else if ("model_score".equals(path)) {
                // Get specific model score
                String modelIp = (String) queryParams.get("model_ip");
                if (modelIp != null) {
                    Double score = credibilityScores.get(modelIp);
                    return score != null ? score.toString() : "0.0";
                } else {
                    return "Missing model_ip parameter";
                }
            } else if ("model_status".equals(path)) {
                // Check if model is loaded
                if (verificationNodeWrapper != null) {
                    Map<String, Object> result = new HashMap<>();
                    result.put("loaded", verificationNodeWrapper.isModelLoaded());
                    return objectMapper.writeValueAsString(result);
                } else {
                    Map<String, Object> result = new HashMap<>();
                    result.put("loaded", false);
                    result.put("error", "Verification node wrapper not initialized");
                    return objectMapper.writeValueAsString(result);
                }
            } else if ("run_model".equals(path)) {
                // Run model with prompt
                String prompt = (String) queryParams.get("prompt");
                if (prompt != null) {
                    return runModel(prompt);
                } else {
                    return "Missing prompt parameter";
                }
            } else {
                return "Unknown query path: " + path;
            }
        } catch (Exception e) {
            return "Error processing query: " + e.getMessage();
        }
    }
    
    /**
     * Verify a response's signature
     */
    private boolean verifySignature(String message, String digest, String modelIp) {
        try {
            String publicKey = knownModelNodes.get(modelIp);
            if (publicKey == null) {
                System.err.println("Unknown model IP: " + modelIp);
                return false;
            }
            
            // TODO: verify signature
            return true;
        } catch (Exception e) {
            System.err.println("Error verifying signature: " + e.getMessage());
            return false;
        }
    }
    
    /**
     * Calculate similarity between a response and the ground truth
     * Higher score = more similar
     */
    private double calculateSimilarity(String response, String groundTruth) {
        try {
            // This is a simplified implementation - in a real system, you'd use more
            // sophisticated natural language processing to compare responses
            
            // Convert to lowercase and tokenize
            String[] respTokens = response.toLowerCase().split("\\W+");
            String[] truthTokens = groundTruth.toLowerCase().split("\\W+");
            
            // Count matching words
            Set<String> respSet = new HashSet<>(Arrays.asList(respTokens));
            Set<String> truthSet = new HashSet<>(Arrays.asList(truthTokens));
            
            int matchCount = 0;
            for (String token : respSet) {
                if (truthSet.contains(token)) {
                    matchCount++;
                }
            }
            
            // Calculate Jaccard similarity
            Set<String> union = new HashSet<>(respSet);
            union.addAll(truthSet);
            
            return (double) matchCount / union.size();
            
        } catch (Exception e) {
            System.err.println("Error calculating similarity: " + e.getMessage());
            return 0.0;
        }
    }
    
    /**
     * Process a challenge request transaction
     */
    private boolean processChallenge(Map<String, Object> txData) {
        // Process the challenge request
        if (CHALLENGE_STATE.equals(currentState)) {
            String sender = (String) txData.get("sender");
            @SuppressWarnings("unchecked")
            Map<String, String> challenges = (Map<String, String>) txData.get("challenges");
            
            if (challenges != null) {
                // Store the new challenges
                currentChallenges.putAll(challenges);
                
                // Move to response state
                currentState = RESPONSE_STATE;
                
                // Submit challenges to the verification node
                if (verificationNodeWrapper != null) {
                    for (String prompt : challenges.values()) {
                        try {
                            verificationNodeWrapper.submitChallenge(prompt);
                        } catch (Exception e) {
                            System.err.println("Error submitting challenge to verification node: " + e.getMessage());
                        }
                    }
                }
                
                return true;
            } else {
                System.err.println("Malformed challenge transaction: missing challenges");
                return false;
            }
        } else {
            System.err.println("Cannot process challenge in current state: " + currentState);
            return false;
        }
    }
    
    /**
     * Process a model response transaction
     */
    private boolean processResponse(Map<String, Object> txData) {
        if (RESPONSE_STATE.equals(currentState)) {
            String modelIp = (String) txData.get("model_ip");
            String prompt = (String) txData.get("prompt");
            String output = (String) txData.get("output");
            String digest = (String) txData.get("digest");
            String timestamp = (String) txData.get("timestamp");
            
            if (modelIp != null && prompt != null && output != null && digest != null) {
                // Verify the response signature
                if (verifySignature(output, digest, modelIp)) {
                    // Store the response
                    ModelResponse response = new ModelResponse(modelIp, prompt, output, digest, timestamp);
                    modelResponses.put(modelIp + ":" + prompt, response);
                    
                    // Use C++ verification node if available to check credibility
                    if (verificationNodeWrapper != null) {
                        try {
                            String result = verificationNodeWrapper.submitModelResponse(modelIp, prompt, output, digest);
                            System.out.println("Model response submitted to verification node: " + result);
                            
                            // Optional: use our local model to generate a response for comparison
                            if (verificationNodeWrapper.isModelLoaded()) {
                                String verificationResponse = verificationNodeWrapper.runModel(prompt, 512, 0.7f);
                                System.out.println("Verification model response: " + verificationResponse);
                            }
                        } catch (Exception e) {
                            System.err.println("Error submitting response to verification node: " + e.getMessage());
                        }
                    }
                    
                    // If all expected models have responded, move to evaluation
                    if (modelResponses.size() >= knownModelNodes.size() * currentChallenges.size()) {
                        currentState = EVALUATION_STATE;
                        System.out.println("Moving to EVALUATION state");
                    }
                    
                    return true;
                } else {
                    System.err.println("Invalid signature for response from " + modelIp);
                    return false;
                }
            } else {
                System.err.println("Malformed response transaction: missing required fields");
                return false;
            }
        } else {
            System.err.println("Cannot process response in current state: " + currentState);
            return false;
        }
    }
    
    /**
     * Process an evaluation transaction
     */
    private boolean processEvaluation(Map<String, Object> txData) {
        if (EVALUATION_STATE.equals(currentState) || txData.get("force") == Boolean.TRUE) {
            String modelIp = (String) txData.get("model_ip");
            
            // If the score is provided directly
            if (txData.containsKey("score")) {
                double score = ((Number) txData.get("score")).doubleValue();
                credibilityScores.put(modelIp, score);
                
                // Submit evaluation to verification node if available
                if (verificationNodeWrapper != null) {
                    try {
                        verificationNodeWrapper.submitEvaluation(modelIp, score);
                    } catch (Exception e) {
                        System.err.println("Error submitting evaluation to verification node: " + e.getMessage());
                    }
                }
                
                return true;
            } 
            // Otherwise, evaluate responses against ground truth
            else {
                double totalScore = 0;
                int promptCount = 0;
                
                for (String promptKey : currentChallenges.keySet()) {
                    String prompt = currentChallenges.get(promptKey);
                    String responseKey = modelIp + ":" + prompt;
                    
                    if (modelResponses.containsKey(responseKey)) {
                        ModelResponse response = modelResponses.get(responseKey);
                        String groundTruth = groundTruthResponses.get(prompt);
                        
                        if (groundTruth != null) {
                            double similarity = calculateSimilarity(response.output, groundTruth);
                            totalScore += similarity;
                            promptCount++;
                        }
                    }
                }
                
                if (promptCount > 0) {
                    double avgScore = totalScore / promptCount;
                    
                    // Update the model's score
                    Double currentScore = credibilityScores.getOrDefault(modelIp, 0.5);
                    
                    // Score adjustment logic
                    if (avgScore > SCORE_THRESHOLD) {
                        // Increase score if above threshold
                        credibilityScores.put(modelIp, Math.min(1.0, currentScore + SCORE_INCREMENT));
                    } else {
                        // Decrease score if below threshold (halve it)
                        credibilityScores.put(modelIp, currentScore / 2);
                    }
                    
                    // Submit the new score to verification node if available
                    if (verificationNodeWrapper != null) {
                        try {
                            verificationNodeWrapper.submitEvaluation(modelIp, credibilityScores.get(modelIp));
                        } catch (Exception e) {
                            System.err.println("Error submitting evaluation to verification node: " + e.getMessage());
                        }
                    }
                    
                    return true;
                } else {
                    System.err.println("No responses found for model " + modelIp);
                    return false;
                }
            }
        } else {
            System.err.println("Cannot process evaluation in current state: " + currentState);
            return false;
        }
    }
    
    /**
     * Clean up resources when shutting down
     */
    public void shutdown() {
        if (verificationNodeWrapper != null) {
            try {
                verificationNodeWrapper.shutdown();
            } catch (Exception e) {
                System.err.println("Error shutting down verification node wrapper: " + e.getMessage());
            }
        }
    }
} 