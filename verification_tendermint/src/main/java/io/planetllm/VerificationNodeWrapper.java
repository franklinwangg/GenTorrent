package io.planetllm;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.JsonNode;

import java.io.IOException;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.Base64;
import java.util.logging.Logger;
import java.util.logging.Level;
import java.nio.file.Paths;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * A Java wrapper for the C++ VerificationNode implementation that connects to Tendermint
 */
public class VerificationNodeWrapper {
    private static final Logger LOGGER = Logger.getLogger(VerificationNodeWrapper.class.getName());
    private final ObjectMapper objectMapper = new ObjectMapper();
    
    // Connection to the native verification node
    private Process verificationNodeProcess;
    
    // Map to store model credibility scores
    private final Map<String, Double> modelScores = new ConcurrentHashMap<>();
    
    // Communication pipe with the C++ process
    private BufferedReader processOutput;
    private Process nativeProcess;
    
    // Flag to track if the model is loaded
    private boolean modelLoaded = false;
    
    // Path to the verification node executable
    private String verificationNodePath = null;
    
    /**
     * Sets the path to the verification node executable
     * @param path Path to the verification_node executable
     */
    public void setVerificationNodePath(String path) {
        if (path != null && Files.exists(Paths.get(path)) && Files.isExecutable(Paths.get(path))) {
            this.verificationNodePath = path;
            LOGGER.info("Set verification node path to: " + path);
        } else {
            LOGGER.warning("Invalid verification node path: " + path);
        }
    }
    
    /**
     * Initializes the VerificationNodeWrapper and starts the C++ verification node process
     */
    public void initialize() {
        try {
            // Find the verification_node executable
            if (verificationNodePath == null) {
                String[] possiblePaths = {
                    "/home/fang/Documents/lab/GenTorrent/build/verification_node",  // Absolute path
                    "../../build/verification_node",  // Relative to project root
                    "../build/verification_node"      // Another possibility
                };
                
                for (String path : possiblePaths) {
                    Path p = Paths.get(path);
                    if (Files.exists(p) && Files.isExecutable(p)) {
                        verificationNodePath = p.toString();
                        LOGGER.info("Found verification_node executable at: " + verificationNodePath);
                        break;
                    }
                }
                
                if (verificationNodePath == null) {
                    LOGGER.severe("verification_node executable not found! Checked paths: " + Arrays.toString(possiblePaths));
                    throw new IOException("verification_node executable not found in expected locations");
                }
            }
            
            // Start the verification node as a separate process
            ProcessBuilder processBuilder = new ProcessBuilder(verificationNodePath);
            processBuilder.redirectErrorStream(true);
            
            nativeProcess = processBuilder.start();
            processOutput = new BufferedReader(new InputStreamReader(nativeProcess.getInputStream()));
            
            // Start a thread to continuously read from the process output
            startOutputReader();
            
            LOGGER.info("VerificationNodeWrapper initialized successfully");
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, "Failed to start verification node process", e);
            throw new RuntimeException("Failed to start verification node process", e);
        }
    }
    
    /**
     * Starts a thread that reads output from the C++ process
     */
    private void startOutputReader() {
        CompletableFuture.runAsync(() -> {
            try {
                String line;
                while ((line = processOutput.readLine()) != null) {
                    // Process output from the verification node
                    processNodeOutput(line);
                }
            } catch (IOException e) {
                LOGGER.log(Level.SEVERE, "Error reading from verification node process", e);
            }
        });
    }
    
    /**
     * Processes output from the verification node process
     * @param line Output line from the process
     */
    private void processNodeOutput(String line) {
        try {
            // Try to parse as JSON
            if (line.startsWith("{") && line.endsWith("}")) {
                JsonNode jsonOutput = objectMapper.readTree(line);
                
                // Check if it's a score update
                if (jsonOutput.has("type") && "score_update".equals(jsonOutput.get("type").asText())) {
                    String modelIp = jsonOutput.get("model_ip").asText();
                    double score = jsonOutput.get("score").asDouble();
                    
                    // Update score in local map
                    modelScores.put(modelIp, score);
                    LOGGER.info("Updated score for model " + modelIp + ": " + score);
                }
                
                // Check if it's a model load status update
                if (jsonOutput.has("type") && "model_status".equals(jsonOutput.get("type").asText())) {
                    modelLoaded = jsonOutput.has("loaded") && jsonOutput.get("loaded").asBoolean();
                    LOGGER.info("Model load status updated: " + (modelLoaded ? "Loaded" : "Not loaded"));
                }
            } else {
                // Regular log output
                LOGGER.info("Verification node: " + line);
            }
        } catch (Exception e) {
            // Not a JSON or other error
            LOGGER.fine("Verification node output: " + line);
        }
    }
    
    /**
     * Sends a command to the verification node process
     * @param command The command to send
     * @return The result from the command
     */
    public String sendCommand(String command) {
        try {
            if (nativeProcess == null || !nativeProcess.isAlive()) {
                LOGGER.severe("Verification node process is not running");
                return "{\"error\": \"Verification node process is not running\"}";
            }
            
            // Write command to process stdin
            nativeProcess.getOutputStream().write((command + "\n").getBytes(StandardCharsets.UTF_8));
            nativeProcess.getOutputStream().flush();
            
            // For synchronous commands, we would need to implement a request-response protocol
            // with the C++ process. For now, return a simple acknowledgment.
            return "{\"status\": \"command_sent\"}";
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, "Error sending command to verification node", e);
            return "{\"error\": \"" + e.getMessage() + "\"}";
        }
    }
    
    /**
     * Loads a model from the given path
     * @param modelPath Path to the model file
     * @return Result of the operation
     */
    public String loadModel(String modelPath) {
        String command = objectMapper.createObjectNode()
            .put("action", "load_model")
            .put("model_path", modelPath)
            .toString();
        
        return sendCommand(command);
    }
    
    /**
     * Runs the loaded model with the given prompt
     * @param prompt The prompt to send to the model
     * @param maxTokens Maximum number of tokens to generate
     * @param temperature Temperature parameter for generation
     * @return The model's response
     */
    public String runModel(String prompt, int maxTokens, float temperature) {
        try {
            if (!modelLoaded) {
                LOGGER.warning("Model not loaded, attempting to run anyway");
            }
            
            String command = objectMapper.createObjectNode()
                .put("action", "run_model")
                .put("prompt", prompt)
                .put("max_tokens", maxTokens)
                .put("temperature", temperature)
                .toString();
            
            return sendCommand(command);
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Error running model", e);
            return "{\"error\": \"" + e.getMessage() + "\"}";
        }
    }
    
    /**
     * Checks if a model is loaded
     * @return true if a model is loaded
     */
    public boolean isModelLoaded() {
        return modelLoaded;
    }
    
    /**
     * Submits a challenge to be broadcast to the network
     * @param prompt The challenge prompt
     * @return Result of the operation
     */
    public String submitChallenge(String prompt) {
        String command = objectMapper.createObjectNode()
            .put("action", "submit_challenge")
            .put("prompt", prompt)
            .toString();
        
        return sendCommand(command);
    }
    
    /**
     * Submits a model response to be verified and broadcast
     * @param modelIp The IP of the model
     * @param prompt The prompt that was given to the model
     * @param output The model's output
     * @param signature Digital signature of the output
     * @return Result of the operation
     */
    public String submitModelResponse(String modelIp, String prompt, String output, String signature) {
        try {
            String command = objectMapper.createObjectNode()
                .put("action", "submit_response")
                .put("model_ip", modelIp)
                .put("prompt", prompt)
                .put("output", output)
                .put("signature", signature)
                .toString();
            
            return sendCommand(command);
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Error submitting model response", e);
            return "{\"error\": \"" + e.getMessage() + "\"}";
        }
    }
    
    /**
     * Manually submits an evaluation for a model
     * @param modelIp The IP of the model
     * @param score The score to assign
     * @return Result of the operation
     */
    public String submitEvaluation(String modelIp, double score) {
        String command = objectMapper.createObjectNode()
            .put("action", "submit_evaluation")
            .put("model_ip", modelIp)
            .put("score", score)
            .toString();
        
        return sendCommand(command);
    }
    
    /**
     * Gets the current scores for all known models
     * @return Map of model IPs to scores
     */
    public Map<String, Double> getModelScores() {
        return new HashMap<>(modelScores);
    }
    
    /**
     * Gets the current score for a specific model
     * @param modelIp The IP of the model
     * @return The model's credibility score, or null if not found
     */
    public Double getModelScore(String modelIp) {
        return modelScores.get(modelIp);
    }
    
    /**
     * Checks if a model's score meets the minimum threshold
     * @param modelIp The IP of the model to check
     * @param threshold The threshold value
     * @return true if the model's score is at or above the threshold
     */
    public boolean isModelTrustworthy(String modelIp, double threshold) {
        Double score = getModelScore(modelIp);
        return score != null && score >= threshold;
    }
    
    /**
     * Cleans up resources when the wrapper is no longer needed
     */
    public void shutdown() {
        try {
            if (nativeProcess != null && nativeProcess.isAlive()) {
                // Send exit command to the process
                sendCommand("{\"action\": \"exit\"}");
                
                // Give it some time to clean up
                Thread.sleep(1000);
                
                // Force termination if still alive
                if (nativeProcess.isAlive()) {
                    nativeProcess.destroy();
                }
            }
            
            if (processOutput != null) {
                processOutput.close();
            }
            
            LOGGER.info("VerificationNodeWrapper shutdown complete");
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Error during shutdown", e);
        }
    }
} 