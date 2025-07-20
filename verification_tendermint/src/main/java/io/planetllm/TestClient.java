package io.planetllm;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;


public class TestClient {
    private static final String SERVER_URL = "http://localhost:26658";
    private static final HttpClient HTTP_CLIENT = HttpClient.newHttpClient();
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    
    public static void main(String[] args) throws Exception {
        // Sample leader ID and model nodes
        // TODO: Replace with actual leader ID and model nodes
        String leaderId = "node1";
        String modelIp1 = "172.16.1.10";
        String modelIp2 = "172.16.1.11";
        
        System.out.println("Starting credibility test sequence...");
        
        Map<String, String> challenges = new HashMap<>();
        //TODO: replace with actual challenges
        // challenges.put(modelIp1, "The United States Congress");
        // challenges.put(modelIp2, "What is climate change?");
        
        submitChallengeRequest(leaderId, challenges);
        
        Thread.sleep(1000);
        
        String modelOutput1 = "is a bicameral legislature of the federal government of the United States consisting of the Senate and the House of Representatives.";
        submitModelResponse(modelIp1, challenges.get(modelIp1), modelOutput1);
        
        String modelOutput2 = "Climate change refers to long-term shifts in temperatures and weather patterns, mainly caused by human activities, especially the burning of fossil fuels.";
        submitModelResponse(modelIp2, challenges.get(modelIp2), modelOutput2);
        
        Thread.sleep(1000);
        
        queryApplicationState();
        
        submitEvaluation(leaderId, modelIp1, 0.95);
        
        Thread.sleep(1000);
        queryApplicationState();
        
        commitState();
        
        System.out.println("\nTest sequence completed.");
    }
    
    private static void submitChallengeRequest(String leaderId, Map<String, String> challenges) throws Exception {
        Map<String, Object> txData = new HashMap<>();
        txData.put("type", "challenge");
        txData.put("sender", leaderId);
        txData.put("challenges", challenges);
        txData.put("timestamp", System.currentTimeMillis() / 1000);
        txData.put("signature", "simulated_signature");
        
        sendTransaction(txData);
    }
    
    private static void submitModelResponse(String modelIp, String prompt, String output) throws Exception {
        Map<String, Object> txData = new HashMap<>();
        txData.put("type", "response");
        txData.put("model_ip", modelIp);
        txData.put("prompt", prompt);
        txData.put("output", output);
        txData.put("digest", "simulated_digest");
        txData.put("timestamp", System.currentTimeMillis() / 1000);
        
        sendTransaction(txData);
    }
    
    private static void submitEvaluation(String senderId, String modelIp, double score) throws Exception {
        Map<String, Object> txData = new HashMap<>();
        txData.put("type", "evaluation");
        txData.put("sender_id", senderId);
        txData.put("model_ip", modelIp);
        txData.put("score", score);
        txData.put("timestamp", System.currentTimeMillis() / 1000);
        txData.put("signature", "simulated_signature");
        
        sendTransaction(txData);
    }
    
    private static void sendTransaction(Map<String, Object> txData) throws Exception {
        String jsonTx = OBJECT_MAPPER.writeValueAsString(txData);
        
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(SERVER_URL + "/tx"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(jsonTx))
                .build();
        
        HttpResponse<String> response = HTTP_CLIENT.send(request, HttpResponse.BodyHandlers.ofString());
        System.out.println("Transaction response: " + response.body());
    }
    
    private static void queryApplicationState() throws Exception {
        queryPath("state");
        
        queryPath("challenges");
        
        queryPath("scores");
        
        queryModelScore("172.16.1.10");
        queryModelScore("172.16.1.11");
    }
    
    private static void queryPath(String path) throws Exception {
        String url = SERVER_URL + "/query?path=" + path;
        
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .GET()
                .build();
        
        HttpResponse<String> response = HTTP_CLIENT.send(request, HttpResponse.BodyHandlers.ofString());
        System.out.println("Query " + path + " response: " + response.body());
    }
    
    private static void queryModelScore(String modelIp) throws Exception {
        String url = SERVER_URL + "/query?path=model_score&model_ip=" + modelIp;
        
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .GET()
                .build();
        
        HttpResponse<String> response = HTTP_CLIENT.send(request, HttpResponse.BodyHandlers.ofString());
        System.out.println("Model " + modelIp + " score: " + response.body());
    }
    
    private static void commitState() throws Exception {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(SERVER_URL + "/commit"))
                .GET()
                .build();
        
        HttpResponse<String> response = HTTP_CLIENT.send(request, HttpResponse.BodyHandlers.ofString());
        System.out.println("Commit response: " + response.body());
    }
} 