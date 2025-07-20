package io.planetllm;

/**
 * Main application entry point for the PlanetLLM Credibility Application.
 */
public class App {
    public static void main(String[] args) {
        System.out.println("Starting PlanetLLM Credibility Application...");
        
        try {
            // Create the application instance
            CredibilityApp app = new CredibilityApp();
            
            // Create and start the server
            GrpcServer server = new GrpcServer(app, 26658);
            server.start();
            
            System.out.println("Server started successfully on port 26658");
            System.out.println("Press Ctrl+C to stop the server");
            
            // Keep the application running
            while (true) {
                try {
                    Thread.sleep(1000);
                } catch (InterruptedException e) {
                    break;
                }
            }
        } catch (Exception e) {
            System.err.println("Failed to start application: " + e.getMessage());
            e.printStackTrace();
        }
    }
} 