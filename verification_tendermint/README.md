# Verification Tendermint Application

A Tendermint-based application for verifying model node outputs against ground truth data and establishing consensus on credibility scores. This application implements a challenge-response mechanism where each node has a ground truth model to compare against.

## Setup Instructions

### Prerequisites
- Java 11 or higher
- Gradle
- Tendermint Core
- C++ compiler with C++17 support
- CMake 3.10 or higher
- OpenSSL development libraries
- cURL development libraries
- nlohmann/json library

### Step 1: Build the C++ Verification Node
First, you need to build the C++ verification_node executable:

```bash
# From the root of the GenTorrent project
mkdir -p build
cd build
cmake ..
make verification_node
```

This will create the `verification_node` executable in the build directory.

### Step 2: Configure the Tendermint Application
The Java application needs to know where to find the verification_node executable. You can configure this in the `config.properties` file:

```properties
# Path to the verification_node executable
verification.node.path=/path/to/GenTorrent/build/verification_node
```

### Step 3: Build and Run the Tendermint Application
```bash
# From the verification_tendermint directory
./gradlew build
./gradlew run
```

## Protocol Flow

1. **Challenge Phase**: A leader node submits challenge prompts for model nodes.
2. **Response Phase**: Model nodes generate responses to the challenge prompts and submit them with a signed digest.
3. **Evaluation Phase**: Responses are automatically evaluated against ground truth data, and model scores are updated.

## Scoring Mechanism

Models are identified by their IP addresses, and each node maintains a score for every known model. The scoring rules are described in our paper.

## Message Format

Each model response includes:
- The model IP address
- The original prompt
- The model output
- A digest (hash) of the output signed with the model's private key
- A timestamp to prevent replay attacks

## Starting Tendermint

Initialize Tendermint (if not already done):
```bash
tendermint init
```

Start Tendermint and point it to our application:
```bash
tendermint node --abci grpc --proxy_app tcp://127.0.0.1:26658
```

## API Endpoints

- `/tx` - Submit transactions (POST)
- `/query?path={path}` - Query application state (GET)
- `/commit` - Commit current state (GET)

## Transaction Types

1. **Challenge**: Initiates a new round of challenges
2. **Response**: Submits a model's response to a challenge
3. **Evaluation**: Manually overrides a model's score (leader only)

## Troubleshooting

### Verification Node Not Found
If you get an error like `Failed to start verification node process: error=2, No such file or directory`, make sure:

1. You've built the verification_node executable in the GenTorrent/build directory
2. The path in config.properties is correct
3. The verification_node executable has execute permissions

You can check the executable exists with:
```bash
ls -la /path/to/GenTorrent/build/verification_node
```

And ensure it has execute permissions:
```bash
chmod +x /path/to/GenTorrent/build/verification_node
``` 