# for X in {0..2}
# do
#   echo "[INFO] Launching vLLM instance mnode$X on GPU $X (port 800$X)..."
#   CUDA_VISIBLE_DEVICES=$X python3 -m vllm.entrypoints.openai.api_server \
#     --model TinyLlama/TinyLlama-1.1B-Chat-v1.0 \
#     --served-model-name mnode$X \
#     --trust-remote-code \
#     --tensor-parallel-size 1 \
#     --pipeline-parallel-size 1 \
#     --max-num-seqs 4 \
#     --port 800$X > logs/llama3_$X.log 2>&1 &
# done

# for X in {0..2}
# do
#   echo "[INFO] Launching vLLM instance mnode$X on GPU $X (port 800$X)..."
#   CUDA_VISIBLE_DEVICES=$X python3 -m vllm.entrypoints.openai.api_server \
#     --model TinyLlama/TinyLlama-1.1B-Chat-v1.0 \
#     --served-model-name mnode$X \
#     --trust-remote-code \
#     --tensor-parallel-size 1 \
#     --pipeline-parallel-size 1 \
#     --max-num-seqs 1 \
#     --port 800$X > logs/llama3_$X.log 2>&1 &
# done

for X in 0
do
  echo "[INFO] Launching vLLM instance mnode$X on GPU $X (port 800$X)..."
  CUDA_VISIBLE_DEVICES=$X python3 -m vllm.entrypoints.openai.api_server \
    --model keeeeenw/MicroLlama \
    --served-model-name mnode$X \
    --trust-remote-code \
    --tensor-parallel-size 1 \
    --pipeline-parallel-size 1 \
    --gpu-memory-utilization 0.6 \
    --max-num-seqs 1 \
    --port 800$X > logs/microllama_$X.log 2>&1 &
done
