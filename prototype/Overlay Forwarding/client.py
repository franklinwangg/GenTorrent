from HashRadixTree.HashRadixTree import HashRadixTree
from HashRadixTree.ModelNode import ModelNode
from transformers import AutoTokenizer

MODEL_NAME = "meta-llama/Llama-3.1-8B-Instruct"
MAX_MODEL_CONCURRENCY = 4

model_list = [
    ModelNode(f"mnode{i}", f"http://127.0.0.1:800{i}/v1/completions", max_concurrency=MAX_MODEL_CONCURRENCY)
    for i in range(8)
]

class Client:
    __slots__ = ["hrt", "tokenizer"]

    def __init__(self):
        self.hrt = HashRadixTree(model_list)
        self.tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)

    def process_request(self, prompt: str):
        tokens = self.tokenizer.encode(prompt)
        model_node, hrt_node = self.hrt.find_match_model(tokens)
        # add logic to post to model node url
