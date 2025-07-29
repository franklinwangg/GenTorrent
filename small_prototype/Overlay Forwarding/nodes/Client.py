# 1) Each client should have: An instance of the hash radix tree, Methods to modify its tree, A way to receive and apply a new global tree
# 2) The broadcaster will: Periodically collect all clients’ trees, Merge them into a single tree, Broadcast that tree back to each client
# 3) convert the hrt into json, send over websocket, then convert the json back into an hrt

import asyncio
import websockets
import json

from HashRadixTree.HashRadixTree import HashRadixTree
from HashRadixTree.ModelNode import ModelNode
from transformers import AutoTokenizer
from nodes.Broadcaster import Broadcaster

MODEL_NAME = "meta-llama/Llama-3.1-8B-Instruct"
MAX_MODEL_CONCURRENCY = 4

model_list = [
    ModelNode(f"mnode{i}", f"http://127.0.0.1:800{i}/v1/completions", max_concurrency=MAX_MODEL_CONCURRENCY)
    for i in range(8)
]

class Client:
    __slots__ = ["hrt", "tokenizer", "broadcaster"]

    def __init__(self, broadcaster):
        self.hrt = HashRadixTree(model_list)
        # self.tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
        self.broadcaster = broadcaster
        # join the broadcaster thing
        
    # CONNECTION CODE
    
    async def join_broadcast_channel(self):
        
        broadcaster_uri = f"ws://{self.broadcaster.host}:{self.broadcaster.port}"
        async with websockets.connect(broadcaster_uri) as websocket:
            print("Client connected to broadcaster")
            
    async def start_listener(self):
        while(True):
            await asyncio.sleep(1)
            print("starting client listener")
            
    async def __send_tree_to_broadcaster(self, websocket):
        tree_to_json = self.__convert_tree_to_json()
        await websocket.send(json.dumps({
            "type": "client_tree",
            "data": tree_to_json
        }))

    def __convert_tree_to_json(self):
        # You need to implement this method in HashRadixTree
        return self.hrt.to_json()

    async def __receive_tree_from_broadcaster(self, json_data):
        tree_obj = json.loads(json_data)
        self.hrt = HashRadixTree.from_json(tree_obj)  # You must implement `from_json` in your class
    
    async def register_with_broadcaster(self, broadcaster):
        broadcaster.add_client(self)

    # async def process_request(self, prompt: str):
    #     tokens = self.tokenizer.encode(prompt)
    #     model_node, hrt_node = self.hrt.find_match_model(tokens)
    #     model_node.send_prompt(prompt)
        