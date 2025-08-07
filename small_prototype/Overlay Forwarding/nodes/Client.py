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
from websockets.asyncio.server import serve, ServerConnection

MODEL_NAME = "TinyLlama/TinyLlama-1.1B-Chat-v1.0"
MAX_MODEL_CONCURRENCY = 4

model_list = [
    ModelNode(f"mnode{i}", f"http://127.0.0.1:800{i}/v1/completions", max_concurrency=MAX_MODEL_CONCURRENCY)
    for i in range(8)
]

class Client:
    
    def __init__(self, name, host, port, prompt_path, neighbor_list = []):
        self.hrt = HashRadixTree(model_list)
        self.name = name
        self.neighbor_list = neighbor_list
        self.tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
        
        self.prompt_path = prompt_path
        
        self.neighbor_list = neighbor_list  # List of (host, port) tuples
        self.neighbor_connections = {}      # Map from neighbor to writer object
        
        self._server_ready = asyncio.Event()
        self._neighbors_ready = asyncio.Event()
        self._all_neighbors_connected = asyncio.Event()

        self.host = host
        self.port = port

        asyncio.create_task(self._wait_and_connect())

    
    def set_neighbors(self, neighbors):
        # Exclude self if needed
        self.neighbor_list = [n for n in neighbors if n.name != self.name]    
        self._neighbors_ready.set()
    
    # CONNECTION CODE
    
    async def _wait_and_connect(self):
        print("1")
        # await self.start_server()
        asyncio.create_task(self.start_server())
        print("2")

        await self._server_ready.wait()
        await self._neighbors_ready.wait()
        
        
        print("3")

        await self._wait_for_all_neighbors()
        await self.process_prompts()
        
                # prompts_task = asyncio.create_task(self.process_prompts())


    async def _wait_for_all_neighbors(self):
        print(f"{self.name} CURRENTLY WAITING ON NEIGHBORS")
        connect_tasks = [
            self._connect_to_neighbor(neighbor) 
            for neighbor in self.neighbor_list
        ]
        await asyncio.gather(*connect_tasks)
        print("[ALL CONNECTED] Proceeding to next step.")
        self._all_neighbors_connected.set()
        
    async def _connect_to_neighbor(self, neighbor):
        host, port = neighbor.host, neighbor.port
        while True:
            try:
                reader, writer = await asyncio.open_connection(host, port)
                self.neighbor_connections[neighbor] = (reader, writer)
                print(f"Client {self.name} is [CONNECTED] to neighbor {neighbor.name}")
                return
            except Exception as e:
                print(f"[RETRYING] Connection to {neighbor.name} failed, host : {host}, port : {port}, : {e}")
                await asyncio.sleep(1)  # Retry delay
                
            
    async def start_server(self):
        
        async def handler(connection: ServerConnection):
            # 1) figure out how the hrt vllm feeds prompts into clients
            print(f"Client joined on {self.name}.")
            try:
                async for message in connection:
                    print(f"Broadcaster received message: {message}")
                    
            except websockets.ConnectionClosed:
                print("Client disconnected")
            finally:
                self.neighbor_connections.pop(connection)
        
        server = await websockets.serve(handler, self.host, self.port)
        print(f"Server started on {self.host}:{self.port}")

        # Keep server alive in background
        asyncio.create_task(server.wait_closed())

        # Launch a forever task so this coroutine doesn't return
        asyncio.create_task(self._keep_alive())
        self._server_ready.set()

        print(f"Client {self.name}'s server started.")

    async def _keep_alive(self):
        await asyncio.Future()  # never completes
    async def process_prompts(self):
        
        # await self._all_neighbors_connected.wait()
        # 1) for each line in prompt_dataset, process it
        # 2) for each line, await it to be finished processing
        # 3) 
        try:
            with open(self.prompt_path, 'r') as f:
                lines = f.readlines()
        except Exception as e:
            print(f"[{self.name}] Error reading prompt file: {e}")
            return

        for line in lines:
            prompt = line.strip()
            if not prompt:
                continue
            print(f"[{self.name}] Processing prompt: {prompt}")
            await self.handle_prompt(prompt)

        print(f"[{self.name}] Finished processing all prompts.")
        
    async def handle_prompt(self, prompt): 
        
        # 1) send to tokenizer
        token_ids = self.tokenizer(prompt)
        
        # 1.1) find the match model. if it doesn't exist, insert a new leaf into the trie
        match_model, hash_radix_node = self.hrt.find_match_model(token_ids)
        
        # 1.2) send the prompt to the match model - TO BE IMPLEMENTED
        
        # 2) send the hash to all neighbors
        for neighbor in self.neighbor_connections:
            # 1) send a hash over to them
            writer = self.neighbor_connections[neighbor][1]

            # Step 1: Convert BatchEncoding to a serializable dictionary
            tokens_dict = token_ids.data  # or tokens.to_dict()

            # Step 2: Convert to JSON string
            json_string = json.dumps(tokens_dict)

            # Step 3: Encode to bytes
            writer.write(json_string.encode('utf-8'))

            # writer.write(token_ids)
            
            # 2) once they receive it, they insert it into their hrt's
            
        