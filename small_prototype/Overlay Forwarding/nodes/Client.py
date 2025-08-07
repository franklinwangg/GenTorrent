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
        asyncio.create_task(self.start_server())

        await self._server_ready.wait()
        await self._neighbors_ready.wait()

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
        uri = f"ws://{neighbor.host}:{neighbor.port}"
        while True:
            try:
                websocket = await websockets.connect(uri)
                self.neighbor_connections[neighbor] = websocket
                print(f"Client {self.name} is [CONNECTED] to neighbor {neighbor.name}")
                return
            except Exception as e:
                print(f"[RETRYING] WebSocket connection to {neighbor.name} failed: {e}")
                await asyncio.sleep(1)
                
                
            
    # async def start_server(self):
        
    #     def handler(websocket, path):
    #         print(f"Client joined on {path}.")
            
    #         try:
    #             for message in websocket:
    #                 print(f"Received message: {message}")
    #         except websockets.exceptions.ConnectionClosed as error:
    #             print(f"Client disconnected: {error}")
                
                
        # async def handler(connection: ServerConnection):
        #     self.connected_client_links.add(connection)
        #     print("client joined")
        #     try:
        #         async for message in connection:
        #             print(f"Broadcaster received message: {message}")
                    
        #             json_to_hrt = HashRadixTree.json_to_tree(message)
        #             self.hrt_list.append(json_to_hrt) # need to convert to hrt?
                    
        #             if len(self.hrt_list) >= len(self.connected_client_links):
        #                 self.all_trees_aggregated.set()
        #             # erase all the entries from the hrt_list afterward
        # server = await websockets.serve(handler, )
        # print(f"Server started on {self.host}:{self.port}")
        # # Keep server alive in background
        # asyncio.create_task(server.wait_closed())

        # # Launch a forever task so this coroutine doesn't return
        # asyncio.create_task(self._keep_alive())
        # self._server_ready.set()

        # print(f"Client {self.name}'s server started.")
        
        
        
        
        
        
    async def start_server(self):
        # 1) start server - 
        async def handler(connection: ServerConnection):
            print(f"Client joined on {self.name}.")
            try:
                async for message in connection:
                    print(f"Client received message: {message}")
                    
                    # erase all the entries from the hrt_list afterward
                
            except websockets.ConnectionClosed:
                print("Client disconnected")
            # finally:
            #     self.connected_client_links.remove(connection)
        
        server = await websockets.serve(handler, self.host, self.port)
        asyncio.create_task(server.wait_closed())
        self._server_ready.set()
        
        
        
        
        
        
        

    # async def start_server(self):
    #     async def handler(connection: ServerConnection):
    #         print("client joined")
    #         try:
    #             async for message in connection:
    #                 print(f"Broadcaster received message: {message}")
                    
    #                 # erase all the entries from the hrt_list afterward
                
    #         except websockets.ConnectionClosed:
    #             print("Client disconnected")
    #         # finally:
    #         #     self.connected_client_links.remove(connection)

    #     self.server = await websockets.serve(handler, self.host, self.port)
    #     print("Broadcaster server started.")
    #     self._server_ready.set()  # Notify clients that server is ready









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
        
                    
        tokens_dict = token_ids.data  # or tokens.to_dict()
        json_string = json.dumps(tokens_dict)

        # 2) send the hash to all neighbors
        for neighbor in self.neighbor_connections:
            await self.neighbor_connections[neighbor].send(json_string)