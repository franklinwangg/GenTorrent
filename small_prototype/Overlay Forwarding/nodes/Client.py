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


MODEL_NAME = "meta-llama/Llama-3.1-8B-Instruct"
MAX_MODEL_CONCURRENCY = 4

model_list = [
    ModelNode(f"mnode{i}", f"http://127.0.0.1:800{i}/v1/completions", max_concurrency=MAX_MODEL_CONCURRENCY)
    for i in range(8)
]

class Client:
    
    def __init__(self, name, host, port, neighbor_list = []):
        self.hrt = HashRadixTree(model_list)
        self.name = name
        self.neighbor_list = neighbor_list
        # self.tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
        
        self.neighbor_list = neighbor_list  # List of (host, port) tuples
        self.neighbor_connections = {}      # Map from neighbor to writer object
        
        self._neighbors_ready = asyncio.Event()
        self.host = host
        self.port = port

        asyncio.create_task(self._wait_and_connect())

    
    def set_neighbors(self, neighbors):
        # Exclude self if needed
        self.neighbor_list = [n for n in neighbors if n.name != self.name]    
        self._neighbors_ready.set()
    
    # CONNECTION CODE
    
    async def _wait_and_connect(self):
        await self.start_server()
        await self._neighbors_ready.wait()

        await self._wait_for_all_neighbors()
        await self._listen_broadcast_channel()

    async def _wait_for_all_neighbors(self):
        connect_tasks = [
            self._connect_to_neighbor(neighbor) 
            for neighbor in self.neighbor_list
        ]
        await asyncio.gather(*connect_tasks)
        print("[ALL CONNECTED] Proceeding to next step.")
        
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
                
    async def _listen_broadcast_channel(self):
        # Example placeholder — you’ll implement actual logic here
        print("[LISTENING] on broadcast channel")
        while True:
            print("client listening")
            await asyncio.sleep(1)
            
            
    async def start_server(self):
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
                
        #     except websockets.ConnectionClosed:
        #         print("Client disconnected")
        #     finally:
        #         self.connected_client_links.remove(connection)
        async def handler(connection: ServerConnection):
            print(f"Client joined on {self.name}.")

        self.server = await websockets.serve(handler, self.host, self.port)
        
        print(f"Client {self.name}'s server started.")        
        # asyncio.create_task(self.broadcast_loop())  # Starts server-wide logic