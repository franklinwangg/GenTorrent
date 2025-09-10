# import asyncio
# import websockets
# import json
# import aiohttp

# from time import perf_counter

# from HashRadixTree.HashRadixTree import HashRadixTree
# from HashRadixTree.ModelNode import ModelNode
# from transformers import AutoTokenizer
# from websockets.asyncio.server import serve, ServerConnection

# MODEL_NAME = "TinyLlama/TinyLlama-1.1B-Chat-v1.0"
# MAX_MODEL_CONCURRENCY = 4

# model_list = [
#     ModelNode(f"mnode{i}", f"http://127.0.0.1:800{i}/v1/completions", max_concurrency=MAX_MODEL_CONCURRENCY)
#     for i in range(1)
# ]

# class Client:
    
#     # connect to bootstrap model node, listen for the model node's request to connect, 
#     # listen for heartbeats from the model nodes and update the bf table accordingly(and then return an ACK to the model node)
    
#     def __init__(self, name, host, port, prompt_path, neighbor_list = []):
        
        
#         self.hrt = HashRadixTree([])
        
        
# client.py
import asyncio
import websockets
import time

class ClientNode:
    
    # (self, name: str, url: str, max_concurrency: int = 1, model_nodes=None):
    def __init__(self, name: str, host:str, port:int, max_concurrency: int = 1):
        self.host = host
        self.port = port
        self.name = name
        self.bf_dictionary = {}
        self.listener_task = asyncio.create_task(self.start_listener())

        
    async def __handle_connection(self, websocket):
        print("New client connected")
        try:
            async for message in websocket:
                # client will also have to keep track of all the web socket connections
                pass
        except websockets.ConnectionClosed:
            print("Client disconnected")
        finally:
            await websocket.close()
        
    async def start_listener(self):
        
        async with websockets.serve(self.__handle_connection, self.host, self.port):
            print(f"Client server started on ws://{self.host}:{self.port}")
            await asyncio.Future()  # Run forever



    async def connect_to_bootstrap_node(self, bootstrap_node_url):
        
        async with websockets.connect(bootstrap_node_url) as conn:
            await conn.send(f"Client URL : {bootstrap_node_url}")
            