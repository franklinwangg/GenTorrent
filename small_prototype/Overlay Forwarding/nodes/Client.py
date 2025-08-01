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
    __slots__ = ["name", "hrt", "tokenizer", "broadcaster"]

    def __init__(self, name, broadcaster):
        self.hrt = HashRadixTree(model_list)
        self.name = name
        # self.tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
        self.broadcaster = broadcaster
        asyncio.create_task(self._wait_and_connect())

        
    # CONNECTION CODE
    async def _wait_and_connect(self):
        await self.broadcaster.ready.wait()  # Wait for broadcaster readiness
        await self.listen_broadcast_channel()
    
    async def listen_broadcast_channel(self):
        broadcaster_uri = f"ws://{self.broadcaster.host}:{self.broadcaster.port}"
        async with websockets.connect(broadcaster_uri) as websocket:
            print(f"Client {self.name} connected to broadcaster")
            # await self.__send_tree_to_broadcaster(websocket)
            
            # Now listen for messages from the broadcaster
            try:
                async for message in websocket:
                    try:
                        msg = json.loads(message)
                        msg_type = msg.get("type")
                        if msg_type == "ask_for_tree":
                            print(f"Client {self.name} received asking for tree : {message}")
                        elif msg_type == "set_tree":
                            print(f"Client {self.name} received set tree : {message}")
                        else:
                            print(f"Client {self.name} received different message : {message}")
                    except Exception as e:
                        print("Error processing message:", e)
                
                    # async for message in websocket:
                    #     try:
                    #         msg = json.loads(message)
                    #         msg_type = msg.get("type")
                            
                    #         if msg_type == "tree_update":
                    #             await self.__receive_tree_from_broadcaster(msg["data"])
                    #         elif msg_type == "ping":
                    #             print("Ping received:", msg["data"])
                    #         elif msg_type == "command":
                    #             await self.handle_command(msg["data"])
                    #         else:
                    #             print("Unknown message type:", msg_type)
                    #     except Exception as e:
                    #         print("Error processing message:", e)


                    # await self.__receive_tree_from_broadcaster(message)
            except websockets.ConnectionClosed:
                print("Connection to broadcaster closed.")    
                
    
    async def __send_tree_to_broadcaster(self, websocket):
        await websocket.send("hello")