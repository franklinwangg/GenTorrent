import asyncio
import websockets
from ModelNode import ModelNode


class BootstrapModelNode(ModelNode):
    
    def __init__(self, name: str, host:str, port:int, max_concurrency: int = 1, model_nodes=None):
        super().__init__(name, host, port, max_concurrency)
        self.model_nodes = model_nodes or []
        
    async def start_listener(self):
        async with websockets.serve(self.handle_connection, self.host, self.port):
            print(f"Bootstrap node server started on ws://{self.host}:{self.port}")
            await asyncio.Future()  # Run forever
                

    # async def __handle_connection(self, websocket):
    #     print("New client connected")
        
    #     self.connections[websocket.remote_address] = websocket

    #     try:
    #         async for message in websocket:
    #             print(f"Received message: {message}")
    #             for model_node in self.model_nodes:
    #                 self.connections[model_node.name].send(f"From bootstrap model node: {message}")
    #     except websockets.ConnectionClosed:
    #         print("Client disconnected")
    #     finally:
    #         await websocket.close()

    # async def start_listener(self):
    #     async with websockets.serve(self.__handle_connection, self.host, self.port):
    #         print(f"Bootstrap model node server started on ws://{self.host}:{self.port}")
    #         await asyncio.Future()  # Run forever
