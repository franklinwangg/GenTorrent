import asyncio
import websockets
from websockets.exceptions import ConnectionClosed, InvalidURI, InvalidHandshake

        
class ModelNode:

    def __init__(self, name: str, host:str, port:int, max_concurrency: int = 1):
        self.host = host
        self.port = port
        self.name = name
        self.connections = {}
        
        # self.listener_task = asyncio.create_task(self.start_node())
        self.listener_task = asyncio.create_task(self.start_listener())

    async def start_node(self) :
        asyncio.create_task(self.start_listener())
    
    # async def handle_connection(self, websocket):
    #     # when you hear about a new client node, connect to it and add the connection to your self.connections

    #     self.connections[websocket.remote_address] = websocket

    #     try:
    #         async for message in websocket:
    #             sender, body = message
    #             if(sender == 'bootstrap-model-node'):
    #                 await self.connect_to_node(body)
                    
    #     except websockets.ConnectionClosed:
    #         print("Client disconnected")
    #     finally:
    #         await websocket.close()

    async def handle_connection(self, websocket):
        # Add the connection to dictionary
        self.connections[websocket.remote_address] = websocket
        print(f"[{self.name}] New connection from {websocket.remote_address}")

        try:
            async for message in websocket:
                print(f"[{self.name}] received message: {message}")
                # try:
                #     sender, body = message  # <-- assumes message is tuple-like
                # except Exception:
                #     print(f"[{self.name}] Malformed message: {message}")
                #     continue

                # if sender == "bootstrap-model-node":
                #     try:
                #         await self.connect_to_node(body)
                #     except Exception as e:
                #         print(f"[{self.name}] Failed to connect to node {body}: {e}")

        except ConnectionClosed:
            print(f"[{self.name}] Client {websocket.remote_address} disconnected")
        except Exception as e:
            print(f"[{self.name}] Error while handling {websocket.remote_address}: {e}")
        finally:
            # Cleanup
            print("cleaning up")
            if websocket.remote_address in self.connections:
                del self.connections[websocket.remote_address]
            await websocket.close()
    
    async def connect_to_node(self, url):
        new_conn = await websockets.connect(url)
        self.connections[url] = new_conn
        

    async def start_listener(self):
        try:
            async with websockets.serve(self.handle_connection, self.host, self.port):
                print(f"[{self.name}] Server started on ws://{self.host}:{self.port}")
                await asyncio.Future()  # Run forever
        except OSError as e:
            print(f"[{self.name}] Failed to bind to {self.host}:{self.port} (port in use?): {e}")
        except Exception as e:
            print(f"[{self.name}] Unexpected listener error: {e}")
    