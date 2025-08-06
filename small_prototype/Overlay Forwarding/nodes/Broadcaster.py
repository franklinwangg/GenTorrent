import asyncio
import websockets
import json

# from websockets.server import ServerConnection
from websockets.asyncio.server import serve, ServerConnection
from HashRadixTree.HashRadixTree import HashRadixTree



class Broadcaster:
    def __init__(self, host, port):
        self.connected_client_links = set()
        self.hrt = None
        self.server = None
        self.host = host
        self.port = port
        self.ready = asyncio.Event()
        self.all_trees_aggregated = asyncio.Event()
        
        self.hrt_list = []
        
        self.ws_uri = f"ws://{host}:{port}"
        asyncio.create_task(self.start_server())
        
    async def start_server(self):
        async def handler(connection: ServerConnection):
            self.connected_client_links.add(connection)
            print("client joined")
            try:
                async for message in connection:
                    print(f"Broadcaster received message: {message}")
                    
                    json_to_hrt = HashRadixTree.json_to_tree(message)
                    self.hrt_list.append(json_to_hrt) # need to convert to hrt?
                    
                    if len(self.hrt_list) >= len(self.connected_client_links):
                        self.all_trees_aggregated.set()
                    # erase all the entries from the hrt_list afterward
                
            except websockets.ConnectionClosed:
                print("Client disconnected")
            finally:
                self.connected_client_links.remove(connection)

        self.server = await websockets.serve(handler, self.host, self.port)
        print("Broadcaster server started.")
        self.ready.set()  # Notify clients that server is ready
        
        asyncio.create_task(self.broadcast_loop())  # Starts server-wide logic

    async def broadcast_loop(self):
        while True:
            await self.count_down(5)
            await self.ask_for_tree()
            
            while(len(self.hrt_list) < len(self.connected_client_links)):
                pass
            
            
    async def count_down(self, seconds):
        await asyncio.sleep(seconds)
            
    async def ask_for_tree(self):
        json_msg = {
            "type": "ask_for_tree"
        }
        await self.send_broadcast(json.dumps(json_msg))
        
    async def send_broadcast(self, message):
        print("sent broadcast : ", message)
        for link in self.connected_client_links:
            await link.send(message)

    async def handle_connection(self, connection: ServerConnection):
        self.connected_client_links.add(connection)
        print("client joined")
        try:
            async for message in connection:
                print(f"Received message: {message}")
                # Process message or broadcast to others
        except websockets.ConnectionClosed:
            print("Client disconnected")
        finally:
            self.connected_client_links.remove(connection)

    async def aggregate_loop(self):
        async with websockets.connect(self.ws_uri) as websocket:
            print("inside websocket connection")
            while True:
                print("running client")
                try:
                    message = await websocket.recv()
                    print(f"Received from client: {message}")
                    data = json.loads(message)

                    await asyncio.sleep(1)  # Aggregate every 1 second
                except websockets.ConnectionClosed:
                    print("WebSocket connection closed.")
                    break
                except json.JSONDecodeError:
                    print("Invalid JSON received.")