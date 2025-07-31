import asyncio
import websockets
import json

# from websockets.server import ServerConnection
from websockets.asyncio.server import serve, ServerConnection


class Broadcaster:
    def __init__(self, host, port):
        self.connected_client_links = set()
        self.hrt = None
        self.server = None
        self.host = host
        self.port = port
        self.ready = asyncio.Event()
        
        self.ws_uri = f"ws://{host}:{port}"
        asyncio.create_task(self.start_server())
        
    async def start_server(self):
        async def handler(connection: ServerConnection):
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

        self.server = await websockets.serve(handler, self.host, self.port)
        print("Broadcaster server started.")
        self.ready.set()  # Notify clients that server is ready
        
    async def run_server_forever(self):
        await self.aggregate_loop()
        
    async def send_broadcast(self, message):
        print("sent broadcast : ", message)
        for link in self.connected_client_links:
            await link.send(message)


    # async def handle_connection(self, websocket, path):
    #     # Get client IP and port as a simple "URI"
    #     self.connected_client_links.add(websocket)
    
    # async def handle_connection(self, connection: ServerConnection):
    #     self.connected_client_links.add(connection)
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

    






    # async def aggregate_loop(self):
    #     while True:
    #         await asyncio.sleep(1)  # aggregate every 1 second
    #         print("Aggregating loop.")
    #         # self.aggregate_broadcasts()
           
    #         async for message in websocket:
    #             print(f"Received from client : {message}")
    #             data = json.loads(message)
            

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