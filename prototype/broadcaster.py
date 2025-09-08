import asyncio
import websockets
import json
from nodes.Client import Client
from nodes.Broadcaster import Broadcaster

class Broadcaster:
    def __init__(self, broadcaster_uri):
        self.client_uri_list = []
        self.hrt = None
        
        self.start_server(broadcaster_uri)

    async def start_server(self, host='localhost', port=8000):
        print(f"Broadcaster listening on ws://{host}:{port}")
        async with websockets.serve(self.handle_connection, host, port):
            await self.aggregate_loop()

    async def handle_connection(self, websocket, path):

        # Get client IP and port as a simple "URI"
        client_ip, client_port = websocket.remote_address
        client_uri = f"{client_ip}:{client_port}"
        self.client_uri_list.append(client_uri)

        try:
            async for message in websocket:
                print(f"Received from client {client_uri}: {message}")
                data = json.loads(message)
                # Update client's HRT here
                # client.hrt.update_from_json(data)  # You must implement this
        except websockets.exceptions.ConnectionClosed:
            print(f"Client {client_uri} disconnected")
            self.client_uri_list.remove(client_uri)


    def add_client(self, client: Client):
        self.client_uri_list.append(client)
        print(f"Client added. Total: {len(self.client_uri_list)}")

    async def aggregate_loop(self):
        while True:
            await asyncio.sleep(1)  # aggregate every 1 second
            self.aggregate_broadcasts()

    def aggregate_broadcasts(self):
        if not self.client_uri_list:
            print("No clients to aggregate.")
            return

        print("Aggregating client trees...")
        aggregated = self.client_uri_list[0].hrt.copy()
        for client in self.client_uri_list[1:]:
            aggregated.merge(client.hrt)

        self.hrt = aggregated

        # Broadcast the HRT to all clients — if you want real broadcasting, you'd need websockets per client
        print("Broadcast complete.")
