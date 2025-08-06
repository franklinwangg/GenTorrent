# from nodes.Broadcaster import Broadcaster
from nodes.Client import Client

import asyncio

async def main():
    
    client1 = Client("client1", "127.0.0.1", 8001)
    client2 = Client("client2", "127.0.0.1", 8002)
    client3 = Client("client3", "127.0.0.1", 8003)
    
    # client_list = [client1, client2, client3]
    
    client1.set_neighbors([client2, client3])
    client2.set_neighbors([client1, client3])
    client3.set_neighbors([client1, client2])
    
    await asyncio.sleep(100)

if __name__ == "__main__":
    asyncio.run(main())