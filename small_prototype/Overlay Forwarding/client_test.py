# from nodes.Broadcaster import Broadcaster
from nodes.Client import Client

import asyncio
import os

async def main():
    
    client1 = Client("client1", "127.0.0.1", 8001, "data/client1_prompts.txt")
    client2 = Client("client2", "127.0.0.1", 8002, "data/client2_prompts.txt")
    client3 = Client("client3", "127.0.0.1", 8003, "data/client3_prompts.txt")
    
    client1.set_neighbors([client2, client3])
    client2.set_neighbors([client1, client3])
    client3.set_neighbors([client1, client2])
    
    await asyncio.sleep(100)

if __name__ == "__main__":
    asyncio.run(main())