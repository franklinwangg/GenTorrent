# from nodes.Broadcaster import Broadcaster
from nodes.Client import Client

import asyncio
import os

async def main():
    
    client1 = Client("client1", "127.0.0.1", 8001, "data/client1_prompts.txt")
    client2 = Client("client2", "127.0.0.1", 8002, "data/client2_prompts.txt")
    client3 = Client("client3", "127.0.0.1", 8003, "data/client3_prompts.txt")
    
    
    # base_dir = os.path.dirname(os.path.abspath(__file__))  # directory of the script
    # data_dir = os.path.join(base_dir, 'data')
    # client1_path = os.path.join(data_dir, 'client1_prompts.txt')
    # client2_path = os.path.join(data_dir, 'client2_prompts.txt')
    # client3_path = os.path.join(data_dir, 'client3_prompts.txt')

    # client1 = Client("client1", "127.0.0.1", 8001, client1_path)
    # client2 = Client("client1", "127.0.0.1", 8002, client2_path)
    # client3 = Client("client1", "127.0.0.1", 8003, client3_path)
    
    # client1 = Client("client1", "127.0.0.1", 8001, "/home/frank/Research/GenTorrent-danielsfork/small_prototype/Overlay Forwarding/data/client1_prompts.txt")
    # client2 = Client("client2", "127.0.0.1", 8002, "/home/frank/Research/GenTorrent-danielsfork/small_prototype/Overlay Forwarding/data/client2_prompts.txt")
    # client3 = Client("client3", "127.0.0.1", 8003, "/home/frank/Research/GenTorrent-danielsfork/small_prototype/Overlay Forwarding/data/client3_prompts.txt")
    
    
    # small_prototype/Overlay Forwarding/data/client1_prompts.txt
    # small_prototype/Overlay Forwarding/client_test.py
    
    # client_list = [client1, client2, client3]
    
    client1.set_neighbors([client2, client3])
    client2.set_neighbors([client1, client3])
    client3.set_neighbors([client1, client2])
    
    await asyncio.sleep(100)

if __name__ == "__main__":
    asyncio.run(main())