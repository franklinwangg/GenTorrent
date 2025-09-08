# from nodes.Broadcaster import Broadcaster
from nodes.Client import Client

import asyncio
import os
import networkx as nx
import random

async def main():

    CLIENT_HOST = "127.0.0.1"
    BASE_PORT = 7001
    CLIENT_TEST_PROMPTS_PATH = "data/client1_prompts.txt"

    # Create a network of 100 clients
    G = nx.erdos_renyi_graph(n=100, p=0.05)  # 5% chance of an edge between nodes
    
    print("1")

    for i, node in enumerate(G.nodes()):
        G.nodes[node]['client'] = Client(
            "client" + str(i),
            CLIENT_HOST,
            BASE_PORT + i,  # unique port for each client
            CLIENT_TEST_PROMPTS_PATH
        )

    print("2")
    
    for u, v in G.edges():
        G.nodes[u]['client'].add_neighbor(G.nodes[v]['client'])
        G.nodes[v]['client'].add_neighbor(G.nodes[u]['client'])
    print("3")

            
    for node in G.nodes():
        G.nodes[node]['client'].set_neighbors_ready()

    print("4")
    await asyncio.sleep(100)
    print("5")

        

        

    
    # client1 = Client("client1", "127.0.0.1", 8001, "data/client1_prompts.txt")
    # client2 = Client("client2", "127.0.0.1", 8002, "data/client2_prompts.txt")
    # client3 = Client("client3", "127.0.0.1", 8003, "data/client3_prompts.txt")
    
    # client1.set_neighbors([client2, client3])
    # client2.set_neighbors([client1, client3])
    # client3.set_neighbors([client1, client2])
    
    # await asyncio.sleep(100)

if __name__ == "__main__":
    asyncio.run(main())