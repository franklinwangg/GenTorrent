from BootstrapModelNode import BootstrapModelNode
from ClientNode import ClientNode
from ModelNode import ModelNode
import asyncio
import time

async def main():
    
    
    # bm = BootstrapModelNode()
    # c = Client()
    MODEL_NODES = 1
    CLIENT_NODES = 1
    MAX_MODEL_CONCURRENCY = 4
    
    model_list = [
        ModelNode(f"mnode{i}", "localhost", 8000 + i, max_concurrency=MAX_MODEL_CONCURRENCY)
        for i in range(MODEL_NODES)
    ]
    
    client_list = [
        ClientNode(f"cnode{i}", "localhost", 9000 + i,)
        for i in range(CLIENT_NODES)
    ]
    
    bootstrap_node = BootstrapModelNode("bootstrap-model-node", "localhost", 8765, MAX_MODEL_CONCURRENCY, model_list)
    
    await asyncio.sleep(5)  # pauses this coroutine for 5 seconds without blocking the event loop
    tasks = [mn.connect_to_node("ws://localhost:8765") for mn in model_list]
    await asyncio.gather(*tasks)
    
    # tasks = [client.connect_to_bootstrap_node(bootstrap_node) for client in client_list]
    # await asyncio.gather(*tasks)
    
    await asyncio.Future()

    
if __name__ == "__main__":
    asyncio.run(main())
    