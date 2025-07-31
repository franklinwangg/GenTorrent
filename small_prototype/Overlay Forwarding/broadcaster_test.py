from nodes.Broadcaster import Broadcaster
from nodes.Client import Client

import asyncio

async def main():
    broadcaster = Broadcaster("localhost", 8000)
    client = Client(broadcaster)
    
    await asyncio.sleep(10)
    
    # await broadcaster.start_server()
    # await client.join_broadcast_channel()
    # await client.__send_tree_to_broadcaster()
    # asyncio.create_task(broadcaster.run_server_forever())
    
    #     # Run client and keep server alive in parallel
    # await asyncio.gather(
    #     broadcaster.run_server_forever()  # the client
    # )

    # client1 = Client(broadcaster)
    # client2 = Client(broadcaster)
    # client3 = Client(broadcaster)

    # # Connect clients (assuming join_broadcast_channel connects only)
    # await asyncio.gather(
    #     client1.join_broadcast_channel(),
    #     client2.join_broadcast_channel(),
    #     client3.join_broadcast_channel(),
    # )

    # # Start listening tasks (make sure these keep running)
    # listeners = [
    #     asyncio.create_task(client1.start_listener()),
    #     asyncio.create_task(client2.start_listener()),
    #     asyncio.create_task(client3.start_listener()),
    # ]

    # # Wait a bit so clients can stabilize connections
    # await asyncio.sleep(1)

    # # Send broadcast
    # await broadcaster.send_broadcast("hello")
    # print("Broadcast sent")

    # # Keep the program running so listeners don't exit immediately
    # await asyncio.gather(*listeners)


if __name__ == "__main__":
    asyncio.run(main())