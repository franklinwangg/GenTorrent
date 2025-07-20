from Client import Client
import threading

class Broadcaster: 
    def __init__(self):
        self.hrt = None  # possibly a Hash Radix Tree?
        self.timer = None
        self.client_list = []

    def add_client(self, client: Client):
        if len(self.client_list) == 0:
            self.timer = threading.Timer(1.0, self.aggregate_broadcasts)
            self.timer.start()
            # self.hrt = client.hrt
        self.client_list.append(client)

    def aggregate_broadcasts(self):
        """
        Called periodically to 1) aggregate all the Hash-Radix Trees inside the Broadcaster, and
        2) set ALL of the clients in client_list's Hash-Radix Trees equal to the aggregated tree
        """
        # 1) aggregate all the Hash-Radix Trees inside the Broadcaster
        for client in self.client_list:
            if(len(client_list) == 0):
                self.hrt = client
            else:
                # aggregate the current client's hrt onto self.hrt
                pass
            
        # 2) set ALL of the clients in client_list's Hash-Radix Trees equal to the aggregated tree
        for client in self.client_list:
            client.hrt = self.hrt

        # Restart the timer if needed
        self.timer = threading.Timer(1.0, self.aggregate_broadcasts)
        self.timer.start()
