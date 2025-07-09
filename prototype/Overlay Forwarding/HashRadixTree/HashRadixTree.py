from collections import deque
from pyexpat import model
from typing import Dict, List, Tuple
from transformers import AutoTokenizer
from .ModelNode import ModelNode
import random

##############################################################################
#                       HASH RADIX TRIE CLASSES
##############################################################################

class HashRadixNode:
    """
    A node in the HashRadix trie, storing children keyed by hash values
    and a marker for the end of a sequence.
    """
    __slots__ = ["children", "is_end", "model_list"]

    def __init__(self) -> None:
        self.children: Dict[int, "HashRadixNode"] = {}
        self.model_list = []
        self.is_end: bool = False

    def merge(self, other: "HashRadixNode") -> None:
        self.model_list.extend(other.model_list)
        for key, child in other.children.items():
            if key in self.children:
                self.children[key].merge(child)
            else:
                self.children[key] = child

class HashRadixTree:
    def __init__(self,
                 first_workload,
                 first_mnode,
                 candidate_models: List[ModelNode],
                 gate: int = 10,
                 model_num: int = 8,
                 chunk_size: int = 10) -> None:
        self.root = HashRadixNode()
        self.gate = gate
        self.chunk_size = chunk_size
        self.candidate_models = candidate_models
        # self.model_task = {model.name: model.pending_tasks for model in self.candidate_models}

        ### for toolbench case
        self.root1 = HashRadixNode()
        self.magic_ids = [128000, 2374, 25, 1472, 527, 9156, 38, 2898, 11, 499, 649, 1005, 1690, 7526, 2993, 82, 8, 311, 656, 279, 2768, 3465, 627,
                     5451, 358, 690, 3041, 499, 279, 3465, 4096, 11, 323, 701, 3465, 1212, 627, 1688, 1855, 3094, 11, 499, 1205, 311, 3041,
                     701, 3463, 311, 24564, 279, 2704, 1457, 323, 1148, 311, 656, 1828, 11, 449, 264, 734, 1650, 311, 3604, 3521, 1088, 701,
                     3094, 627, 6153, 279, 1650, 11, 499, 690, 636, 279, 1650, 1121, 11, 323, 499, 527, 1457, 304, 264, 502, 1614, 627, 12487,
                     499, 690, 24564, 701, 2704, 1457, 11, 1243, 10491, 1148, 311, 656, 1828, 9522, 6153, 1690, 320, 85269, 59997, 8, 13840,
                     11, 499, 5616, 2804, 279, 3465, 11, 1243, 499, 649, 3041, 701, 1913, 532, 4320, 627, 29690, 25, 720, 16, 42901, 1614,
                     2349, 374, 93294, 11, 499, 649, 956, 733, 1203, 311, 832, 315, 279, 4846, 1614, 11, 422, 499, 1390, 311, 17460, 279,
                     3465, 11, 2019, 330, 40, 3041, 709, 323, 17460, 23811, 17, 17182, 279, 3463, 374, 2875, 11, 520, 1455, 304, 220, 20,
                     11914, 627, 18, 39537, 649, 656, 810, 1243, 832, 490, 1065, 11, 779, 422, 701, 3197, 374, 311, 2018, 355, 398, 1456,
                     1063, 4787, 11, 499, 649, 656, 832, 315, 279, 4787, 824, 1456, 627, 10267, 596, 19110, 4999, 6396, 4096, 25, 1472, 1288,
                     1005, 5865, 311, 1520, 3790, 279, 1972, 892, 1217, 3319, 82, 13, 20474, 512, 16, 42163, 37641, 1650, 330, 26748, 1, 734,
                     520, 279, 842, 315, 279, 3465, 13, 1628, 279, 1620, 4320, 1288, 6782, 3403, 2038, 311, 1501, 311, 279, 1217, 11, 2746,
                     499, 649, 956, 3790, 279, 3465, 11, 477, 499, 1505, 430, 734, 6880, 2744, 3775, 31524, 734, 374, 539, 2764, 1457, 705,
                     1005, 734, 36633, 405, 47530, 8401, 8543, 70492, 627, 17, 34696, 539, 1005, 6371, 5507, 5144, 11, 1005, 1193, 1207, 22124,
                     6, 5144, 627, 2675, 617, 2680, 315, 279, 2768, 7526, 512, 16, 13]
        h_val = self.hash_chunk(self.magic_ids)
        self.root.children[h_val] = self.root1


        node = self.insert_workload(first_workload)
        self.assign_workload(first_mnode, node)

    def find_idle_node(self) -> str:
        task_list = {model.pending_tasks:model for model in self.candidate_models}
        sorted_models = sorted(self.candidate_models, key=lambda model: model.pending_tasks)
        return sorted_models[0]

    def assign_workload(self, modelnode, hrt_node) -> None:
        model_name = modelnode.name
        # modelnode.pending_tasks += 1
        # self.model_task[model_name] += 1

        if modelnode not in hrt_node.model_list:
            hrt_node.model_list.append(modelnode)
        # print(hrt_node.model_list)


    @staticmethod
    def hash_chunk(chunk: Tuple[int, ...], mod: int = 15) -> int:
        """
        Compute an integer hash for a tuple of token IDs. Collisions are possible
        for sufficiently large data, but for small chunk sizes and small mod,
        this is just a demonstration of the approach.
        """
        hash_val = 0
        for tid in chunk:
            hash_val = (hash_val * 31 + tid) % mod
        return hash_val

    def insert_workload(self, tokens) -> None:
        """
        Insert a sequence of chunks (each chunk a tuple of token IDs) into the trie.
        """
        current = self.root
        h_val = self.hash_chunk(self.magic_ids)
        current = current.children[h_val]

        # if isinstance(tokens, list):
        #     input_ids = tokens
        # else:
        if isinstance(tokens, list):
            input_ids = tokens
        else:
            input_ids = tokens["input_ids"].tolist()[0]



        total_tokens = len(input_ids)
        chunks: List[Tuple[int, ...]] = []

        i = 0

        while i < total_tokens:
            chunk = tuple(input_ids[i: i + self.chunk_size])
            chunks.append(chunk)
            i += self.chunk_size
            if int(i / self.chunk_size) > self.gate:
                break

            hval = self.hash_chunk(chunk)
            if hval not in current.children:
                current.children[hval] = HashRadixNode()
            current = current.children[hval]
        current.is_end = True

        return current


    def find_match_model(self, tokens) -> ModelNode:
        current = self.root
        h_val = self.hash_chunk(self.magic_ids)
        current = current.children[h_val]

        i = 0
        d = 0

        if isinstance(tokens, list):
            input_ids = tokens
        else:
            input_ids = tokens["input_ids"].tolist()[0]


        total_tokens = len(input_ids)
        while i < total_tokens:
            hval = self.hash_chunk(tuple(input_ids[i: i+self.chunk_size]))
            i += self.chunk_size
            if hval in current.children:
                current = current.children[hval]
                d += 1
                if d >= self.gate:
                    break

            else:
                break

        if d >= self.gate:
            # print("! matched")
            # self.assign_workload(current.model_list[0], current)
            # print(self.model_task)
            match_model = None
            min = 1e9
            for model in current.model_list:
                if min > model.pending_tasks:
                    match_model = model
                    min = model.pending_tasks
            return  current.model_list[0], current
        else:
            node = self.insert_workload(tokens)
            match_model = random.choice(self.candidate_models)
            self.assign_workload(match_model, node)
            return match_model, node



    def print_tree_by_layers(self) -> List[List[str]]:
        """
        Returns a list of layers (each layer is a list of string descriptions).
        Layer 0 is the root, layer 1 are the root's children, etc.
        """
        from collections import deque
        result: List[List[str]] = []
        queue = deque([("Root", self.root, 0)])  # (prefix, node, level)
        current_level = 0
        current_level_nodes: List[str] = []

        while queue:
            prefix, node, level = queue.popleft()
            if level > current_level:
                result.append(current_level_nodes)
                current_level_nodes = []
                current_level = level
            node_info = f"{prefix}"
            if node.is_end:
                node_info += " (End)"
            current_level_nodes.append(node_info)
            for hash_val, child in sorted(node.children.items(), key=lambda x: x[0]):
                child_prefix = f"{prefix}-{hash_val}" if prefix != "Root" else f"{hash_val}"
                queue.append((child_prefix, child, level + 1))
        if current_level_nodes:
            result.append(current_level_nodes)
        return result
