import aiohttp
import asyncio
import json
from time import perf_counter
import numpy as np
from transformers import AutoTokenizer
import multiprocessing
from HashRadixTree.HashRadixTree import HashRadixTree
from HashRadixTree.ModelNode import ModelNode

# ----------- Configuration -----------
MODEL_NAME = "meta-llama/Llama-3.1-8B-Instruct"
MAX_MODEL_CONCURRENCY = 4
SCHED_WORKERS = 1
SERVE_WORKERS = 256
REQUEST_RATE = 72
DATASET_PATH = "../datasets/toolbench_zipf_1.1_prompts_6000.jsonl"

# magic_ids = [128000, 2374, 25, 1472, 527, 9156, 38, 2898, 11, 499, 649, 1005, 1690, 7526, 2993, 82, 8, 311, 656, 279, 2768,
#             3465, 627, 5451, 358, 690, 3041, 4096, 323, 701, 1212, 1688, 1855, 3094, 24564, 2704, 1457, 264, 502, 1614, 12487,
#             10491, 9522, 85269, 59997, 532, 4320, 29690, 42901, 93294, 17460, 23811, 17182, 2875, 520, 1455, 11914, 39537,
#             810, 490, 1065, 779, 3197, 2018, 398, 1456, 4787, 824, 10267, 596, 19110, 4999, 6396, 8392, 4333, 2038, 1501,
#             2746, 3775, 31524, 539, 2764, 705, 36633, 47530, 8401, 8543, 70492]

# build_text = "System: You are AutoGPT, you can use many tools(functions) to do the following task.\nFirst I will give you the task description, and your task start.\nAt each step, you need to give your thought to analyze the status now and what to do next, with a function call to actually excute your step.\nAfter the call, you will get the call result, and you are now in a new state.\nThen you will analyze your status now, then decide what to do next...\nAfter many (Thought-call) pairs, you finally perform the task, then you can give your finial answer.\nRemember: \n1.the state change is irreversible, you can't go back to one of the former state, if you want to restart the task, say \"I give up and restart\".\n2.All the thought is short, at most in 5 sentence.\n3.You can do more then one trys, so if your plan is to continusly try some conditions, you can do one of the conditions per try.\nLet's Begin!\nTask description: You should use functions to help handle the real time user querys. Remember:\n1.ALWAYS call \"Finish\" function at the end of the task. And the final answer should contain enough information to show to the user,If you can't handle the task, or you find that function calls always fail(the function is not valid now), use function Finish->give_up_and_restart.\n2.Do not use origin tool names, use only subfunctions' names.\nYou have access of the following tools:\n1."
  

with open(DATASET_PATH, "r") as f:
    raw_samples = [json.loads(line) for line in f]

# shared tokenizer
tokenizer = AutoTokenizer.from_pretrained(
    MODEL_NAME,
    token=""
)

# ----------- Shared Objects -----------
model_list = [
    ModelNode(f"mnode{i}", f"http://127.0.0.1:800{i}/v1/completions", max_concurrency=MAX_MODEL_CONCURRENCY)
    for i in range(8)
]
hrt = None
hrt_ready = asyncio.Lock()

Q2_MS, INF_MS, E2E_MS = [], [], []
# sched_q = asyncio.Queue(maxsize=SERVE_WORKERS)
sched_q = asyncio.Queue(maxsize=8)
serve_q = asyncio.Queue(maxsize=SERVE_WORKERS)

async def monitor_queues():
    while True:
        await asyncio.sleep(30) 
        print(f"[Monitor] sched_q: {sched_q.qsize()}, serve_q: {serve_q.qsize()}")

async def sched_worker():
    global hrt
    while True:
        idx, sample, t0 = await sched_q.get()
        t1 = perf_counter()

        ids = tokenizer(sample, return_tensors="pt")["input_ids"][0].tolist()
        tokens = ids
        match_model, _ = hrt.find_match_model(tokens)
        
        t2_sched = perf_counter()
        await serve_q.put((idx, sample, t0, t1, t2_sched, match_model))
        sched_q.task_done()

async def serve_worker(session: aiohttp.ClientSession):
    while True:
        idx, sample, t0, t1, t2_sched, model_node = await serve_q.get()
        t3 = perf_counter()
        Q2_MS.append((t3 - t2_sched) * 1000)

        await model_node.add_task()
        inf_start = perf_counter()
        async with session.post(model_node.url, json={
            "model": model_node.name,
            "prompt": sample['text'],
            "max_tokens": 128,
            "temperature": sample.get('sampling_params', {}).get('temperature', 0),
            "stop": None,
            "echo": False
        }, timeout=80) as resp:
            _ = await resp.json(content_type=None)
        INF_MS.append((perf_counter() - inf_start) * 1000)
        await model_node.finish_task()
        serve_q.task_done()

        t4 = perf_counter()
        E2E_MS.append((t4 - t1) * 1000)
        print(f"model:{model_node.name} is processing idx:{idx} E2E: {E2E_MS[-1]:.1f}ms")

async def main():
    async with aiohttp.ClientSession() as session:
        scheders = [asyncio.create_task(sched_worker()) for _ in range(SCHED_WORKERS)]
        servers = [asyncio.create_task(serve_worker(session)) for _ in range(SERVE_WORKERS)]

        for idx, sample in enumerate(raw_samples):
            await asyncio.sleep(np.random.exponential(1/REQUEST_RATE))
            t0 = perf_counter()
            await sched_q.put((idx, sample, t0))

        await sched_q.join()
        await serve_q.join()
        for t in scheders + servers:
            t.cancel()

    print("----- Perf Summary -----")
    print(f"P50 Q2: {np.percentile(Q2_MS,50):.1f}ms")
    print(f"P50 Inf: {np.percentile(INF_MS,50):.1f}ms, E2E: {np.percentile(E2E_MS,50):.1f}ms")
    print(f"P99 E2E: {np.percentile(E2E_MS,99):.1f}ms, Mean E2E: {np.mean(E2E_MS):.1f}ms")

if __name__ == "__main__":
    asyncio.run(main())