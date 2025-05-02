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

Q1_MS, Q2_MS, INF_MS, E2E_MS = [], [], [], []
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
        Q1_MS.append((t1 - t0) * 1000)
        ids = tokenizer(sample, return_tensors="pt")["input_ids"][0].tolist()
        tokens = ids
        

        match_model, hrt_node = hrt.find_match_model(tokens)
        if match_model.pending_tasks == 4:
            match_model = hrt.find_idle_node()
            hrt.assign_workload(match_model, hrt_node)

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
        E2E_MS.append((t4 - t0) * 1000)
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
    print(f"P50 Q1: {np.percentile(Q1_MS,50):.1f}ms, Q2: {np.percentile(Q2_MS,50):.1f}ms")
    print(f"P50 Inf: {np.percentile(INF_MS,50):.1f}ms, E2E: {np.percentile(E2E_MS,50):.1f}ms")
    print(f"P99 E2E: {np.percentile(E2E_MS,99):.1f}ms, Mean E2E: {np.mean(E2E_MS):.1f}ms")

if __name__ == "__main__":
    asyncio.run(main())