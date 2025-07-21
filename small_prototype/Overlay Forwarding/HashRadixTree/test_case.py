from typing import List, Tuple
from HashRadixTree import HashRadixTree
from ModelNode import ModelNode
import json
from transformers import AutoTokenizer


MODEL_NAME = "meta-llama/Llama-3.1-8B-Instruct"
# chunk_size = 5
tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME, token = "")
build_text = "System: You are AutoGPT, you can use many tools(functions) to do the following task.\nFirst I will give you the task description, and your task start.\nAt each step, you need to give your thought to analyze the status now and what to do next, with a function call to actually excute your step.\nAfter the call, you will get the call result, and you are now in a new state.\nThen you will analyze your status now, then decide what to do next...\nAfter many (Thought-call) pairs, you finally perform the task, then you can give your finial answer.\nRemember: \n1.the state change is irreversible, you can't go back to one of the former state, if you want to restart the task, say \"I give up and restart\".\n2.All the thought is short, at most in 5 sentence.\n3.You can do more then one trys, so if your plan is to continusly try some conditions, you can do one of the conditions per try.\nLet's Begin!\nTask description: You should use functions to help handle the real time user querys. Remember:\n1.ALWAYS call \"Finish\" function at the end of the task. And the final answer should contain enough information to show to the user,If you can't handle the task, or you find that function calls always fail(the function is not valid now), use function Finish->give_up_and_restart.\n2.Do not use origin tool names, use only subfunctions' names.\nYou have access of the following tools:\n1."
# tokens = tokenizer(build_text, return_tensors="pt")
# input_ids = tokens["input_ids"].tolist()[0]
# print(input_ids)

mnode0 = ModelNode("mnode0", "http://test")
mnode1 = ModelNode("mnode1", "http://test")
mnode2 = ModelNode("mnode2", "http://test")
mnode3 = ModelNode("mnode3", "http://test")
mnode4 = ModelNode("mnode4", "http://test")
mnode5 = ModelNode("mnode5", "http://test")
mnode6 = ModelNode("mnode6", "http://test")
mnode7 = ModelNode("mnode7", "http://test")

model_list = [mnode0, mnode1, mnode2, mnode3, mnode4, mnode5, mnode6, mnode7]


workloads = []
with open('../../datasets/toolbench_zipf_1.1_prompts_6000.jsonl', "r", encoding="utf-8") as f:
    workloads = [json.loads(line) for line in f]
    
model_task = {f"mnode{i}":[] for i in range(8)}

hrt = HashRadixTree(first_workload=tokenizer(workloads[0]['text'][len(build_text):], return_tensors="pt"),
                    first_mnode=mnode0,
                    candidate_models = model_list)

for workload in workloads[1:]:
    print(workload['text'][len(build_text): len(build_text) + 20])
    prompt = workload['text'][len(build_text):]
    tokens = tokenizer(prompt, return_tensors="pt")
    
    match_model, hrt_node = hrt.find_match_model(tokens)
    
    model = hrt.assign_match_workload(match_model, hrt_node, tokens)

    model_task[match_model.name if match_model is not None else model.name].append(workload['text'][len(build_text): len(build_text) + 20]) 
    print("-" * 60)
    

for model_name, task_list in model_task.items():
    sorted_tasks = sorted(task_list)
    filename = f"./test_logs/{model_name}.txt"

    with open(filename, "w+", encoding="utf-8") as f:
        for task in sorted_tasks:
            f.write(str(task) + "\n")

    print(f"Wrote {len(sorted_tasks)} tasks to {filename}")
