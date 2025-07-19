from transformers import AutoTokenizer
from vllm import LLM

model_name = "TinyLlama/TinyLlama-1.1B-Chat-v1.0"
tokenizer = AutoTokenizer.from_pretrained(model_name)
llm = LLM(model=model_name)

input_text = "San Francisco is a "
input_ids = tokenizer(input_text).input_ids

print(input_ids, [input_ids])

# Pass the input_ids directly
outputs = llm.generate(prompt_token_ids=input_ids)

for output in outputs:
    prompt = output.prompt_token_ids
    generated_text = output.outputs[0].token_ids
    print(output.outputs[0])
    print(f"Prompt: {prompt!r}, Generated text: {generated_text}")
    print(tokenizer.decode(generated_text))

llm.generate("hello, my name is Daniel")
llm.generate("hello, my name is Peter")
