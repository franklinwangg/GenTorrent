import asyncio

class ModelNode:
    """
    Each ModelNode holds:
      - name: model's name
      - url: model's link
      - controls its own concurrency via a semaphore
      - supports both get_pending_tasks() and a pending_tasks property for compatibility
    """

    def __init__(self, name: str, url: str, max_concurrency: int = 1) -> None:
        self.name = name
        self.url = url
        self.max_concurrency = max_concurrency
        # semaphore controls concurrent requests per model
        self._sem = asyncio.Semaphore(max_concurrency)

    async def add_task(self):
        # acquire a slot or wait
        await self._sem.acquire()

    async def finish_task(self):
        # release slot
        self._sem.release()

    def get_pending_tasks(self) -> int:
        # approximate in-flight requests: slots used = max_concurrency - available permits
        return self.max_concurrency - self._sem._value

    @property
    def pending_tasks(self) -> int:
        # alias for compatibility with HashRadixTree.find_match_model
        return self.get_pending_tasks()
    
    
# send to model_url
    async def finish_task(self):
        self._sem.release()

    async def send_prompt(self, prompt: str, max_tokens: int = 100):
        """
        Sends a prompt to the model server at self.url and returns the completion.
        Assumes OpenAI-style /v1/completions endpoint.
        """
        await self.add_task()
        try:
            async with aiohttp.ClientSession() as session:
                payload = {
                    "prompt": prompt,
                    "max_tokens": max_tokens,
                    "temperature": 0.7
                }
                async with session.post(self.url, json=payload) as resp:
                    if resp.status != 200:
                        raise Exception(f"Request failed with status {resp.status}")
                    data = await resp.json()
                    return data
        finally:
            await self.finish_task()
