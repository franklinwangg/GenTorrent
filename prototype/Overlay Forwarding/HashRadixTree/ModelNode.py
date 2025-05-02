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
