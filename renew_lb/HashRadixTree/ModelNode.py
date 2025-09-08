import asyncio
from collections import deque
from typing import Deque, List, Optional
import threading
import time

class ModelNode:
    """
    Each ModelNode holds:
      - name: model's name
      - url: model's link
      - controls its own concurrency via a semaphore
      - maintains a fixed-size (8) latency window and computes a latency factor:
        latency_factor = mean(previous latencies) + latest_latency
    """

    def __init__(self, name: str, url: str, max_concurrency: int = 1) -> None:
        self.name = name
        self.url = url
        self.max_concurrency = max_concurrency

        # concurrency control
        self._sem = asyncio.Semaphore(max_concurrency)

        # --- latency window (FIFO, size<=8), protected by an async lock ---
        self._lat_lock = threading.RLock()
        self._lat_win: Deque[float] = deque()  # 手动维护长度，方便更新sum
        self._lat_sum: float = 0.0
        self._lat_maxlen: int = 8           # sum of values in _lat_win for O(1) avg

    # ---------------- Concurrency APIs ----------------
    async def add_task(self) -> None:
        await self._sem.acquire()

    async def finish_task(self) -> None:
        self._sem.release()

    def get_pending_tasks(self) -> int:
        # approximate in-flight requests: slots used = max_concurrency - available permits
        return self.max_concurrency - self._sem._value  # uses private attr, but OK in practice

    @property
    def pending_tasks(self) -> int:
        return self.get_pending_tasks()

    # # ---------------- Latency APIs ----------------
    def push_latency(self, latency: float) -> None:
        """仅入队，维护固定窗口与总和（线程安全）。"""
        with self._lat_lock:
            if len(self._lat_win) == self._lat_maxlen:
                oldest = self._lat_win.popleft()
                self._lat_sum -= oldest
            self._lat_win.append(latency)
            self._lat_sum += latency

    def history_mean(self) -> float:
        """
        返回历史均值（不含最新）：
          - 空窗口或仅1个元素 -> 0
          - 长度2~7 -> 除最新外的平均
          - 长度8 -> 前7个的平均
        """
        with self._lat_lock:
            n = len(self._lat_win)
            if n <= 1:
                return 0.0
            latest = self._lat_win[-1]
            sum_hist = self._lat_sum - latest
            n_hist = n - 1
            return sum_hist / n_hist

    def latency_factor(self) -> float:
        """
        返回 latency_factor = history_mean + latest。
          - 空窗口 -> 0
          - 否则 = history_mean() + 最新值
        """
        with self._lat_lock:
            if not self._lat_win:
                return 0.0
            latest = self._lat_win[-1]
            return self.history_mean() * 0.875 + latest * 0.125


    # def latency_window(self) -> List[float]:
    #     """Return current window (oldest -> newest)."""
    #     with self._lat_lock:
    #         return list(self._lat_win)

    # def latency_avg(self) -> Optional[float]:
    #     """Average over current window, or None if empty."""
    #     with self._lat_lock:
    #         if not self._lat_win:
    #             return None
    #         return self._lat_sum / len(self._lat_win)

    # def last_latency(self) -> Optional[float]:
    #     """Most recent latency, or None if empty."""
    #     with self._lat_lock:
    #         if not self._lat_win:
    #             return None
    #         return self._lat_win[-1]

    # def clear_latencies(self) -> None:
    #     """Clear the latency window."""
    #     with self._lat_lock:
    #         self._lat_win.clear()
    #         self._lat_sum = 0.0


# async def worker(node: ModelNode, wid: int, delays_ms: list[int]) -> None:
#     """
#     每个 worker 会顺序发起若干“请求”，每个请求 sleep 指定毫秒数来模拟延迟，
#     然后把测得的 latency_ms 推入 node。
#     """
#     print("inside worker")
#     for d in delays_ms:
#         await node.add_task()
#         t0 = time.perf_counter()
#         print("before sleep")
#         await asyncio.sleep(d / 1000000.0)  # 模拟推理耗时
#         t1 = time.perf_counter()
#         latency_ms = (t1 - t0) * 1000000.0
#         node.push_latency(latency_ms)

#         print(
#             f"[W{wid}] add={latency_ms:.1f} ms | "
#             f"hist_mean={node.history_mean():.1f} | "
#             f"factor={node.latency_factor():.1f} | "
#             f"inflight={node.pending_tasks}"
#         )
#         await node.finish_task()

# async def amain():
#     node = ModelNode("llama8b", "http://127.0.0.1:8000", max_concurrency=2)

#     # 三个 worker 的“请求时延脚本”（毫秒）
#     w1 = [100, 120, 90, 110]
#     w2 = [95, 105, 115, 130, 125]
#     w3 = [80, 160, 140]

#     await asyncio.gather(
#         worker(node, 1, w1),
#         worker(node, 2, w2),
#         worker(node, 3, w3),
#     )

#     print("\n=== Final ===")
#     print("history_mean:", round(node.history_mean(), 2))
#     print("latency_factor:", round(node.latency_factor(), 2))
#     print("inflight:", node.pending_tasks)

if __name__ == "__main__":
    asyncio.run(amain())