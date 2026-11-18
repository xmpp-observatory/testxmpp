import asyncio
import logging
import time

class TaskItem:
    __slots__ = ("func", "data", "run_at", "backoff", "attempts")

    def __init__(self, func, data, run_at, backoff, attempts=0):
        self.func = func
        self.data = data
        self.run_at = run_at
        self.backoff = backoff
        self.attempts = attempts

    def __eq__(self, other):
        return self.func == other.func and self.data == other.data

    def __ne__(self, other):
        return not (self == other)

    def __hash__(self):
        return hash(self.func) ^ hash(self.data)

    def __str__(self):
        return "{}({})".format(self.func, self.data)

class TaskQueue:
    def __init__(self, *,
                 backoff_base=2,
                 backoff_start=0.5,
                 backoff_max=120,
                 max_size=None,
                 max_attempts=20,
                 logger=None):
        super().__init__()
        self._queue = []
        self._max_size = max_size
        self._backoff_base = backoff_base
        self._backoff_start = backoff_start
        self._backoff_max = backoff_max
        self._max_attempts = max_attempts
        self._queue_changed = asyncio.Event()
        self.completed_jobs = set()
        self.logger = logger or logging.getLogger(__name__)

    def _add(self, task_item):
        self._queue.append(task_item)
        self._queue.sort(key=lambda x: x.run_at)

    def push(self, func, data):
        task_item = TaskItem(func, data, 0, self._backoff_start)
        if task_item in self._queue or task_item in self.completed_jobs:
            return
        if self._max_size is not None and len(self._queue) >= self._max_size:
            removed_task = self._queue.pop(0)  # Remove the oldest task
            self.logger.info("Queue is full. Removing oldest task: %s", removed_task)
        task_item.run_at = time.monotonic()
        self._add(task_item)
        self._queue_changed.set()

    async def run_next_task(self):
        while True:
            self._queue_changed.clear()
            now = time.monotonic()
            if not self._queue:
                await self._queue_changed.wait()
                continue

            if self._queue[0].run_at > now:
                try:
                    await asyncio.wait_for(self._queue_changed.wait(), self._queue[0].run_at - now)
                except asyncio.TimeoutError:
                    pass
                continue

            task_item = self._queue.pop(0)
            func = task_item.func
            data = task_item.data
            try:
                await func(data)
                self.completed_jobs.add(task_item)
                self.logger.info("Task %s completed successfully.", task_item)
            except Exception as exc:
                task_item.attempts += 1
                if task_item.attempts >= self._max_attempts:
                    self.logger.error("Task %s failed after %d attempts. Giving up.", task_item, self._max_attempts, exc_info=True)
                else:
                    task_item.backoff = min(task_item.backoff * self._backoff_base, self._backoff_max)
                    task_item.run_at = time.monotonic() + task_item.backoff
                    self.logger.error("Task %s failed. Retrying in %r seconds (attempt %d/%d).", task_item, task_item.backoff, task_item.attempts, self._max_attempts, exc_info=True)
                    self._add(task_item)

            return

    async def run(self):
        while True:
            await self.run_next_task()
