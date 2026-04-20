import asyncio
import json
import sys
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))) ; sys.path.append(BASE_DIR)

from app.core.redis import init_redis, get_redis
from app.core.process import process_logs
from app.utils.logger import logger


async def worker(worker_id: int):

    await init_redis()
    redis_client = get_redis()

    logger.info(f"[WORKER {worker_id}] started")

    while True:

        job = await redis_client.rpop("logs_queue")

        if job:

            data = json.loads(job)
            logger.debug(f"[DATA] {data}")

            try:
                await process_logs(
                    data["file_path"],
                    data["log_id"],
                    data["user_id"]
                )

                logger.info(f"[WORKER {worker_id}] DONE log_id={data['log_id']}")

            except Exception as e:
                logger.error(f"[WORKER {worker_id}] ERROR: {e}")

        else:
            await asyncio.sleep(0.5)


async def main():

    workers = []

    for i in range(1):  # adjust scale
        workers.append(asyncio.create_task(worker(i)))

    await asyncio.gather(*workers)


if __name__ == "__main__":
    asyncio.run(main())