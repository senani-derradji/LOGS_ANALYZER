import asyncio
import json
import sys
import os
import aio_pika

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.append(BASE_DIR)

from app.core.redis import init_redis, get_redis
from app.core.process import process_logs
from app.utils.logger import logger
from app.core.rabbitmq import init_rabbitmq, create_channel


async def worker(worker_id: int):

    redis = get_redis()

    channel = await create_channel()

    queue = await channel.get_queue("logs_queue_v2")

    async with queue.iterator() as queue_iter:
        async for message in queue_iter:

            async with message.process():

                data = json.loads(message.body)
                log_id = data["log_id"]
                retry = data.get("retry", 0)

                try:
                    await redis.set(f"log:{log_id}:status", "processing", ex=300)

                    await process_logs(
                        data["file_path"],
                        log_id,
                        data["user_id"]
                    )

                    await redis.set(f"log:{log_id}:status", "done", ex=300)

                except Exception as e:
                    retry += 1

                    if retry < 3:
                        await channel.default_exchange.publish(
                            aio_pika.Message(
                                body=json.dumps({**data, "retry": retry}).encode(),
                                delivery_mode=aio_pika.DeliveryMode.PERSISTENT
                            ),
                            routing_key="logs_queue_v2"
                        )

                        await redis.set(
                            f"log:{log_id}:status",
                            f"retrying ({retry})",
                            ex=300
                        )

                    else:
                        await channel.default_exchange.publish(
                            aio_pika.Message(
                                body=json.dumps(data).encode(),
                                delivery_mode=aio_pika.DeliveryMode.PERSISTENT
                            ),
                            routing_key="logs_dlq"
                        )

                        await redis.set(
                            f"log:{log_id}:status",
                            "failed",
                            ex=300
                        )

                    logger.error(f"[Worker {worker_id}] ERROR: {e}")


async def main():

    await init_redis()
    await init_rabbitmq()

    workers = []

    for i in range(2):
        workers.append(asyncio.create_task(worker(i)))

    await asyncio.gather(*workers)


if __name__ == "__main__":
    asyncio.run(main())