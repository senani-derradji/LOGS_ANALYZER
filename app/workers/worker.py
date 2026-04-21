import asyncio
import json
import aio_pika
import sys
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.append(BASE_DIR)

from app.core.redis import init_redis, get_redis
from app.core.process import process_logs
from app.utils.logger import logger
from app.core.config import MQ_URL


RABBIT_URL = MQ_URL


async def worker(worker_id: int):

    await init_redis()
    redis = get_redis()

    connection = await aio_pika.connect_robust(RABBIT_URL)
    channel = await connection.channel()

    await channel.set_qos(prefetch_count=1)

    queue = await channel.declare_queue("logs_queue", durable=True)

    async with queue.iterator() as queue_iter:
        async for message in queue_iter:

            async with message.process(requeue=False):

                data = json.loads(message.body)
                log_id = data["log_id"]
                retry = data.get("retry", 0)

                try:
                    await redis.set(f"log:{log_id}:status", "processing")

                    await process_logs(
                        data["file_path"],
                        log_id,
                        data["user_id"]
                    )

                    await redis.set(f"log:{log_id}:status", "done")

                except Exception as e:

                    retry += 1

                    if retry < 3:
                        await channel.default_exchange.publish(
                            aio_pika.Message(
                                body=json.dumps({
                                    **data,
                                    "retry": retry
                                }).encode(),
                                delivery_mode=aio_pika.DeliveryMode.PERSISTENT
                            ),
                            routing_key="logs_queue"
                        )

                        await redis.set(
                            f"log:{log_id}:status",
                            f"retrying ({retry})"
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
                            "failed"
                        )

                    logger.error(f"ERROR: {e}")


async def main():
    workers = []

    for i in range(5):  # scaling
        workers.append(asyncio.create_task(worker(i)))

    await asyncio.gather(*workers)


if __name__ == "__main__":
    asyncio.run(main())