import aio_pika
import json
from app.core.config import MQ_URL


RABBIT_URL = MQ_URL

async def send_log_job(job_data: dict):
    connection = await aio_pika.connect_robust(RABBIT_URL)
    channel = await connection.channel()

    queue = await channel.declare_queue("logs_queue", durable=True)

    await channel.default_exchange.publish(
        aio_pika.Message(
            body=json.dumps(job_data).encode(),
            delivery_mode=aio_pika.DeliveryMode.PERSISTENT
        ),
        routing_key="logs_queue"
    )

    await connection.close()
