import aio_pika
import json
from app.core.config import settings

connection = None


# =========================
# INIT CONNECTION (SINGLE)
# =========================
async def init_rabbitmq():
    global connection

    if connection is None:
        connection = await aio_pika.connect_robust(settings.MQ_URL)

    return connection


# =========================
# GET CONNECTION
# =========================
def get_connection():
    return connection


# =========================
# CREATE CHANNEL (PER WORKER)
# =========================
async def create_channel():
    global connection

    if connection is None:
        await init_rabbitmq()

    channel = await connection.channel()
    await channel.set_qos(prefetch_count=1)

    return channel


# =========================
# SETUP QUEUES (RUN ONCE)
# =========================
async def setup_queues():
    channel = await create_channel()

    await channel.declare_queue(
        "logs_queue_v2",
        durable=True,
        arguments={
            "x-message-ttl": 3600 * 1000,  # 1 hour in ms
            "x-max-length": 10000,
            "x-dead-letter-exchange": "",
            "x-dead-letter-routing-key": "logs_dlq",
        }
    )

    await channel.declare_queue("logs_dlq", durable=True)

    await channel.close()


# =========================
# PUBLISH JOB
# =========================
async def send_log_job(job_data: dict):
    channel = await create_channel()

    await channel.default_exchange.publish(
        aio_pika.Message(
            body=json.dumps(job_data).encode(),
            delivery_mode=aio_pika.DeliveryMode.PERSISTENT
        ),
        routing_key="logs_queue_v2"
    )

    await channel.close()