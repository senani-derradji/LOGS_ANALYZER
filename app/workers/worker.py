import asyncio, json
import sys, os ; BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))) ; sys.path.append(BASE_DIR)

from app.core.redis import init_redis, get_redis
from app.services.logs_services import LogsOperations
from app.services.result_services import ResultOperations
from app.db.session import SessionLocal
from app.api.routes_logs import process_logs

async def worker():

    await init_redis()
    redis_client = get_redis()

    while True:
        job = await redis_client.rpop("logs_queue")
        print("[WORKER JOB] -> ", job)

        if job:
            data = json.loads(job)
            print("[WORKER DATA] -> ", data)

            db = SessionLocal()

            try:
                log_ops = LogsOperations(db)
                res_ops = ResultOperations(db)

                process_logs(
                    data["file_path"],
                    data["log_id"],
                    data["user_id"],
                    res_ops,
                    log_ops
                )

            finally:
                db.close()

        else:
            await asyncio.sleep(1)

if __name__ == "__main__":
    async def main():
        tasks = []

        for _ in range(2):
            tasks.append(asyncio.create_task(worker()))

        await asyncio.gather(*tasks)

    asyncio.run(main())