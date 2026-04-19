import asyncio,  sys
from app.services.logs.parser import LogParser
from app.services.logs.ai import ai_analyzer
from app.utils.logger import logger
import json
from pathlib import Path



async def process_single_log(log, log_id, user_id):

    level = log.get("level")
    message = log.get("message")
    extra = log.get("extra")

    note = "NO AI NOTES"

    try:

        if level in ["ERROR", "CRITICAL"]:

            ai_result = await asyncio.to_thread(
                ai_analyzer,
                json.dumps(log, ensure_ascii=False)
            )

            if ai_result and ai_result.get("AI"):
                note = ai_result["AI"][0].get("note", "NO NOTE")


        from app.db.session import SessionLocal
        from app.services.result_services import ResultOperations

        db = SessionLocal()

        try:
            res_ops = ResultOperations(db)

            res_ops.create_result({
                "log_id": log_id,
                "user_id": user_id,
                "level": level,
                "message": message,
                "details": json.dumps(extra) if extra else None,
                "ai_note": note,
            })

            db.commit()

        except Exception as e:
            db.rollback()
            logger.error(f"[DB ERROR] {e}")

        finally:
            db.close()

    except Exception as e:
        logger.error(f"[PROCESS ERROR] {e}")



async def process_logs(file_path: Path, log_id: int, user_id: int):

    parser = LogParser()
    result = parser.parse_file(file_path=str(file_path))

    logs = result["result"]["logs"]


    SEM = asyncio.Semaphore(5)

    async def limited_task(log):
        async with SEM:
            await process_single_log(log, log_id, user_id)


    tasks = [limited_task(log) for log in logs]

    await asyncio.gather(*tasks)


    from app.db.session import SessionLocal
    from app.services.logs_services import LogsOperations

    db = SessionLocal()

    try:
        log_ops = LogsOperations(db)
        log_ops.change_status(log_id, "completed")
        db.commit()

    except Exception as e:
        db.rollback()
        logger.error(f"[STATUS UPDATE ERROR] {e}")

    finally:
        db.close()
