import asyncio, sys
from app.services.logs.parser import LogParser
from app.services.logs.ai import ai_analyzer
from app.utils.logger import logger
import json
from pathlib import Path
from app.db.session import SessionLocal
from app.services.result_services import ResultOperations
from app.services.logs_services import LogsOperations


async def process_single_log(log, log_id, user_id):

    level = log.get("level")
    message = log.get("message")
    extra = log.get("extra")

    note = "NO AI NOTES"

    # try:

    # if level in ["ERROR", "CRITICAL"]:

    #     ai_result = await asyncio.to_thread(
    #         ai_analyzer,
    #         json.dumps(log, ensure_ascii=False)
    #     )

    #     if ai_result and ai_result.get("AI"):
    #         note = ai_result["AI"][0].get("note", "NO NOTE")

    db = SessionLocal()

    try:
        res_ops = ResultOperations(db)

        print("DATA BEFORE SAVED : ", log_id, user_id, level, message, extra, note)

        res_ops.create_result(
            {
                "log_id": log_id,
                "user_id": user_id,
                "level": level,
                "message": message,
                "details": json.dumps(extra) if extra else None,
                "ai_note": note,
            }
        )

        db.commit()

    except Exception as e:
        db.rollback()
        logger.error(f"[DB ERROR] {e}\n")

    finally:
        db.close()

    # except Exception as e:
    #     logger.error(f"[PROCESS ERROR] {e}\n")


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

    db = SessionLocal()

    try:
        log_ops = LogsOperations(db)
        log_ops.change_status(log_id, "completed")
        db.commit()

    except Exception as e:
        db.rollback()
        logger.error(f"[STATUS UPDATE ERROR] {e}\n")

    finally:
        db.close()
