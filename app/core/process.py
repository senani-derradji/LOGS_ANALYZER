import asyncio, sys
from app.services.logs.parser import LogParser
from app.services.logs.ai import ai_analyzer
from app.utils.logger import logger
import json
from pathlib import Path
from app.db.session import SessionLocal
from app.services.result_services import ResultOperations
from app.services.logs_services import LogsOperations
from app.services.users_services import UserOperations


async def process_single_log(tenant_id, log, log_id, user_id):
    # tenant_id = log.get("tenant_id") or None

    level = log.get("level") or ''
    message = log.get("message") or ''
    extra = log.get("extra")
    correlation = log.get("correlation")
    template = log.get("template")
    signature = log.get("signature")
    detected_type = log.get("detected_type")
    event_category = log.get("event_category")
    confidence = log.get("confidence")
    signals = log.get("signals")
    timestamp = log.get("timestamp")
    normalized_timestamp = log.get("normalized_timestamp")
    epoch = log.get("epoch")
    line_number = log.get("line_number")
    note = "NO AI NOTES"

    if level.lower() in ["error", "critical"] and message:
        ai_result = ai_analyzer(message)  # no await, sync call

        if ai_result is None:
            # AI failed, keep default note
            logger.error("AI analyzer returned None, using default note")
        else:
            # Safely extract the first note if present
            ai_list = ai_result.get("AI") or []
            if ai_list and isinstance(ai_list, list) and isinstance(ai_list[0], dict):
                note = ai_list[0].get("note", note)
                logger.debug(f"AI note extracted: {note}")
            else:
                logger.warning(f"AI result has unexpected shape: {ai_result}")
    db = SessionLocal()

    try:

        res_ops = ResultOperations(db)

        res_ops.create_result(
            {
                "tenant_id": tenant_id,
                "log_id": log_id,
                "user_id": user_id,
                "line_number": line_number,
                "timestamp": timestamp,
                "normalized_timestamp": normalized_timestamp,
                "epoch": epoch,
                "detected_type": detected_type,
                "level": level,
                "message": message,
                "template": template,
                "signature": signature,
                "confidence": confidence,
                "event_category": event_category,
                "correlation": correlation,
                "extra": extra,
                "signals": signals,
                "details": extra,
                "ai_note": note,
            }
        )

        db.commit()
        logger.info(f"Result {log_id}-{signature} created successfully")

    except Exception as e:
        db.rollback()
        logger.error(f"[DB ERROR] {e}\n")

    finally:
        db.close()


async def process_logs(file_path: Path, log_id: int, user_id: int):
    db = SessionLocal()
    try:
        log_ops = LogsOperations(db)
        log_ops.change_status(log_id, "processing")
        db.commit()
    except Exception as e:
        logger.error(f"[STATUS UPDATE ERROR] {e}\n")
    finally:
        db.close()

    parser = LogParser()
    result = parser.parse_file(file_path=str(file_path))

    logs = result["result"]["logs"]
    parsed_result = result["result"]

    SEM = asyncio.Semaphore(5)
    user_ops = UserOperations(db)
    user = user_ops.get_user_by_id(user_id) ; tenant_id = user.tenant_id if user else None

    async def limited_task(log):
        async with SEM:
            await process_single_log(tenant_id, log, log_id, user_id)

    tasks = [limited_task(log) for log in logs]

    await asyncio.gather(*tasks)

    db = SessionLocal()

    try:
        log_ops = LogsOperations(db)
        log_ops.update_log_summary(log_id, {
            "summary": parsed_result.get("summary"),
            "levels_summary": parsed_result.get("levels_summary"),
            "top_ips": parsed_result.get("top_ips"),
            "top_users": parsed_result.get("top_users"),
            "top_urls": parsed_result.get("top_urls"),
            "templates_summary": parsed_result.get("templates_summary"),
            "signatures_summary": parsed_result.get("signatures_summary"),
            "event_category_summary": parsed_result.get("event_category_summary"),
            "correlations": parsed_result.get("correlations"),
            "anomalies": parsed_result.get("anomalies"),
            "total_lines": parsed_result.get("total_lines"),
            "parsed_lines": parsed_result.get("parsed_lines"),
            "unknown_lines": parsed_result.get("unknown_lines"),
        })
        log_ops.change_status(log_id, "completed")
        db.commit()

    except Exception as e:
        db.rollback()
        logger.error(f"[STATUS UPDATE ERROR] {e}\n")
        db = SessionLocal()
        try:
            log_ops = LogsOperations(db)
            log_ops.change_status(log_id, "failed")
            db.commit()
        except Exception:
            pass
    finally:
        db.close()
