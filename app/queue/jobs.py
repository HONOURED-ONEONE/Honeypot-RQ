from app.callback.client import send_final_result


def send_final_callback_job(session_id: str):
    # Executed by RQ worker
    send_final_result(session_id)
