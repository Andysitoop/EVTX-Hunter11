import os
import threading
import time
import uuid
from pathlib import Path
from typing import Optional

from flask import Flask, flash, jsonify, redirect, render_template, request, send_from_directory, url_for

from evtx_extractor import ExtractionCancelled, process_input_root


PROJECT_ROOT = Path(__file__).resolve().parent
DEFAULT_INPUT = PROJECT_ROOT / "Input"
DEFAULT_OUTPUT = PROJECT_ROOT / "Salidacsv"

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev")

_jobs_lock = threading.Lock()
_jobs: dict[str, dict] = {}


def _now_ms() -> int:
    return int(time.time() * 1000)


def _new_job(initial: dict) -> str:
    job_id = uuid.uuid4().hex
    with _jobs_lock:
        _jobs[job_id] = {
            "job_id": job_id,
            "status": "queued",
            "pause_event": threading.Event(),
            "cancel_event": threading.Event(),
            "created_ms": _now_ms(),
            "updated_ms": _now_ms(),
            "progress": {
                "planned_tasks": 0,
                "completed_tasks": 0,
                "percent": 0,
                "stage": "",
                "evidence": "",
                "computer": "",
                "log_kind": "",
            },
            "results": [],
            "error": None,
            **initial,
        }
    return job_id


def _update_job(job_id: str, patch: dict) -> None:
    with _jobs_lock:
        job = _jobs.get(job_id)
        if not job:
            return
        job.update(patch)
        job["updated_ms"] = _now_ms()


def _get_job(job_id: str) -> Optional[dict]:
    with _jobs_lock:
        return _jobs.get(job_id)


def _update_progress(job_id: str, payload: dict) -> None:
    with _jobs_lock:
        job = _jobs.get(job_id)
        if not job:
            return

        prog = job.get("progress", {})
        prog.update(payload)

        planned = int(prog.get("planned_tasks") or 0)
        completed = int(prog.get("completed_tasks") or 0)
        percent = 100 if planned == 0 else int((completed / planned) * 100)
        if percent < 0:
            percent = 0
        if percent > 100:
            percent = 100
        prog["percent"] = percent

        job["progress"] = prog
        job["updated_ms"] = _now_ms()


@app.get("/")
def index():
    input_root = request.args.get("input_root") or str(DEFAULT_INPUT)
    output_root = request.args.get("output_root") or str(DEFAULT_OUTPUT)
    job_id = request.args.get("job_id")

    out_dir = Path(output_root)
    files = []
    if out_dir.exists() and out_dir.is_dir():
        files = sorted([p.name for p in out_dir.glob("*.csv")], key=str.lower)

    return render_template(
        "index.html",
        input_root=input_root,
        output_root=output_root,
        files=files,
        job_id=job_id,
    )


@app.get("/image/<path:filename>")
def image_file(filename: str):
    return send_from_directory(PROJECT_ROOT / "image", filename)


@app.post("/run")
def run_extract():
    input_root = Path(request.form.get("input_root") or str(DEFAULT_INPUT))
    output_root = Path(request.form.get("output_root") or str(DEFAULT_OUTPUT))
    max_events_raw = request.form.get("max_events", "0")
    include_xml_raw = request.form.get("include_xml", "")
    logs_choice = (request.form.get("logs_choice") or "all").lower()

    try:
        max_events = int(max_events_raw)
    except ValueError:
        max_events = 0

    include_xml = include_xml_raw.lower() in ("1", "true", "on", "yes")

    if logs_choice == "security":
        logs_to_process = {"security"}
    elif logs_choice == "powershell":
        logs_to_process = {"powershell"}
    elif logs_choice == "sysmon":
        logs_to_process = {"sysmon"}
    else:
        logs_to_process = {"security", "powershell", "sysmon"}

    if not input_root.exists() or not input_root.is_dir():
        flash(f"InputRoot no existe o no es carpeta: {input_root}")
        return redirect(url_for("index", input_root=str(input_root), output_root=str(output_root)))

    output_root.mkdir(parents=True, exist_ok=True)

    job_id = _new_job({
        "input_root": str(input_root),
        "output_root": str(output_root),
        "max_events": max_events,
        "include_xml": include_xml,
        "logs_choice": logs_choice,
    })

    def _worker() -> None:
        _update_job(job_id, {"status": "running"})

        job = _get_job(job_id) or {}
        control = {
            "pause": job.get("pause_event"),
            "cancel": job.get("cancel_event"),
        }

        def _cb(payload: dict) -> None:
            _update_progress(job_id, payload)

        try:
            created = process_input_root(
                input_root=input_root,
                output_root=output_root,
                max_events=max_events,
                include_xml=include_xml,
                progress_callback=_cb,
                control=control,
                logs_to_process=logs_to_process,
            )
            _update_job(job_id, {"status": "done", "results": created})
        except ExtractionCancelled:
            _update_job(job_id, {"status": "cancelled"})
        except Exception as e:
            _update_job(job_id, {"status": "error", "error": str(e)})

    t = threading.Thread(target=_worker, daemon=True)
    t.start()

    return redirect(url_for("index", input_root=str(input_root), output_root=str(output_root), job_id=job_id))


@app.post("/api/start")
def api_start():
    data = request.get_json(silent=True) or {}
    input_root = Path(data.get("input_root") or str(DEFAULT_INPUT))
    output_root = Path(data.get("output_root") or str(DEFAULT_OUTPUT))
    max_events = int(data.get("max_events") or 0)
    include_xml = bool(data.get("include_xml"))
    logs_choice = str(data.get("logs_choice") or "all").lower()

    if logs_choice == "security":
        logs_to_process = {"security"}
    elif logs_choice == "powershell":
        logs_to_process = {"powershell"}
    elif logs_choice == "sysmon":
        logs_to_process = {"sysmon"}
    else:
        logs_to_process = {"security", "powershell", "sysmon"}

    if not input_root.exists() or not input_root.is_dir():
        return jsonify({"ok": False, "error": f"InputRoot no existe o no es carpeta: {input_root}"}), 400

    output_root.mkdir(parents=True, exist_ok=True)
    job_id = _new_job({
        "input_root": str(input_root),
        "output_root": str(output_root),
        "max_events": max_events,
        "include_xml": include_xml,
        "logs_choice": logs_choice,
    })

    def _worker() -> None:
        _update_job(job_id, {"status": "running"})

        job = _get_job(job_id) or {}
        control = {
            "pause": job.get("pause_event"),
            "cancel": job.get("cancel_event"),
        }

        def _cb(payload: dict) -> None:
            _update_progress(job_id, payload)

        try:
            created = process_input_root(
                input_root=input_root,
                output_root=output_root,
                max_events=max_events,
                include_xml=include_xml,
                progress_callback=_cb,
                control=control,
                logs_to_process=logs_to_process,
            )
            _update_job(job_id, {"status": "done", "results": created})
        except ExtractionCancelled:
            _update_job(job_id, {"status": "cancelled"})
        except Exception as e:
            _update_job(job_id, {"status": "error", "error": str(e)})

    threading.Thread(target=_worker, daemon=True).start()
    return jsonify({"ok": True, "job_id": job_id})


@app.get("/api/status/<job_id>")
def api_status(job_id: str):
    with _jobs_lock:
        job = _jobs.get(job_id)
        if not job:
            return jsonify({"ok": False, "error": "job_id no encontrado"}), 404

        safe = {
            "ok": True,
            "job_id": job_id,
            "status": job.get("status"),
            "progress": job.get("progress"),
            "results": job.get("results"),
            "error": job.get("error"),
            "input_root": job.get("input_root"),
            "output_root": job.get("output_root"),
        }
    return jsonify(safe)


@app.post("/api/pause/<job_id>")
def api_pause(job_id: str):
    with _jobs_lock:
        job = _jobs.get(job_id)
        if not job:
            return jsonify({"ok": False, "error": "job_id no encontrado"}), 404
        if job.get("status") != "running":
            return jsonify({"ok": True, "status": job.get("status")})
        job.get("pause_event").set()
        job["status"] = "paused"
        job["updated_ms"] = _now_ms()
    return jsonify({"ok": True, "status": "paused"})


@app.post("/api/resume/<job_id>")
def api_resume(job_id: str):
    with _jobs_lock:
        job = _jobs.get(job_id)
        if not job:
            return jsonify({"ok": False, "error": "job_id no encontrado"}), 404
        if job.get("status") != "paused":
            return jsonify({"ok": True, "status": job.get("status")})
        job.get("pause_event").clear()
        job["status"] = "running"
        job["updated_ms"] = _now_ms()
    return jsonify({"ok": True, "status": "running"})


@app.post("/api/cancel/<job_id>")
def api_cancel(job_id: str):
    with _jobs_lock:
        job = _jobs.get(job_id)
        if not job:
            return jsonify({"ok": False, "error": "job_id no encontrado"}), 404
        if job.get("status") in ("done", "error", "cancelled"):
            return jsonify({"ok": True, "status": job.get("status")})
        job.get("cancel_event").set()
        job.get("pause_event").clear()
        job["status"] = "cancelling"
        job["updated_ms"] = _now_ms()
    return jsonify({"ok": True, "status": "cancelling"})


@app.get("/download/<path:filename>")
def download(filename: str):
    output_root = Path(request.args.get("output_root") or str(DEFAULT_OUTPUT))
    return send_from_directory(output_root, filename, as_attachment=True)


@app.post("/delete")
def delete_csv():
    filename = request.form.get("filename") or ""
    output_root = Path(request.form.get("output_root") or str(DEFAULT_OUTPUT))
    input_root = request.form.get("input_root") or str(DEFAULT_INPUT)

    if not filename.lower().endswith(".csv"):
        flash("Solo se permite eliminar archivos .csv")
        return redirect(url_for("index", input_root=str(input_root), output_root=str(output_root)))

    try:
        base = output_root.resolve()
        target = (output_root / filename).resolve()
        if base not in target.parents:
            flash("Ruta inválida")
            return redirect(url_for("index", input_root=str(input_root), output_root=str(output_root)))

        if not target.exists() or not target.is_file():
            flash("El archivo no existe")
            return redirect(url_for("index", input_root=str(input_root), output_root=str(output_root)))

        target.unlink()
        flash(f"Eliminado: {filename}")
    except Exception as e:
        flash(f"Error al eliminar: {e}")

    return redirect(url_for("index", input_root=str(input_root), output_root=str(output_root)))


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
