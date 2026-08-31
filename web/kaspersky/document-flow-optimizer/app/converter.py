import os
import resource
import shutil
import signal
import subprocess
import tempfile
from urllib.parse import urlparse


class ConversionError(Exception):
    pass


HTML2PDF_BIN = os.environ.get("HTML2PDF_BIN", "/app/tools/html2pdf")
WORK_DIR = os.environ.get("HTML2PDF_WORK_DIR", "/app/work")
CACHE_DIR = os.path.join(WORK_DIR, ".cache")

TIMEOUT_SECONDS = int(os.environ.get("HTML2PDF_TIMEOUT", "30"))
MEM_LIMIT_MB = int(os.environ.get("HTML2PDF_MEM_LIMIT_MB", "100"))
MAX_PDF_SIZE = int(os.environ.get("HTML2PDF_MAX_PDF_SIZE", str(50 * 1024 * 1024)))
MAX_SOURCE_LENGTH = 2048
ALLOWED_SCHEMES = {"http", "https"}

_CPU_LIMIT_SECONDS = TIMEOUT_SECONDS + 5
_MEM_LIMIT_BYTES = MEM_LIMIT_MB * 1024 * 1024
_FSIZE_LIMIT_BYTES = MAX_PDF_SIZE + 1024 * 1024
_NOFILE_LIMIT = 256
_NPROC_LIMIT = 64


def _apply_child_limits():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CPU, (_CPU_LIMIT_SECONDS, _CPU_LIMIT_SECONDS))
    resource.setrlimit(resource.RLIMIT_AS, (_MEM_LIMIT_BYTES, _MEM_LIMIT_BYTES))
    resource.setrlimit(resource.RLIMIT_FSIZE, (_FSIZE_LIMIT_BYTES, _FSIZE_LIMIT_BYTES))
    resource.setrlimit(resource.RLIMIT_NOFILE, (_NOFILE_LIMIT, _NOFILE_LIMIT))
    try:
        resource.setrlimit(resource.RLIMIT_NPROC, (_NPROC_LIMIT, _NPROC_LIMIT))
    except (ValueError, OSError):
        pass


def _new_job_dir() -> str:
    os.makedirs(WORK_DIR, exist_ok=True)
    return tempfile.mkdtemp(prefix="job-", dir=WORK_DIR)


def _kill_process_group(proc: subprocess.Popen) -> None:
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass
    try:
        proc.wait(timeout=5)
    except Exception:
        pass


def validate_url(source: str) -> str:
    source = (source or "").strip()
    if not source or len(source) > MAX_SOURCE_LENGTH:
        raise ConversionError("Invalid source address")

    parsed = urlparse(source)
    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        raise ConversionError("Only http:// and https:// URLs are allowed")
    if not parsed.hostname:
        raise ConversionError("URL is missing a host")

    return source


def render_url(source: str) -> tuple[str, str]:
    source = validate_url(source)
    return _run(source)


def _run(source: str) -> tuple[str, str]:
    job_dir = _new_job_dir()
    output_path = os.path.join(job_dir, "output.pdf")
    cmd = [HTML2PDF_BIN, source, output_path, "--cache", CACHE_DIR]
    env = {
        "PATH": "/usr/bin:/bin",
        "HOME": job_dir,
        "LANG": "C.UTF-8",
    }

    try:
        proc = subprocess.Popen(
            cmd,
            cwd=job_dir,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            preexec_fn=_apply_child_limits,
            start_new_session=True,
        )
    except OSError as exc:
        shutil.rmtree(job_dir, ignore_errors=True)
        raise ConversionError(f"Failed to start html2pdf: {exc}") from exc

    try:
        _, stderr = proc.communicate(timeout=TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        _kill_process_group(proc)
        shutil.rmtree(job_dir, ignore_errors=True)
        raise ConversionError("Rendering timed out")

    if proc.returncode != 0:
        shutil.rmtree(job_dir, ignore_errors=True)
        message = stderr.decode("utf-8", "replace").strip()
        raise ConversionError(
            f"html2pdf exited with an error (code {proc.returncode}): {message or 'no output'}"
        )

    if not os.path.isfile(output_path):
        shutil.rmtree(job_dir, ignore_errors=True)
        raise ConversionError("html2pdf did not produce an output file")

    size = os.path.getsize(output_path)
    if size == 0 or size > MAX_PDF_SIZE:
        shutil.rmtree(job_dir, ignore_errors=True)
        raise ConversionError("Invalid size of the resulting PDF")

    return job_dir, output_path


def cleanup(job_dir: str) -> None:
    if job_dir:
        shutil.rmtree(job_dir, ignore_errors=True)
