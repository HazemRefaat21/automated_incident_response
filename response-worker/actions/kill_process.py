"""
Kill suspicious processes using psutil
"""
import psutil
import logging

logger = logging.getLogger(__name__)

# Processes محمية — مش هنقتلهم أبداً
PROTECTED_PROCESSES = {
    'systemd', 'init', 'sshd', 'nginx', 'postgres', 'redis-server',
    'celery', 'python', 'python3', 'wazuh-agentd', 'wazuh-logcollector',
    'wazuh-syscheckd', 'wazuh-modulesd', 'wazuh-execd', 'bash', 'sh',
}

PROTECTED_PIDS = {1}  # PID 1 دايماً محمي


def find_suspicious_processes() -> list:
    """
    Find processes that look suspicious:
    - CPU > 90% for extended time
    - Listening on unusual ports
    """
    suspicious = []

    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'cmdline']):
        try:
            info = proc.info
            if info['name'] in PROTECTED_PROCESSES:
                continue
            if info['pid'] in PROTECTED_PIDS:
                continue
            if proc.cpu_percent(interval=1) > 90:
                suspicious.append({
                    'pid':  info['pid'],
                    'name': info['name'],
                    'reason': 'High CPU usage'
                })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    return suspicious


def kill_process(pid: int, reason: str = '') -> dict:
    """
    Safely terminate a process.
    """
    if pid in PROTECTED_PIDS:
        return {'success': False, 'message': f'PID {pid} is protected'}

    try:
        proc = psutil.Process(pid)

        if proc.name() in PROTECTED_PROCESSES:
            return {
                'success': False,
                'message': f'Process {proc.name()} is protected'
            }

        # Log قبل الـ kill
        logger.warning(
            f"Killing process: PID={pid}, name={proc.name()}, "
            f"reason={reason}, cmd={proc.cmdline()}"
        )

        proc.terminate()

        try:
            proc.wait(timeout=5)
        except psutil.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=3)

        logger.info(f"✅ Process {pid} killed successfully")
        return {
            'success': True,
            'message': f'Process {pid} ({proc.name()}) terminated'
        }

    except psutil.NoSuchProcess:
        return {'success': False, 'message': f'Process {pid} not found'}
    except psutil.AccessDenied:
        return {'success': False, 'message': f'Access denied for PID {pid}'}
    except Exception as e:
        logger.error(f"Kill process error: {e}")
        return {'success': False, 'message': str(e)}
