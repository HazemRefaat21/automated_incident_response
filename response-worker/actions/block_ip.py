"""
Block IP via iptables
"""
import subprocess
import logging
from datetime import datetime, timedelta
from django.utils import timezone

logger = logging.getLogger(__name__)

# IPs دايماً محمية — مش هنبلوكهم أبداً
PROTECTED_IPS = {
    '127.0.0.1',
    '::1',
    'localhost',
    '172.18.0.1',   # Docker gateway
    '172.18.0.3',   # Wazuh Manager
}


def block_ip(ip_address: str, duration_hours: int = 24) -> dict:
    """
    Block an IP using iptables.
    Returns: {success, message}
    """
    if not ip_address or ip_address in PROTECTED_IPS:
        return {
            'success': False,
            'message': f'IP {ip_address} is protected — skipping block'
        }

    try:
        # تحقق لو IP اتبلك بالفعل
        check = subprocess.run(
            ['sudo', 'iptables', '-C', 'INPUT', '-s', ip_address, '-j', 'DROP'],
            capture_output=True
        )
        if check.returncode == 0:
            return {
                'success': True,
                'message': f'IP {ip_address} already blocked'
            }

        # اعمل الـ block
        result = subprocess.run(
            ['sudo', 'iptables', '-I', 'INPUT', '-s', ip_address, '-j', 'DROP'],
            capture_output=True,
            text=True,
            timeout=10
        )

        if result.returncode != 0:
            return {
                'success': False,
                'message': f'iptables error: {result.stderr}'
            }

        # حدّث الـ IPProfile في DB
        try:
            from alerts.models import IPProfile
            ip, _ = IPProfile.objects.get_or_create(ip_address=ip_address)
            ip.is_blocked    = True
            ip.blocked_at    = timezone.now()
            ip.blocked_reason = f'Auto-blocked for {duration_hours}h'
            ip.save()
        except Exception as e:
            logger.warning(f"Could not update IPProfile: {e}")

        logger.info(f"✅ Blocked IP: {ip_address} for {duration_hours}h")
        return {
            'success': True,
            'message': f'IP {ip_address} blocked for {duration_hours}h'
        }

    except subprocess.TimeoutExpired:
        return {'success': False, 'message': 'iptables command timed out'}
    except Exception as e:
        logger.error(f"Block IP error: {e}")
        return {'success': False, 'message': str(e)}


def unblock_ip(ip_address: str) -> dict:
    """Remove IP block from iptables."""
    try:
        result = subprocess.run(
            ['sudo', 'iptables', '-D', 'INPUT', '-s', ip_address, '-j', 'DROP'],
            capture_output=True,
            text=True,
            timeout=10
        )

        # حدّث الـ IPProfile
        try:
            from alerts.models import IPProfile
            ip = IPProfile.objects.filter(ip_address=ip_address).first()
            if ip:
                ip.is_blocked    = False
                ip.blocked_at    = None
                ip.blocked_reason = None
                ip.save()
        except Exception:
            pass

        logger.info(f"✅ Unblocked IP: {ip_address}")
        return {
            'success': result.returncode == 0,
            'message': f'IP {ip_address} unblocked'
        }
    except Exception as e:
        return {'success': False, 'message': str(e)}


def is_ip_blocked(ip_address: str) -> bool:
    """Check if IP is currently blocked in iptables."""
    try:
        result = subprocess.run(
            ['sudo', 'iptables', '-C', 'INPUT', '-s', ip_address, '-j', 'DROP'],
            capture_output=True
        )
        return result.returncode == 0
    except Exception:
        return False
