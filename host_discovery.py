"""
host_discovery.py
------------------
اكتشاف الأجهزة الحيّة (UP) داخل مدى شبكة معيّن (CIDR).

الفكرة:
- نأخذ مدى شبكة مثل "192.168.1.0/24" ونولّد كل عناوين IP القابلة للاستخدام فيه.
- لكل عنوان، نرسل طلب ping واحد (عبر أمر النظام `ping`) للتحقق إن كان الجهاز يستجيب.
- نستخدم Multithreading لتسريع العملية بدل فحص كل IP بالتسلسل.

ملاحظة تقنية:
نعتمد على subprocess لاستدعاء أمر `ping` الموجود في نظام Linux، بدل استخدام
raw sockets مباشرة، لأن إنشاء ICMP raw socket يتطلب صلاحيات root عادةً.
استخدام أمر `ping` النظامي أبسط تعليميًا ويعمل بدون صلاحيات خاصة في أغلب الأحيان.
"""

import ipaddress
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

from logger import setup_logger

log = setup_logger()


def is_host_up(ip: str, timeout: float = 1.0) -> bool:
    """
    التحقق من كون عنوان IP معيّن حيًّا (يستجيب لطلب ping) أم لا.

    المعاملات:
        ip (str): عنوان IP المراد فحصه.
        timeout (float): المهلة القصوى بالثواني لانتظار الرد.

    القيمة المُرجعة:
        bool: True إذا استجاب الجهاز، False إن لم يستجب أو حدث خطأ.
    """
    # -c 1  : إرسال حزمة واحدة فقط
    # -W    : مهلة الانتظار بالثواني (خاصة بنسخة Linux من ping)
    command = ["ping", "-c", "1", "-W", str(int(timeout)), ip]

    try:
        result = subprocess.run(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout + 1,  # مهلة أمان إضافية على مستوى subprocess نفسه
        )
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        log.debug(f"انتهت مهلة ping لـ {ip}")
        return False
    except Exception as e:
        log.debug(f"خطأ أثناء فحص {ip}: {e}")
        return False


def discover_hosts(network_cidr: str, timeout: float = 1.0, max_threads: int = 50) -> list[str]:
    """
    اكتشاف كل الأجهزة الحيّة داخل مدى شبكة معيّن.

    المعاملات:
        network_cidr (str): مدى الشبكة بصيغة CIDR، مثل "192.168.1.0/24".
        timeout (float): المهلة القصوى لكل عملية ping فردية.
        max_threads (int): أقصى عدد من الخيوط (threads) العاملة في نفس الوقت.

    القيمة المُرجعة:
        list[str]: قائمة بعناوين IP الحيّة، مرتبة تصاعديًا.

    ترفع:
        ValueError: إذا كانت صيغة الشبكة غير صحيحة.
    """
    try:
        network = ipaddress.ip_network(network_cidr, strict=False)
    except ValueError as e:
        log.error(f"صيغة الشبكة غير صحيحة '{network_cidr}': {e}")
        raise

    # نستخدم hosts() للحصول على العناوين القابلة للاستخدام فقط
    # (باستثناء عنوان الشبكة nework وعنوان البث broadcast)
    host_list = list(network.hosts())

    # حالة خاصة: شبكة /32 (مضيف واحد فقط) لا تحتوي hosts()، فنستخدم العنوان نفسه
    if not host_list:
        host_list = [network.network_address]

    total = len(host_list)
    log.info(f"بدء اكتشاف الأجهزة في {network_cidr} ({total} عنوان محتمل)...")

    live_hosts = []

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        # نُطلق مهمة فحص لكل عنوان IP في نفس الوقت (ضمن حد الخيوط المسموح)
        future_to_ip = {
            executor.submit(is_host_up, str(ip), timeout): str(ip) for ip in host_list
        }

        for future in as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                if future.result():
                    log.info(f"{ip}\tUP")
                    live_hosts.append(ip)
                else:
                    log.debug(f"{ip}\tDOWN")
            except Exception as e:
                log.debug(f"استثناء غير متوقع أثناء فحص {ip}: {e}")

    # ترتيب النتائج حسب قيمة IP الرقمية (وليس أبجديًا كنص)
    live_hosts.sort(key=lambda x: ipaddress.ip_address(x))

    log.info(f"انتهى الاكتشاف: {len(live_hosts)} جهاز حيّ من أصل {total}")
    return live_hosts


if __name__ == "__main__":
    # اختبار سريع مستقل للوحدة
    import sys

    if len(sys.argv) < 2:
        print("الاستخدام: python host_discovery.py <network_cidr> [timeout] [max_threads]")
        print("مثال: python host_discovery.py 192.168.1.0/24")
        sys.exit(1)

    cidr = sys.argv[1]
    to = float(sys.argv[2]) if len(sys.argv) > 2 else 1.0
    threads = int(sys.argv[3]) if len(sys.argv) > 3 else 50

    hosts = discover_hosts(cidr, timeout=to, max_threads=threads)

    print("\nالأجهزة الحيّة:")
    for h in hosts:
        print(f"  {h}\tUP")
