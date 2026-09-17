"""
port_scanner.py
----------------
فحص منافذ TCP لجهاز واحد عبر تقنية TCP Connect Scan.

الفكرة:
- لكل منفذ في المدى المطلوب، نحاول فتح اتصال TCP كامل (three-way handshake)
  باستخدام socket.connect_ex().
- إذا نجح الاتصال (قيمة الإرجاع 0)، فالمنفذ مفتوح (OPEN).
- نستخدم Multithreading لفحص عدد كبير من المنافذ بالتوازي بدل التسلسل،
  ونضبط timeout لكل محاولة اتصال لتفادي الانتظار الطويل على المنافذ المغلقة/المفلترة.

ملاحظة تقنية:
هذا النوع (TCP Connect Scan) لا يحتاج صلاحيات root، على عكس SYN Scan
الذي يتطلب raw sockets وصلاحيات مرتفعة. لذلك هو الأنسب تعليميًا وعمليًا هنا.
"""

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from logger import setup_logger

log = setup_logger()


def parse_ports(ports_str: str) -> list[int]:
    """
    تحويل نص وصف المنافذ إلى قائمة أرقام منافذ فريدة ومرتبة.

    يدعم الصيغ التالية (يمكن دمجها بفواصل):
        "80"            -> [80]
        "1-1000"        -> [1, 2, ..., 1000]
        "22,80,443"     -> [22, 80, 443]
        "22,80,1000-1010" -> [22, 80, 1000, 1001, ..., 1010]

    المعاملات:
        ports_str (str): وصف نصي للمنافذ.

    القيمة المُرجعة:
        list[int]: قائمة أرقام المنافذ الفريدة، مرتبة تصاعديًا.

    ترفع:
        ValueError: إذا كانت الصيغة غير صحيحة أو رقم المنفذ خارج المدى [1, 65535].
    """
    ports: set[int] = set()

    for part in ports_str.split(","):
        part = part.strip()
        if not part:
            continue

        if "-" in part:
            start_str, _, end_str = part.partition("-")
            try:
                start, end = int(start_str), int(end_str)
            except ValueError:
                raise ValueError(f"مدى منافذ غير صحيح: '{part}'")
            if start > end:
                raise ValueError(f"مدى منافذ غير منطقي (البداية أكبر من النهاية): '{part}'")
            ports.update(range(start, end + 1))
        else:
            try:
                ports.add(int(part))
            except ValueError:
                raise ValueError(f"رقم منفذ غير صحيح: '{part}'")

    for p in ports:
        if not (1 <= p <= 65535):
            raise ValueError(f"رقم المنفذ خارج المدى المسموح [1-65535]: {p}")

    if not ports:
        raise ValueError("لم يتم تحديد أي منفذ صالح")

    return sorted(ports)


def scan_port(ip: str, port: int, timeout: float = 1.0) -> bool:
    """
    فحص منفذ واحد على جهاز معيّن باستخدام TCP Connect Scan.

    المعاملات:
        ip (str): عنوان IP للجهاز الهدف.
        port (int): رقم المنفذ المراد فحصه.
        timeout (float): المهلة القصوى بالثواني لمحاولة الاتصال.

    القيمة المُرجعة:
        bool: True إذا كان المنفذ مفتوحًا (OPEN)، False إذا كان مغلقًا أو مفلترًا.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        # connect_ex ترجع 0 عند نجاح الاتصال، وإلا ترجع رمز خطأ (بدون رفع استثناء)
        result = sock.connect_ex((ip, port))
        return result == 0
    except socket.gaierror as e:
        log.error(f"تعذّر تحليل العنوان '{ip}': {e}")
        return False
    except Exception as e:
        log.debug(f"خطأ أثناء فحص المنفذ {port} على {ip}: {e}")
        return False
    finally:
        sock.close()


def scan_ports(ip: str, ports: list[int], timeout: float = 1.0, max_threads: int = 100) -> list[int]:
    """
    فحص قائمة من المنافذ على جهاز واحد بالتوازي، وإرجاع المنافذ المفتوحة فقط.

    المعاملات:
        ip (str): عنوان IP للجهاز الهدف.
        ports (list[int]): قائمة أرقام المنافذ المراد فحصها.
        timeout (float): المهلة القصوى لكل محاولة اتصال فردية.
        max_threads (int): أقصى عدد من الخيوط العاملة في نفس الوقت.

    القيمة المُرجعة:
        list[int]: قائمة المنافذ المفتوحة، مرتبة تصاعديًا.
    """
    total = len(ports)
    log.info(f"بدء فحص {total} منفذ على {ip}...")

    open_ports: list[int] = []

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        future_to_port = {
            executor.submit(scan_port, ip, port, timeout): port for port in ports
        }

        for future in as_completed(future_to_port):
            port = future_to_port[future]
            try:
                if future.result():
                    log.info(f"{port}\tOPEN")
                    open_ports.append(port)
                else:
                    log.debug(f"{port}\tCLOSED/FILTERED")
            except Exception as e:
                log.debug(f"استثناء غير متوقع أثناء فحص المنفذ {port}: {e}")

    open_ports.sort()
    log.info(f"انتهى فحص المنافذ: {len(open_ports)} منفذ مفتوح من أصل {total}")
    return open_ports


if __name__ == "__main__":
    # اختبار سريع مستقل للوحدة
    import sys

    if len(sys.argv) < 3:
        print("الاستخدام: python port_scanner.py <ip> <ports> [timeout] [max_threads]")
        print("مثال: python port_scanner.py 127.0.0.1 1-1000")
        sys.exit(1)

    target_ip = sys.argv[1]
    ports_arg = sys.argv[2]
    to = float(sys.argv[3]) if len(sys.argv) > 3 else 1.0
    threads = int(sys.argv[4]) if len(sys.argv) > 4 else 100

    try:
        port_list = parse_ports(ports_arg)
    except ValueError as e:
        print(f"خطأ: {e}")
        sys.exit(1)

    results = scan_ports(target_ip, port_list, timeout=to, max_threads=threads)

    print(f"\nالمنافذ المفتوحة على {target_ip}:")
    for p in results:
        print(f"  {p}\tOPEN")
