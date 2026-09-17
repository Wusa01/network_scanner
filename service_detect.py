"""
service_detect.py
------------------
تحديد اسم الخدمة المرتبطة بمنفذ مفتوح، بطريقتين:

1. مطابقة رقم المنفذ مع قاموس المنافذ المعروفة (Well-Known Ports) — سريعة
   وموثوقة للمنافذ القياسية (22->SSH, 80->HTTP, ...).

2. Banner Grabbing (اختياري): الاتصال الفعلي بالمنفذ ومحاولة قراءة أول
   استجابة نصية يرسلها الخادم (مثل نسخة SSH أو ترويسة HTTP)، لتأكيد
   أو تفصيل ما استنتجناه من رقم المنفذ فقط.
"""

import socket

from logger import setup_logger

log = setup_logger()


# قاموس المنافذ المعروفة (Well-Known Ports) -> اسم الخدمة
COMMON_PORTS: dict[int, str] = {
    20: "FTP-DATA",
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    69: "TFTP",
    80: "HTTP",
    110: "POP3",
    111: "RPCBIND",
    123: "NTP",
    135: "MSRPC",
    137: "NETBIOS-NS",
    138: "NETBIOS-DGM",
    139: "NETBIOS-SSN",
    143: "IMAP",
    161: "SNMP",
    179: "BGP",
    194: "IRC",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    514: "SYSLOG",
    515: "PRINTER",
    587: "SMTP-SUBMISSION",
    631: "IPP",
    636: "LDAPS",
    873: "RSYNC",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "ORACLE-DB",
    2049: "NFS",
    2181: "ZOOKEEPER",
    3128: "SQUID-PROXY",
    3306: "MYSQL",
    3389: "RDP",
    5000: "UPNP/FLASK-DEV",
    5432: "POSTGRESQL",
    5900: "VNC",
    5984: "COUCHDB",
    6379: "REDIS",
    6443: "KUBERNETES-API",
    8000: "HTTP-ALT",
    8080: "HTTP-PROXY",
    8443: "HTTPS-ALT",
    9000: "HTTP-ALT",
    9092: "KAFKA",
    9200: "ELASTICSEARCH",
    27017: "MONGODB",
}


def get_service_name(port: int) -> str:
    """
    إرجاع اسم الخدمة المعروفة لمنفذ معيّن حسب قاموس COMMON_PORTS.

    المعاملات:
        port (int): رقم المنفذ.

    القيمة المُرجعة:
        str: اسم الخدمة إن كان معروفًا، وإلا "UNKNOWN".
    """
    return COMMON_PORTS.get(port, "UNKNOWN")


def grab_banner(ip: str, port: int, timeout: float = 1.5) -> str | None:
    """
    محاولة الاتصال بمنفذ مفتوح وقراءة الـ banner الذي يرسله الخادم.

    لبعض الخدمات (مثل SSH وSMTP وFTP) يرسل الخادم رسالة ترحيب فور الاتصال.
    أما خدمات مثل HTTP فلا ترسل شيئًا حتى تستقبل طلبًا، لذلك نرسل طلب
    HTTP بسيط (HEAD /) على منافذ HTTP الشائعة لمحاولة استخراج الترويسة.

    المعاملات:
        ip (str): عنوان IP للجهاز الهدف.
        port (int): رقم المنفذ المفتوح.
        timeout (float): المهلة القصوى بالثواني لعملية الاتصال والقراءة.

    القيمة المُرجعة:
        str | None: نص الـ banner المُنظّف (سطر واحد)، أو None إن تعذّر الحصول عليه.
    """
    http_like_ports = {80, 8000, 8080, 8443, 9000}

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((ip, port))

            if port in http_like_ports:
                # نرسل طلب HTTP بسيط لاستدراج ترويسة الاستجابة
                request = f"HEAD / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n"
                sock.sendall(request.encode(errors="ignore"))

            data = sock.recv(1024)
            banner = data.decode(errors="ignore").strip()

            if not banner:
                return None

            # نأخذ أول سطر فقط لعرض مختصر ونظيف
            first_line = banner.splitlines()[0].strip()
            return first_line if first_line else None

    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        log.debug(f"تعذّر قراءة banner من {ip}:{port} — {e}")
        return None
    except Exception as e:
        log.debug(f"خطأ غير متوقع أثناء قراءة banner من {ip}:{port} — {e}")
        return None


def detect_service(ip: str, port: int, timeout: float = 1.5, with_banner: bool = True) -> dict:
    """
    تحديد معلومات الخدمة الكاملة لمنفذ مفتوح: الاسم المعروف + banner اختياري.

    المعاملات:
        ip (str): عنوان IP للجهاز الهدف.
        port (int): رقم المنفذ المفتوح.
        timeout (float): المهلة القصوى لعملية قراءة الـ banner.
        with_banner (bool): إذا كانت True، تُجرى محاولة فعلية لقراءة الـ banner.

    القيمة المُرجعة:
        dict: قاموس بالشكل التالي:
            {
                "port": int,
                "service": str,       # من القاموس المعروف، أو "UNKNOWN"
                "banner": str | None  # نص الـ banner إن وُجد
            }
    """
    service_name = get_service_name(port)
    banner = grab_banner(ip, port, timeout) if with_banner else None

    if banner:
        log.debug(f"{ip}:{port} banner: {banner}")

    return {"port": port, "service": service_name, "banner": banner}


if __name__ == "__main__":
    # اختبار سريع مستقل للوحدة
    import sys

    if len(sys.argv) < 3:
        print("الاستخدام: python service_detect.py <ip> <port> [timeout]")
        print("مثال: python service_detect.py 127.0.0.1 80")
        sys.exit(1)

    target_ip = sys.argv[1]
    target_port = int(sys.argv[2])
    to = float(sys.argv[3]) if len(sys.argv) > 3 else 1.5

    info = detect_service(target_ip, target_port, timeout=to)
    print(f"\nمنفذ {info['port']}:")
    print(f"  الخدمة : {info['service']}")
    print(f"  Banner : {info['banner'] or '(لا يوجد)'}")
