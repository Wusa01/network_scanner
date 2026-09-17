"""
output.py
---------
عرض نتائج الفحص بشكل منسّق في الطرفية، وتصديرها إلى ملف JSON عند الطلب.

هذه الوحدة منفصلة عن logger.py عمدًا:
- logger.py يسجّل "أحداث سير العمل" (بدء الفحص، تقدّمه، أخطاء...).
- output.py يعرض "النتيجة النهائية" للمستخدم بشكل جدول واضح، ويبنيها
  كبنية بيانات (dict) موحّدة صالحة للتصدير كـ JSON.
"""

import json
from datetime import datetime, timezone

from logger import setup_logger

log = setup_logger()


def _timestamp() -> str:
    """إرجاع الوقت الحالي بصيغة ISO 8601 (UTC) لاستخدامه في نتائج JSON."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# بناء بنية النتائج (لاستخدامها في التصدير JSON)
# ---------------------------------------------------------------------------

def build_host_discovery_result(network_cidr: str, total_scanned: int, hosts_up: list[str]) -> dict:
    """
    بناء قاموس نتائج اكتشاف الأجهزة، جاهز للعرض أو التصدير.

    المعاملات:
        network_cidr (str): مدى الشبكة الذي تم فحصه.
        total_scanned (int): إجمالي عدد العناوين التي تم فحصها.
        hosts_up (list[str]): قائمة عناوين IP الحيّة.

    القيمة المُرجعة:
        dict: بنية موحّدة لنتائج اكتشاف الأجهزة.
    """
    return {
        "scan_type": "host_discovery",
        "target": network_cidr,
        "timestamp": _timestamp(),
        "total_scanned": total_scanned,
        "total_up": len(hosts_up),
        "hosts": [{"ip": ip, "status": "UP"} for ip in hosts_up],
    }


def build_port_scan_result(ip: str, total_scanned: int, service_results: list[dict]) -> dict:
    """
    بناء قاموس نتائج فحص المنافذ، جاهز للعرض أو التصدير.

    المعاملات:
        ip (str): عنوان IP الذي تم فحصه.
        total_scanned (int): إجمالي عدد المنافذ التي تم فحصها.
        service_results (list[dict]): قائمة نتائج من detect_service، كل عنصر
            بالشكل {"port": int, "service": str, "banner": str | None}.

    القيمة المُرجعة:
        dict: بنية موحّدة لنتائج فحص المنافذ.
    """
    return {
        "scan_type": "port_scan",
        "target": ip,
        "timestamp": _timestamp(),
        "total_scanned": total_scanned,
        "total_open": len(service_results),
        "open_ports": [
            {
                "port": r["port"],
                "state": "OPEN",
                "service": r["service"],
                "banner": r.get("banner"),
            }
            for r in sorted(service_results, key=lambda x: x["port"])
        ],
    }


# ---------------------------------------------------------------------------
# العرض في الطرفية
# ---------------------------------------------------------------------------

def print_host_results(result: dict) -> None:
    """
    طباعة نتائج اكتشاف الأجهزة بشكل جدول منسّق في الطرفية.

    المعاملات:
        result (dict): ناتج build_host_discovery_result.
    """
    print(f"\nنتائج اكتشاف الأجهزة في {result['target']}")
    print(f"({result['total_up']} جهاز حيّ من أصل {result['total_scanned']})")
    print("-" * 40)

    if not result["hosts"]:
        print("لم يتم العثور على أي جهاز حيّ.")
    else:
        for host in result["hosts"]:
            print(f"{host['ip']:<20} {host['status']}")

    print("-" * 40)


def print_port_results(result: dict) -> None:
    """
    طباعة نتائج فحص المنافذ بشكل جدول منسّق في الطرفية.

    المعاملات:
        result (dict): ناتج build_port_scan_result.
    """
    print(f"\nنتائج فحص المنافذ على {result['target']}")
    print(f"({result['total_open']} منفذ مفتوح من أصل {result['total_scanned']} تم فحصه)")
    print("-" * 60)
    print(f"{'PORT':<8}{'STATE':<10}{'SERVICE':<18}{'BANNER'}")
    print("-" * 60)

    if not result["open_ports"]:
        print("لم يتم العثور على أي منفذ مفتوح.")
    else:
        for entry in result["open_ports"]:
            banner = entry["banner"] or ""
            print(f"{entry['port']:<8}{entry['state']:<10}{entry['service']:<18}{banner}")

    print("-" * 60)


# ---------------------------------------------------------------------------
# التصدير إلى JSON
# ---------------------------------------------------------------------------

def save_json(data: dict, filepath: str) -> str:
    """
    حفظ بنية نتائج (dict) إلى ملف JSON منسّق.

    المعاملات:
        data (dict): بنية النتائج (من build_host_discovery_result أو build_port_scan_result).
        filepath (str): مسار ملف الحفظ، مثل "results.json".

    القيمة المُرجعة:
        str: المسار الفعلي للملف الذي تم الحفظ فيه.

    ترفع:
        OSError: إذا تعذّرت الكتابة إلى المسار المحدد.
    """
    try:
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        log.info(f"تم حفظ النتائج في: {filepath}")
        return filepath
    except OSError as e:
        log.error(f"تعذّر حفظ النتائج في '{filepath}': {e}")
        raise


if __name__ == "__main__":
    # اختبار سريع مستقل للوحدة ببيانات وهمية
    host_result = build_host_discovery_result(
        network_cidr="192.168.1.0/24",
        total_scanned=254,
        hosts_up=["192.168.1.1", "192.168.1.5", "192.168.1.10"],
    )
    print_host_results(host_result)
    save_json(host_result, "test_hosts.json")

    port_result = build_port_scan_result(
        ip="192.168.1.10",
        total_scanned=1000,
        service_results=[
            {"port": 22, "service": "SSH", "banner": "SSH-2.0-OpenSSH_8.9"},
            {"port": 80, "service": "HTTP", "banner": "HTTP/1.1 200 OK"},
            {"port": 443, "service": "HTTPS", "banner": None},
        ],
    )
    print_port_results(port_result)
    save_json(port_result, "test_ports.json")

