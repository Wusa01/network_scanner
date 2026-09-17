"""
scanner.py
----------
نقطة الدخول الرئيسية لأداة Network Security Scanner.

يحدّد سلوك الأداة تلقائيًا حسب صيغة الهدف (target) المُدخل:

1. إذا كان الهدف مدى شبكة (CIDR)، مثل "192.168.1.0/24":
   -> وضع اكتشاف الأجهزة (Host Discovery)
   مثال:
       python scanner.py 192.168.1.0/24

2. إذا كان الهدف عنوان IP واحد، مثل "192.168.1.10":
   -> وضع فحص المنافذ (Port Scanning)، مع تحديد الخدمة لكل منفذ مفتوح
   مثال:
       python scanner.py 192.168.1.10 --ports 1-1000

خيارات إضافية:
   --timeout     مهلة كل محاولة اتصال/ping فردية (ثانية). الافتراضي: 1.0
   --threads     أقصى عدد من الخيوط المتوازية. الافتراضي: 50 (اكتشاف) / 200 (منافذ)
   --json FILE   حفظ النتائج في ملف JSON بالإضافة للعرض في الطرفية
   --no-banner   تعطيل قراءة الـ banner (فحص أسرع، الاعتماد على القاموس فقط)
   --verbose     عرض تفاصيل تقنية إضافية (DEBUG) في الطرفية
"""

import argparse
import ipaddress
import sys
import time

from logger import setup_logger
from host_discovery import discover_hosts
from port_scanner import parse_ports, scan_ports
from service_detect import detect_service
from output import (
    build_host_discovery_result,
    build_port_scan_result,
    print_host_results,
    print_port_results,
    save_json,
)


def build_arg_parser() -> argparse.ArgumentParser:
    """بناء وإرجاع كائن argparse.ArgumentParser الخاص بالأداة."""
    parser = argparse.ArgumentParser(
        prog="scanner.py",
        description="Network Security Scanner - أداة تعليمية بسيطة لاكتشاف الأجهزة وفحص المنافذ.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "أمثلة:\n"
            "  python scanner.py 192.168.1.0/24\n"
            "  python scanner.py 192.168.1.10 --ports 1-1000\n"
            "  python scanner.py 192.168.1.10 --ports 22,80,443 --json result.json\n"
            "  python scanner.py 192.168.1.0/24 --timeout 0.5 --threads 100 --verbose\n"
        ),
    )

    parser.add_argument(
        "target",
        help="الهدف: مدى شبكة بصيغة CIDR (192.168.1.0/24) لاكتشاف الأجهزة، "
             "أو عنوان IP واحد (192.168.1.10) لفحص المنافذ.",
    )
    parser.add_argument(
        "--ports",
        metavar="RANGE",
        default=None,
        help="المنافذ المراد فحصها عند فحص IP واحد. مثال: '1-1000' أو '22,80,443'. "
             "الافتراضي عند عدم التحديد: '1-1024'.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=1.0,
        help="المهلة القصوى بالثواني لكل محاولة اتصال/ping فردية (افتراضي: 1.0)",
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=None,
        help="أقصى عدد من الخيوط المتوازية (افتراضي: 50 لاكتشاف الأجهزة، 200 لفحص المنافذ)",
    )
    parser.add_argument(
        "--json",
        metavar="FILE",
        default=None,
        help="حفظ النتائج في ملف JSON بالإضافة إلى عرضها في الطرفية.",
    )
    parser.add_argument(
        "--no-banner",
        action="store_true",
        help="تعطيل قراءة الـ banner للمنافذ المفتوحة (فحص أسرع).",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="عرض تفاصيل تقنية إضافية (مستوى DEBUG) في الطرفية.",
    )

    return parser


def is_network_target(target: str) -> bool:
    """
    تحديد ما إذا كان الهدف المُدخل مدى شبكة (CIDR) أو عنوان IP واحد.

    المعاملات:
        target (str): النص المُدخل من المستخدم (target).

    القيمة المُرجعة:
        bool: True إذا كان الهدف مدى شبكة (يحتوي على '/'), False إذا كان IP واحد.

    ترفع:
        ValueError: إذا كان الهدف غير صالح كـ IP ولا كشبكة CIDR على الإطلاق.
    """
    if "/" in target:
        ipaddress.ip_network(target, strict=False)  # يرفع ValueError إذا كانت الصيغة خاطئة
        return True

    ipaddress.ip_address(target)  # يرفع ValueError إذا لم يكن IP صالحًا
    return False


def run_host_discovery(target: str, timeout: float, threads: int | None) -> dict:
    """
    تنفيذ وضع اكتشاف الأجهزة الحيّة على مدى شبكة، وإرجاع بنية النتائج.

    المعاملات:
        target (str): مدى الشبكة بصيغة CIDR.
        timeout (float): مهلة كل عملية ping فردية.
        threads (int | None): أقصى عدد خيوط متوازية (افتراضي 50 إن كانت None).

    القيمة المُرجعة:
        dict: بنية نتائج اكتشاف الأجهزة (من build_host_discovery_result).
    """
    max_threads = threads if threads is not None else 50

    network = ipaddress.ip_network(target, strict=False)
    total_scanned = len(list(network.hosts())) or 1

    hosts_up = discover_hosts(target, timeout=timeout, max_threads=max_threads)
    return build_host_discovery_result(target, total_scanned, hosts_up)


def run_port_scan(
    target: str, ports_str: str, timeout: float, threads: int | None, with_banner: bool
) -> dict:
    """
    تنفيذ وضع فحص المنافذ على عنوان IP واحد، مع تحديد الخدمة لكل منفذ مفتوح.

    المعاملات:
        target (str): عنوان IP الهدف.
        ports_str (str): وصف نطاق المنافذ (مثل "1-1000").
        timeout (float): مهلة كل محاولة اتصال فردية.
        threads (int | None): أقصى عدد خيوط متوازية (افتراضي 200 إن كانت None).
        with_banner (bool): تفعيل/تعطيل قراءة الـ banner.

    القيمة المُرجعة:
        dict: بنية نتائج فحص المنافذ (من build_port_scan_result).
    """
    max_threads = threads if threads is not None else 200

    port_list = parse_ports(ports_str)
    open_ports = scan_ports(target, port_list, timeout=timeout, max_threads=max_threads)

    service_results = [
        detect_service(target, port, timeout=timeout, with_banner=with_banner)
        for port in open_ports
    ]

    return build_port_scan_result(target, len(port_list), service_results)


def main() -> int:
    """نقطة التشغيل الرئيسية للأداة. تُرجع رمز الخروج (0 نجاح، غير ذلك خطأ)."""
    parser = build_arg_parser()
    args = parser.parse_args()

    # إعادة ضبط الـ logger أولاً حسب --verbose قبل أي عملية فحص
    log = setup_logger(verbose=args.verbose)

    try:
        network_mode = is_network_target(args.target)
    except ValueError as e:
        log.error(f"هدف غير صالح '{args.target}': {e}")
        return 1

    start_time = time.time()

    try:
        if network_mode:
            if args.ports:
                log.warning(
                    "تم تجاهل --ports لأن الهدف مدى شبكة (وضع اكتشاف الأجهزة فقط في هذه النسخة)."
                )
            result = run_host_discovery(args.target, args.timeout, args.threads)
            print_host_results(result)
        else:
            ports_str = args.ports if args.ports else "1-1024"
            if not args.ports:
                log.info("لم يتم تحديد --ports، سيتم استخدام المدى الافتراضي 1-1024")
            result = run_port_scan(
                args.target, ports_str, args.timeout, args.threads, not args.no_banner
            )
            print_port_results(result)

    except ValueError as e:
        log.error(f"خطأ في المدخلات: {e}")
        return 1
    except KeyboardInterrupt:
        log.warning("تم إيقاف الفحص يدويًا من قِبل المستخدم.")
        return 130
    except Exception as e:
        log.error(f"خطأ غير متوقع: {e}")
        return 1

    elapsed = time.time() - start_time
    log.info(f"إجمالي وقت التنفيذ: {elapsed:.2f} ثانية")

    if args.json:
        try:
            save_json(result, args.json)
        except OSError:
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
