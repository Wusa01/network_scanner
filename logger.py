"""
logger.py
---------
إعداد نظام تسجيل الأحداث (Logging) الموحّد لأداة Network Scanner.

الفكرة:
- نطبع رسائل المستوى INFO فما فوق على الشاشة (console) دائمًا.
- عند تفعيل وضع verbose، نعرض أيضًا رسائل DEBUG (تفاصيل تقنية دقيقة).
- نحتفظ بكل الأحداث (بما فيها DEBUG) في ملف scanner.log بشكل دائم،
  بغض النظر عن وضع verbose، حتى يمكن مراجعة سجل كامل لاحقًا.
"""

import logging
import sys


def setup_logger(verbose: bool = False, log_file: str = "scanner.log") -> logging.Logger:
    """
    إعداد وإرجاع كائن Logger جاهز للاستخدام في كل وحدات المشروع.

    المعاملات:
        verbose (bool): إذا كانت True، تُعرض رسائل DEBUG في الطرفية أيضًا.
        log_file (str): مسار ملف السجل الذي تُحفظ فيه كل الأحداث.

    القيمة المُرجعة:
        logging.Logger: كائن logger مهيأ بالاسم "network_scanner".
    """
    logger = logging.getLogger("network_scanner")
    logger.setLevel(logging.DEBUG)  # نلتقط كل شيء، والفلترة تتم لكل handler على حدة

    # تجنّب تكرار الـ handlers إذا تم استدعاء الدالة أكثر من مرة،
    # لكن نُحدّث مستوى console handler في حال تغيّرت قيمة verbose
    # (مهم لأن الوحدات الأخرى تستدعي setup_logger() عند الاستيراد
    # قبل أن يقرأ scanner.py خيار --verbose من سطر الأوامر)
    if logger.handlers:
        for handler in logger.handlers:
            if isinstance(handler, logging.StreamHandler) and not isinstance(handler, logging.FileHandler):
                handler.setLevel(logging.DEBUG if verbose else logging.INFO)
        return logger

    # صيغة موحدة للرسائل: الوقت - المستوى - الرسالة
    formatter = logging.Formatter(
        fmt="%(asctime)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # --- Handler 1: الطرفية (Console) ---
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.DEBUG if verbose else logging.INFO)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # --- Handler 2: ملف السجل (File) ---
    try:
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    except OSError as e:
        # إذا تعذر إنشاء ملف السجل (مثلاً بسبب صلاحيات)، نكتفي بالطرفية
        logger.warning(f"تعذّر إنشاء ملف السجل '{log_file}': {e}")

    return logger


if __name__ == "__main__":
    # اختبار سريع للوحدة عند تشغيلها مباشرة
    log = setup_logger(verbose=True)
    log.debug("رسالة تجريبية من نوع DEBUG")
    log.info("رسالة تجريبية من نوع INFO")
    log.warning("رسالة تجريبية من نوع WARNING")
    log.error("رسالة تجريبية من نوع ERROR")
