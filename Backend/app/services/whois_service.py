from datetime import datetime, timezone
import whois


def get_whois_info(host):
    try:
        w = whois.whois(host)
        created = w.creation_date
        if isinstance(created, list):
            created = created[0]

        age_days = None
        if created:
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
            age_days = (datetime.now(timezone.utc) - created).days

        return {
            "registrar": w.registrar,
            "creation_date": str(created) if created else None,
            "age_days": age_days,
            "privacy_protected": _looks_privacy_protected(w),
            "raw_registrant_org": getattr(w, "org", None),
        }
    except Exception as e:
        return {"error": str(e)}


def _looks_privacy_protected(w):
    text = " ".join(str(v) for v in vars(w).values() if v).lower()
    markers = ["privacy", "whoisguard", "redacted", "proxy", "protection"]
    return any(m in text for m in markers)