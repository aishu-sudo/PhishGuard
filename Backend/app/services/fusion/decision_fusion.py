from os import path
from pyexpat import features
import re
import math
import time
import joblib
import numpy as np
import pandas as pd
import traceback
from pathlib import Path
from urllib.parse import urlparse
from scipy.sparse import hstack, csr_matrix

from rapidfuzz.distance import Levenshtein
from rapidfuzz import fuzz
from app.services.threat_intel import investigate
from app.services.safe_browsing import check_safe_browsing

from app.config import (
    XGB_MODEL_PATH,
    ISO_MODEL_PATH,
    TFIDF_PATH,
    FEATURE_NAMES_PATH,
    URL_META_PATH,
    W_SUPERVISED,
    W_ANOMALY,
    ANOMALY_MIN,
    ANOMALY_MAX,
    RED_THRESHOLD,
    YELLOW_THRESHOLD,
    SAFE_BROWSING_BONUS,
)

# ==========================================================
# URL FEATURE CONSTANTS
# ==========================================================

IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

SPECIAL_CHARS = {
    "@",
    "?",
    "=",
    "&",
    "%",
}

SUSPICIOUS_WORDS = [
    "login",
    "verify",
    "secure",
    "account",
    "bank",
    "update",
    "signin",
    "password",
    "confirm",
    "wallet",
    "crypto",
    "bonus",
    "free",
]

RISKY_TLDS = {
    "xyz",
    "top",
    "tk",
    "ml",
    "ga",
    "cf",
    "gq",
    "click",
    "work",
}

SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "cutt.ly",
    "cutt.us",
    "shorturl.at",
    "rb.gy",
    "tiny.cc",
    "t.ly",
    "v.gd",
    "savelinks.me",
    "ln.run",
}
_MULTI_TLDS = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "co.jp", "co.in", "co.kr",
    "com.au", "com.br", "com.bd", "com.pk", "com.tr", "com.mx", "com.sg",
    "com.hk", "com.tw", "co.za", "co.nz", "com.ar", "com.ua", "net.au",
}


def _extract_apex(host_no_www):
    """
    Registrable domain from an already-lowercased, www-stripped host.
    "app.notion.com" -> "notion.com"; "notion.com" -> "notion.com";
    "shop.example.co.uk" -> "example.co.uk".
    """
    parts = host_no_www.split(".")
    if len(parts) <= 2:
        return host_no_www
    if ".".join(parts[-2:]) in _MULTI_TLDS and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])
# ==========================================================
# LOAD TOP BRANDS
# ==========================================================
# LOAD TOP BRANDS
# ==========================================================

from app.config import BASE_DIR

tranco_candidates = [
    BASE_DIR / "Research/data/Top Sites.csv",
    Path(__file__).resolve().parents[4] / "Research/data/Top Sites.csv",
    Path(r"E:\CAPSTONE\PhishGuard_Friend\Research\data\Top Sites.csv"),
    Path(r"E:\Project Demo\Research\data\Top Sites.csv")
]

TRANCO_FILE = None
for candidate in tranco_candidates:
    if candidate.exists():
        TRANCO_FILE = str(candidate)
        break

if TRANCO_FILE:
    print(f"[fusion] Loading top domains from {TRANCO_FILE}")
    df = pd.read_csv(
        TRANCO_FILE,
        header=None,
        names=["rank", "domain"],
        nrows=100000,
    )
    _raw_domains = (
        df["domain"]
          .dropna()
          .astype(str)
          .str.lower()
          .str.split(".")
          .str[0]
          .tolist()
    )
    FULL_TOP_DOMAINS = set(
        df["domain"].dropna().astype(str).str.lower().tolist()
    )
else:
    print("[fusion] Warning: Top Sites.csv not found; initializing empty brand lists.")
    _raw_domains = []
    FULL_TOP_DOMAINS = set()

# NOTE: must match notebook training logic exactly (length filter + dedupe),
# otherwise TOP_BRANDS/ALL_BRANDS differ from what the model was trained on.
domains = []
for brand in _raw_domains:
    if len(brand) >= 3:
        domains.append(brand)

domains = list(dict.fromkeys(domains))  # dedupe, preserve order

TOP_BRANDS = domains[:10000]
ALL_BRANDS = domains[:20000]

# Full registrable domains (e.g. "bkash.com"), used ONLY for the exact-match
# allowlist short-circuit below. This is intentionally separate from
# TOP_BRANDS/ALL_BRANDS (first-label tokens like "bkash"), because matching
# on the first label alone would allowlist any TLD swap of a known brand
# (e.g. "bkash.xyz", "paypal.tk") — precisely the typosquat pattern this
print(f"TOP_BRANDS: {len(TOP_BRANDS)}")
print(f"ALL_BRANDS: {len(ALL_BRANDS)}")
print(f"FULL_TOP_DOMAINS: {len(FULL_TOP_DOMAINS)}")



# ==========================================================
# HOMOGRAPH MAPS
# ==========================================================

HOMOGLYPHS = {
    "0": "o",
    "1": "l",
    "3": "e",
    "5": "s",
    "@": "a",
    "$": "s",
}

HOMOGRAPH_MAP = {
    "а": "a",
    "е": "e",
    "о": "o",
    "р": "p",
    "с": "c",
    "у": "y",
    "х": "x",
    "і": "i",
    "ј": "j",
    "ӏ": "l",
}

import urllib.request

def _unshorten_url(url: str, timeout: float = 2.5) -> str:
    """Follow HTTP redirects for shorteners to unmask destination URL."""
    full_url = url if url.startswith(("http://", "https://")) else "http://" + url
    try:
        req = urllib.request.Request(
            full_url,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
        )
        with urllib.request.urlopen(req, timeout=timeout) as response:
            target = response.geturl()
            if target and target != full_url:
                print(f"[fusion] Unshortened link: {url} -> {target}")
                return target
    except Exception as e:
        print(f"[fusion] Could not unshorten {url}: {e}")
    return url

def safe_parse_url(url):

    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", url):
        url = "http://" + url

    return urlparse(url)


def calculate_entropy(text):

    if not text:
        return 0.0

    prob = [text.count(c) / len(text) for c in set(text)]

    return -sum(
        p * math.log2(p)
        for p in prob
    )


def normalize_homoglyphs(text):

    text = text.lower()

    for fake, real in HOMOGLYPHS.items():
        text = text.replace(fake, real)

    return text


def normalize_homograph(text):

    normalized = ""

    for ch in text:
        normalized += HOMOGRAPH_MAP.get(ch, ch)

    return normalized


def get_closest_brand(domain):

    best_brand = ""
    min_dist = 999

    for brand in ALL_BRANDS:

        dist = Levenshtein.distance(domain, brand)

        if dist < min_dist:

            min_dist = dist
            best_brand = brand

    return best_brand, min_dist


def similarity_score(domain):

    max_score = 0

    for brand in ALL_BRANDS:

        score = fuzz.ratio(domain, brand)

        max_score = max(max_score, score)

    return max_score


def is_typosquat(domain):

    normalized = normalize_homograph(domain)
    normalized = normalize_homoglyphs(normalized)

    if normalized in TOP_BRANDS and domain != normalized:
        return 1

    return 0


def homograph_features(domain):

    count = 0

    for ch in domain:

        if ch in HOMOGRAPH_MAP:
            count += 1

    normalized = normalize_homograph(domain)
    normalized = normalize_homoglyphs(normalized)

    brand_match = 0

    if normalized in TOP_BRANDS:
        brand_match = 1

    return {
        "has_homograph": int(count > 0),
        "homograph_count": count,
        "normalized_brand_match": brand_match,
    }


def brand_features(url):

    parsed = safe_parse_url(url)

    host = (parsed.hostname or "").lower()

    if host.startswith("www."):
        host = host[4:]

    domain = host.split(".")[0]

    normalized = normalize_homograph(domain)
    normalized = normalize_homoglyphs(normalized)

    closest_brand, distance = get_closest_brand(normalized)

    spoof_score = similarity_score(normalized)

    keyword_count = 0

    for brand in TOP_BRANDS:
        if brand in domain:
            if domain != brand:
                keyword_count += 1

    return {
        "brand_spoof_score": spoof_score,
        "closest_brand_distance": distance,
        "brand_keyword_count": keyword_count,
        "is_typosquat": is_typosquat(domain),
    }
    
    
# ==========================================================
# FEATURE EXTRACTION
# ==========================================================

def extract_features(url):

    features = {}

    parsed = safe_parse_url(url)

    host = (parsed.hostname or "").lower()

    path = parsed.path or ""

    query = parsed.query or ""

    url_lower = url.lower()

    host_no_www = host[4:] if host.startswith("www.") else host

    domain_parts = host_no_www.split(".") if host_no_www else []

    has_ip = 1 if IPV4_RE.match(host) else 0

    # ------------------------------------------------------
    # Length Features
    # ------------------------------------------------------

    features["url_length"] = len(url)
    features["host_length"] = len(host)
    features["path_length"] = len(path)
    features["query_length"] = len(query)

    # ------------------------------------------------------
    # Character Features
    # ------------------------------------------------------

    features["dot_count"] = url.count(".")
    features["hyphen_count"] = url.count("-")
    features["slash_count"] = url.count("/")
    features["digit_count"] = sum(c.isdigit() for c in url)
    features["special_char_count"] = sum(c in SPECIAL_CHARS for c in url)

    features["has_at_symbol"] = int("@" in url)

    # ------------------------------------------------------
    # HTTPS
    # ------------------------------------------------------

    features["has_https"] = int(parsed.scheme == "https")

    features["https_in_path"] = int(
        "https" in path.lower()
    )

    # ------------------------------------------------------
    # Subdomain
    # ------------------------------------------------------

    if has_ip:

        features["subdomain_count"] = 0

    elif len(domain_parts) > 2:

        features["subdomain_count"] = len(domain_parts) - 2

    else:

        features["subdomain_count"] = 0

    # ------------------------------------------------------
    # Host Features
    # ------------------------------------------------------

    features["host_digit_ratio"] = (
        sum(c.isdigit() for c in host) / len(host)
        if len(host)
        else 0
    )

    features["hyphen_in_host"] = int("-" in host)

    features["has_ip"] = has_ip

    # ------------------------------------------------------
    # Path Features
    # ------------------------------------------------------

    features["path_depth"] = path.count("/")

    cleaned_url = re.sub(
        r"^[a-zA-Z][a-zA-Z0-9+.\-]*://",
        "",
        url,
    )

    features["double_slash_count"] = cleaned_url.count("//")

    tokens = re.split(
        r"[./?=&_\-:]",
        url,
    )

    features["max_token_length"] = max(
        (len(t) for t in tokens if t),
        default=0,
    )

    # ------------------------------------------------------
    # Suspicious Words
    # ------------------------------------------------------

    features["suspicious_word_count"] = sum(
        word in url_lower
        for word in SUSPICIOUS_WORDS
    )
    
    domain_only = host_no_www.split(".")[0]

    # ------------------------------------------------------
    # TLD Features
    # ------------------------------------------------------

    tld = ""

    if not has_ip:
        
        if len(domain_parts) >= 2:
            
            tld = domain_parts[-1]

    features["risky_tld"] = int(tld in RISKY_TLDS)
    features["tld_in_path"] = int(bool(tld) and tld in path.lower())

    features["is_shortened"] = int(host in SHORTENERS)

    features["host_entropy"] = calculate_entropy(host) if len(host) >= 12 else 0.0
    features["path_entropy"] = calculate_entropy(path) if len(path) >= 12 else 0.0

    features.update(brand_features(url))
    features.update(homograph_features(domain_only))

    return list(features.values()), list(features.keys())



# ==========================================================
# URL NORMALIZER
# ==========================================================

def _normalize_url(url):

    url = str(url).strip()

    for prefix in (
        "https://",
        "http://",
        "ftp://",
    ):

        if url.lower().startswith(prefix):

            return url[len(prefix):]

    return url

# ==========================================================
# LOAD MODELS (LAZY)
# ==========================================================

_xgb = None
_iso = None
_tfidf = None
_feature_names = None

def _get_url_models():
    global _xgb, _iso, _tfidf, _feature_names
    if _xgb is None:
        import gc
        gc.collect()
        _xgb = joblib.load(XGB_MODEL_PATH)
        _iso = joblib.load(ISO_MODEL_PATH)
        try:
            _tfidf = joblib.load(TFIDF_PATH)
        except Exception as err:
            print(f"[URL] Warning: Could not load TFIDF vectorizer ({err}); using fallback.")
            _tfidf = None
        try:
            _meta = joblib.load(URL_META_PATH)
            _feature_names = _meta.get("feature_names") or joblib.load(FEATURE_NAMES_PATH)
        except Exception:
            _feature_names = joblib.load(FEATURE_NAMES_PATH)
        gc.collect()
        tfidf_vocab = len(_tfidf.vocabulary_) if (_tfidf and hasattr(_tfidf, "vocabulary_")) else 0
        print(f"[URL] Models Loaded | Features: {len(_feature_names)} | TF-IDF: {tfidf_vocab}")
    return _xgb, _iso, _tfidf, _feature_names

# ==========================================================
# HELPERS
# ==========================================================

def _normalize_anomaly(raw):

    return float(
        np.clip(
            (raw - ANOMALY_MIN)
            / (ANOMALY_MAX - ANOMALY_MIN),
            0.0,
            1.0,
        )
    )


def _alert(score):

    if score >= RED_THRESHOLD:
        return "RED"

    if score >= YELLOW_THRESHOLD:
        return "YELLOW"

    return "GREEN"




    # ------------------------------------------------------
    # Feature Extraction
    # ------------------------------------------------------

def score_url(url: str, fast: bool = False):

    _xgb, _iso, _tfidf, _feature_names = _get_url_models()
    _n_features = len(_feature_names)

    total_start = time.time()

    raw_url = str(url).strip()

    norm = _normalize_url(raw_url)
    
    # ------------------------------------------------------
    # Allowlist short-circuit for known-safe top domains
    # ------------------------------------------------------
    
    parsed = safe_parse_url(raw_url)
    host = (parsed.hostname or "").lower()
    host_no_www = host[4:] if host.startswith("www.") else host

   

    is_shortener_domain = host_no_www in SHORTENERS or any(s in host_no_www for s in SHORTENERS)

    is_allowlisted = False
    if not is_shortener_domain:
        is_allowlisted = host_no_www in FULL_TOP_DOMAINS
        if not is_allowlisted:
            apex_candidate = _extract_apex(host_no_www)
            if apex_candidate in FULL_TOP_DOMAINS:
                is_allowlisted = True

    if is_allowlisted:
        return {
            "url": raw_url,
            "alert_level": "GREEN",
            "fused_score": 0.0,
            "supervised_score": 0.0,
            "anomaly_score": 0.0,
            "note": "allowlisted_domain",
        }

    t = time.time()
    target_url = norm
    if host_no_www in SHORTENERS or any(s in host_no_www for s in SHORTENERS):
        unmasked = _unshorten_url(raw_url)
        if unmasked and unmasked != raw_url:
            target_url = _normalize_url(unmasked)
            print(f"[fusion] Unmasked shortener target: {target_url}")

    try:
        values, names = extract_features(target_url)

        print(f"Feature Extraction : {time.time()-t:.3f} sec")
        print("=" * 70)
        print("RUNTIME FEATURE NAMES")
        print(names)

        print("=" * 70)
        print("MODEL FEATURE NAMES")
        print(_feature_names)

        print("=" * 70)
        print("ORDER MATCH:", names == _feature_names)

        print("Runtime Feature Count :", len(names))
        print("Model Feature Count   :", len(_feature_names))
        print("=" * 70)
        print("\n================ AMAZON FEATURES ================\n")

        for n, v in zip(names, values):
            print(f"{n:30} {v}")
    except Exception as e:
        traceback.print_exc()
        return {
            "url": raw_url,
            "alert_level": "YELLOW",
            "fused_score": 0.50,
            "error": str(e),
        }

    print(f"Extracted Features : {len(values)}")
    print(f"Model Features     : {_n_features}")

    if len(values) != _n_features:
        return {
        "url": raw_url,
        "alert_level": "YELLOW",
        "fused_score": 0.50,
        "error": f"Feature Count Mismatch ({len(values)} vs {_n_features})",
        }

    # ------------------------------------------------------
    # TF-IDF
    # ------------------------------------------------------

    feature_dict = dict(zip(names, values))

    ordered_values = [
        feature_dict[f]
        for f in _feature_names
    ]

    h_arr = np.array(
        ordered_values,
        dtype=np.float32,
    ).reshape(1, -1)

    t = time.time()

    if _tfidf is not None:
        try:
            t_arr = _tfidf.transform([norm])
        except Exception:
            num_tfidf = max(0, getattr(_xgb, "n_features_in_", 0) - h_arr.shape[1])
            t_arr = csr_matrix((1, num_tfidf))
    else:
        num_tfidf = max(0, getattr(_xgb, "n_features_in_", 0) - h_arr.shape[1])
        t_arr = csr_matrix((1, num_tfidf))

    print(
        f"TF-IDF             : {time.time()-t:.3f} sec"
    )

    X = hstack(
        [
            csr_matrix(h_arr),
            t_arr,
        ]
    )

    # ------------------------------------------------------
    # XGBoost
    # ------------------------------------------------------

    t = time.time()

    sup_score = float(
        _xgb.predict_proba(X)[0, 1]
    )

    print(
        f"XGBoost            : {time.time()-t:.3f} sec"
    )

    # ------------------------------------------------------
    # Isolation Forest
    # ------------------------------------------------------

    t = time.time()

    raw = float(
        -_iso.score_samples(h_arr)[0]
    )

    anom_score = _normalize_anomaly(raw)

    print(
        f"Isolation Forest   : {time.time()-t:.3f} sec"
    )

    # ------------------------------------------------------
    # Decision Fusion
    # ------------------------------------------------------

    fused = (
        W_SUPERVISED * sup_score
        +
        W_ANOMALY * anom_score
    )

    # ------------------------------------------------------
    # Shortener Link Masking Risk Floor Rule
    # ------------------------------------------------------
    if feature_dict.get("is_shortened") == 1 or host_no_www in SHORTENERS:
        # URL shorteners mask the true destination domain, posing inherent risk
        fused = max(fused, 0.48)

    # ------------------------------------------------------
    # Google Safe Browsing
    # ------------------------------------------------------

    threat_intel_report = None

    if fused >= 0.40:

        print(
            "Checking Google Safe Browsing..."
        )

        t = time.time()

        sb_result = check_safe_browsing(raw_url)

        print(
            f"Google Safe Browsing : "
            f"{time.time()-t:.3f} sec"
        )

        if sb_result.get("flagged"):

            print(
                "Google detected malicious URL."
            )

            fused = min(
                fused + SAFE_BROWSING_BONUS,
                1.0,
            )

        elif sb_result.get("status") != "ok":

            print(
                f"Google Safe Browsing check inconclusive: {sb_result.get('status')}"
            )

        else:

            print(
                "Google says URL is safe."
            )

        alert_preview = _alert(fused)

        if not fast and alert_preview in ("YELLOW", "RED"):

            print("Running threat intelligence enrichment...")

            t = time.time()

            threat_intel_report = investigate(raw_url)

            print(
                f"Threat Intel Enrichment : "
                f"{time.time()-t:.3f} sec"
            )

    # ------------------------------------------------------
    # Total Time
    # ------------------------------------------------------

    print(
        f"Total Prediction Time : "
        f"{time.time()-total_start:.3f} sec"
    )

    result = {

        "url": raw_url,

        "alert_level": _alert(fused),

        "fused_score": round(
            fused,
            4,
        ),

        "supervised_score": round(
            sup_score,
            4,
        ),

        "anomaly_score": round(
            anom_score,
            4,
        ),
    }

    if threat_intel_report is not None:
        result["threat_intel"] = threat_intel_report

    return result