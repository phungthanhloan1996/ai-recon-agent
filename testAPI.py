#!/usr/bin/env python3
"""
check_apis.py - Kiểm tra Groq, OpenRouter, WPScan, NVD (fix NVD 404)
Chạy: python3 check_apis.py
"""

import os
import json
import requests
from pathlib import Path
from datetime import datetime

# ─── CONFIG ────────────────────────────────────────────────────────────────
ENV_PATH = Path("/home/root17/Desktop/ai-recon-agent/.env")
TIMEOUT = 12  # giây

# ─── LOAD .env ─────────────────────────────────────────────────────────────
if ENV_PATH.is_file():
    print(f"→ Đọc env từ: {ENV_PATH}")
    with ENV_PATH.open() as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, val = line.split("=", 1)
                os.environ[key.strip()] = val.strip()

# ─── Helpers ───────────────────────────────────────────────────────────────
def get_env(key: str) -> str:
    val = os.environ.get(key, "").strip()
    if not val:
        print(f"⚠️ Thiếu {key}")
    return val


def print_header(name: str):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"\n{'═' * 60}")
    print(f" {name.upper()}  |  {now}")
    print(f"{'═' * 60}")


def check_api(
    name: str,
    url: str,
    headers: dict = None,
    success_key: str = None,
    success_label: str = "items",
    is_list: bool = False,
    fallback_no_auth: bool = False,
):
    print_header(name)

    full_url = url
    print(f"  URL: {full_url}")
    
    try:
        r = requests.get(full_url, headers=headers or {}, timeout=TIMEOUT)
        print(f"  Status: {r.status_code}")

        if r.status_code == 200:
            try:
                data = r.json()

                if success_key and success_key in data:
                    value = data[success_key]
                    count = len(value) if is_list else value
                    print(f"✅ OK - {success_label}: {count:,}")
                else:
                    print("⚠️ OK nhưng không thấy key mong muốn")
                    preview = json.dumps(data, indent=2, ensure_ascii=False)[:600]
                    print("Preview:", preview, "..." if len(preview) > 590 else "")

                # Rate limit info nếu có
                if "X-RateLimit-Remaining" in r.headers:
                    print(f"   → Rate limit còn: {r.headers['X-RateLimit-Remaining']} (30s window)")
                if fallback_no_auth:
                    print("   → Chạy ở chế độ public (không key - rate limit thấp)")

            except json.JSONDecodeError:
                print("❌ Không parse được JSON")
                print("Raw preview:", repr(r.text[:500]))

        elif r.status_code in (401, 403):
            print("❌ Auth lỗi (key sai/hết hạn/chưa activate)")
            if fallback_no_auth:
                print("→ Fallback không key...")
                check_api(name, url, {}, success_key, success_label, is_list, True)
            else:
                print("   → Request key mới: https://nvd.nist.gov/developers/request-an-api-key")

        elif r.status_code == 404:
            print("❌ 404 Not Found (có thể param không hợp lệ hoặc server glitch)")
            print("Response preview:", r.text[:400])
            if fallback_no_auth:
                print("→ Thử lại không param thừa...")
                # Thử bare URL như curl của bạn
                bare_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
                check_api(name, bare_url, {}, success_key, success_label, is_list, True)

        else:
            print(f"❌ HTTP {r.status_code}: {r.reason}")
            print("Preview:", r.text[:400])

    except requests.RequestException as e:
        print(f"❌ Request fail: {e.__class__.__name__} - {e}")


# ─── MAIN ──────────────────────────────────────────────────────────────────
def main():
    # GROQ
    groq_key = get_env("GROQ_API_KEY")
    check_api(
        "GROQ",
        "https://api.groq.com/openai/v1/models",
        {"Authorization": f"Bearer {groq_key}"},
        "data",
        "models",
        is_list=True,
    )

    # OPENROUTER
    or_key = get_env("OPENROUTER_API_KEY")
    check_api(
        "OPENROUTER",
        "https://openrouter.ai/api/v1/models",
        {"Authorization": f"Bearer {or_key}"},
        "data",
        "models",
        is_list=True,
    )

    # WPSCAN
    wpscan_token = get_env("WPSCAN_API_TOKEN")
    check_api(
        "WPSCAN",
        "https://wpscan.com/api/v3/status",
        {"Authorization": f"Token token={wpscan_token}"},
        "requests_remaining",
        "requests remaining",
    )

    # NVD - Fix: dùng bare URL như curl của bạn (không resultsPerPage)
    # Nếu có key thì thử với header apiKey, fallback nếu fail
    nvd_key = get_env("NVD_API_KEY")
    nvd_headers = {"apiKey": nvd_key} if nvd_key else {}
    nvd_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"  # bare, như curl OK

    print_header("NVD")
    print(f"  Using key: {'Có' if nvd_key else 'Không'}")
    check_api(
        "NVD",
        nvd_url,
        nvd_headers,
        "totalResults",
        "total CVEs",
        fallback_no_auth=bool(nvd_key),  # fallback nếu có key nhưng fail
    )


if __name__ == "__main__":
    print("=== KIỂM TRA API - BẮT ĐẦU ===")
    main()
    print("\n=== HOÀN TẤT ===\n")
