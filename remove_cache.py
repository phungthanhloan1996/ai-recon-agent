#!/usr/bin/env python3
"""
cache_cleaner.py - Xóa toàn bộ cache của ai-recon-agent
"""

import os
import shutil
from pathlib import Path

BASE = Path("/home/root17/Desktop/ai-recon-agent")

TARGETS = [
    BASE / "data" / "recon_cache.json",
    BASE / "results",  # <-- thêm xóa results
    Path.home() / ".wpscan" / "cache",
    BASE / "data" / "ai_cache.json",
]

def clean():
    print("=== CACHE CLEANER ===")
    total = 0

    for target in TARGETS:
        if not target.exists():
            print(f"⏭️  {target} — không tồn tại, bỏ qua")
            continue

        try:
            if target.is_file():
                size = target.stat().st_size
                target.unlink()
                print(f"🗑️  {target} — xóa file ({size} bytes)")
                total += size

            elif target.is_dir():
                size = sum(f.stat().st_size for f in target.rglob('*') if f.is_file())
                shutil.rmtree(target)
                target.mkdir(exist_ok=True)  # Tạo lại folder rỗng
                print(f"🗑️  {target} — xóa folder ({size} bytes, tạo lại rỗng)")
                total += size

        except Exception as e:
            print(f"❌  {target} — lỗi: {e}")

    print()
    print(f"✅ Xong! Đã giải phóng {total / 1024:.1f} KB")
    print("🚀 Sẵn sàng chạy fresh scan!")

if __name__ == "__main__":
    clean()