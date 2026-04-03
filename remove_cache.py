#!/usr/bin/env python3
"""
cache_cleaner.py - Xóa toàn bộ cache của ai-recon-agent
"""

import os
import shutil
import sqlite3
from pathlib import Path

BASE = Path("/home/root17/Desktop/ai-recon-agent")

# 1. Cache trong project data
PROJECT_CACHE = [
    BASE / "data" / "cve_cache.db",        # SQLite CVE cache
    BASE / "data" / "recon_cache.json",    # Recon cache
    BASE / "data" / "ai_cache.json",       # AI cache
    BASE / "data" / "http_cache.json",     # HTTP cache (nếu có)
    BASE / "data" / "dns_cache.json",      # DNS cache (nếu có)
    BASE / "data" / "blacklist.json",      # Blacklist cache
    BASE / "data" / "unreachable.json",    # Unreachable hosts
]

# 2. Cache của tools bên ngoài
TOOL_CACHE = [
    Path.home() / ".wpscan" / "cache",
    Path.home() / ".subfinder" / "cache",
    Path.home() / ".gau" / "cache",
    Path.home() / ".cache" / "waybackurls",
    Path.home() / ".cache" / "httpx",
    Path.home() / ".assetfinder" / "cache",
]

# 3. Temp files patterns
TEMP_PATTERNS = [
    "/tmp/ai-recon-*",
    "/tmp/recon-*",
    "/tmp/wpscan-*",
    "/tmp/*cache*",
]

# 4. Python cache trong project
PYCACHE_DIRS = [
    BASE / "ai" / "__pycache__",
    BASE / "core" / "__pycache__",
    BASE / "integrations" / "__pycache__",
    BASE / "learning" / "__pycache__",
    BASE / "modules" / "__pycache__",
    BASE / "reports" / "__pycache__",
    BASE / "__pycache__",
]

# 5. Results (toàn bộ kết quả quét cũ)
RESULTS_DIR = BASE / "results"


def delete_file(path):
    """Xóa file an toàn"""
    try:
        if path.exists():
            size = path.stat().st_size
            path.unlink()
            print(f"  🗑️  Xóa file: {path} ({size:,} bytes)")
            return size
    except Exception as e:
        print(f"  ❌ Lỗi xóa {path}: {e}")
    return 0


def delete_folder(path):
    """Xóa folder an toàn"""
    try:
        if path.exists():
            # Tính tổng dung lượng trước khi xóa
            total_size = sum(f.stat().st_size for f in path.rglob('*') if f.is_file())
            shutil.rmtree(path)
            # Tạo lại folder rỗng nếu là thư mục kết quả
            if path == RESULTS_DIR:
                path.mkdir(exist_ok=True)
            print(f"  🗑️  Xóa folder: {path} ({total_size:,} bytes)")
            return total_size
    except Exception as e:
        print(f"  ❌ Lỗi xóa {path}: {e}")
    return 0


def delete_temp_patterns():
    """Xóa temp files theo pattern"""
    import glob
    total = 0
    for pattern in TEMP_PATTERNS:
        for path in glob.glob(pattern):
            p = Path(path)
            if p.is_file():
                total += delete_file(p)
            elif p.is_dir():
                total += delete_folder(p)
    return total


def main():
    print("=" * 60)
    print("🧹 AI-RECON-AGENT CACHE CLEANER")
    print("=" * 60)
    print()
    
    total_freed = 0
    
    # 1. Xóa cache trong project
    print("📁 1. Xóa cache trong project data/")
    for path in PROJECT_CACHE:
        if path.exists():
            total_freed += delete_file(path)
        else:
            print(f"  ⏭️  Không tồn tại: {path}")
    print()
    
    # 2. Xóa cache của tools
    print("🛠️  2. Xóa cache của tools bên ngoài")
    for path in TOOL_CACHE:
        if path.exists():
            total_freed += delete_folder(path)
        else:
            print(f"  ⏭️  Không tồn tại: {path}")
    print()
    
    # 3. Xóa temp files
    print("🌡️  3. Xóa temporary files")
    total_freed += delete_temp_patterns()
    print()
    
    # 4. Xóa __pycache__ (Python cache)
    print("🐍 4. Xóa Python bytecode cache (__pycache__)")
    for path in PYCACHE_DIRS:
        if path.exists():
            total_freed += delete_folder(path)
        else:
            print(f"  ⏭️  Không tồn tại: {path}")
    print()
    
    # 5. Xóa kết quả quét cũ
    print("📊 5. Xóa kết quả quét cũ (results/)")
    if RESULTS_DIR.exists():
        total_freed += delete_folder(RESULTS_DIR)
    else:
        print(f"  ⏭️  Không tồn tại: {RESULTS_DIR}")
    print()
    
    # Kết quả
    print("=" * 60)
    print(f"✅ XONG! Đã giải phóng: {total_freed / (1024*1024):.2f} MB")
    print("=" * 60)
    print()
    print("🚀 Sẵn sàng chạy fresh scan!")
    print("   Lưu ý: Khi chạy lại, các tool sẽ tự động tạo lại cache cần thiết.")


if __name__ == "__main__":
    # Chạy luôn không cần xác nhận
    main()