# Pipeline Data Storage Fix - Integration Tools

## Problem Statement

Các tool trong thư mục `/integrations` đang lưu dữ liệu không nhất quán, gây gãy pipeline nghiêm trọng:

1. **wayback_runner.py**: Không có `output_dir` và không lưu dữ liệu ra file
2. **httpx_runner.py**: Không lưu kết quả ra file (chỉ trả về trong bộ nhớ)
3. Các tool khác (subfinder, gau, nuclei, sqlmap) lưu vào `output_dir` nhưng không có cơ chế fallback

## Solution

### 1. Fixed: `integrations/wayback_runner.py`

**Changes:**
- Added `output_dir` parameter to `__init__()` method
- Added `_save_results()` method to save URLs to both `.txt` and `.json` files
- Modified `fetch_urls()` to automatically save results when `output_dir` is set

**Output files created:**
- `wayback_{domain}.txt` - List of URLs (one per line)
- `wayback_{domain}.json` - Structured JSON with metadata

### 2. Fixed: `integrations/httpx_runner.py`

**Changes:**
- Added `_save_results()` method to save probe results
- Modified `validate_live_hosts()` to automatically save results when `output_dir` is set

**Output files created:**
- `httpx_results.json` - Structured JSON with all probe results
- `live_hosts.txt` - List of live URLs (one per line)

### 3. Updated: `modules/recon.py`

**Changes:**
- Modified `ReconEngine.__init__()` to pass `output_dir` to `WaybackRunner`

```python
# Before
self.wayback = WaybackRunner()

# After
self.wayback = WaybackRunner(output_dir)
```

## Standardized Output Location

Tất cả các integration tools bây giờ lưu dữ liệu vào cùng một thư mục output:

```
results/
└── {domain}_{timestamp}/
    ├── state.json                    # Central state (from state_manager)
    ├── subdomains.txt                # From subfinder_runner.py
    ├── subdomains_scored.json        # From subfinder_runner.py
    ├── archived_urls.txt             # From recon.py
    ├── wayback_{domain}.txt          # From wayback_runner.py (NEW)
    ├── wayback_{domain}.json         # From wayback_runner.py (NEW)
    ├── gau_{domain}.txt              # From gau_runner.py
    ├── httpx_results.json            # From httpx_runner.py (NEW)
    ├── live_hosts.txt                # From httpx_runner.py (NEW)
    ├── nuclei_*.json                 # From nuclei_runner.py
    └── sqlmap_results/               # From sqlmap_runner.py
```

## Benefits

1. **Data Persistence**: Tất cả dữ liệu được lưu vào file, không chỉ trong bộ nhớ
2. **Recoverability**: Có thể resume scan từ dữ liệu đã lưu
3. **Debugging**: Dễ dàng kiểm tra dữ liệu ở mỗi giai đoạn
4. **Consistency**: Tất cả tools lưu vào cùng một thư mục output
5. **Multiple Formats**: Cả text (cho human-readable) và JSON (cho machine processing)

## Testing

Run a test scan to verify:

```bash
python agent.py --target example.com --output ./test_results
```

Check that all expected files are created in the output directory:
- `wayback_example_com.txt`
- `wayback_example_com.json`
- `httpx_results.json`
- `live_hosts.txt`

## Files Modified

1. `integrations/wayback_runner.py` - Added output_dir support and file saving
2. `integrations/httpx_runner.py` - Added file saving capability
3. `modules/recon.py` - Updated to pass output_dir to WaybackRunner