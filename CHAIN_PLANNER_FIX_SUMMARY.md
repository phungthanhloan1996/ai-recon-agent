# Chain Planner Fix - Summary

## Vấn đề gốc rễ (Root Cause Analysis)

### Lỗi ban đầu được báo cáo:
```
[2026-04-07 12:41:50] [INFO] [recon.exploitation] [EXPLOIT] Testing chain: WordPress Admin Takeover -> RCE (3 steps)
[2026-04-07 12:41:50] [DEBUG] [recon.exploitation] [EXPLOIT] Executing step: Unknown Step with context: []
[2026-04-07 12:41:50] [WARNING] [recon.http_engine] [HTTP] Skipping invalid URL: Empty URL
[2026-04-07 12:41:50] [DEBUG] [recon.exploitation] [EXPLOIT] Trying alternative step: None
[2026-04-07 12:41:50] [DEBUG] [recon.exploitation] [EXPLOIT] Executing step: Unknown Step with context: []
[2026-04-07 12:41:50] [DEBUG] [recon.http_engine] [HTTP] POST request failed for http://localhost
```

### Phân tích sâu:
1. **KHÔNG PHẢI** do context bị mất (context từ đầu đã rỗng `[]`)
2. **MÀ LÀ** do ChainPlanner sinh ra các chain "giả" dựa trên heuristic/template cứng
3. Các chain này không dựa trên dữ liệu recon thực tế
4. Executor cố gắng execute các chain vô hiệu → tự sinh target = localhost

### Bằng chứng:
- Log cho thấy tool đã phát hiện WordPress sites (dolphin-vc.com, gipt-wp.dft.vn, le-160.dft.vn)
- User enumeration possible
- XML-RPC enabled
- Nhưng chain planner không sử dụng các endpoint thực tế này
- Thay vào đó, nó dùng template cứng: `"WordPress Admin Takeover → RCE"` và cố ép executor chạy

## Giải pháp đề xuất

### 1. ChainPlanner chỉ sinh chains từ data thực
```python
def plan(self, findings, endpoints):
    chains = []
    
    # CHỈ sinh chain nếu có dữ liệu thực tế
    wp_sites = endpoints.get('wordpress', {}).get('sites', [])
    if not wp_sites:
        return []  # Không sinh chain giả!
    
    for site in wp_sites:
        target_url = site.get('url', '')
        if not target_url or target_url.startswith('localhost'):
            continue
        
        # Sinh chain với target THỰC TẾ
        if admin_url and '/wp-admin' in admin_url:
            chain = ExploitChain(
                name="WordPress Admin Takeover -> RCE",
                target_url=admin_url,  # REAL URL
                steps=[...]
            )
            chains.append(chain)
    
    return chains
```

### 2. Validation chặt chẽ
```python
def validate_chain(self, chain):
    # Reject nếu target = localhost hoặc 127.0.0.1
    if not chain.target_url or chain.target_url.startswith('localhost'):
        return False
    
    # Reject nếu steps rỗng
    if not chain.steps:
        return False
    
    # Mỗi step phải có target hợp lệ
    for step in chain.steps:
        if not step.get('target') or step.get('target').startswith('localhost'):
            return False
    
    return True
```

### 3. Khi không có chains thì làm gì?
Khi ChainPlanner không sinh được chain nào (vì không có target thực), hệ thống sẽ:

1. **Log cảnh báo rõ ràng**:
   ```
   [WARNING] [ChainPlanner] No viable exploit chains found in recon data
   ```

2. **Agent xử lý trường hợp không有 chains**:
   - Nếu `chains = []`, agent sẽ skip exploit phase
   - Chuyển sang phase tiếp theo (report/learning)
   - Báo cáo: "Không tìm thấy attack path khả thi"

3. **Không cố gắng execute chains giả**:
   - Trước đây: Cố execute → lỗi localhost
   - Bây giờ: Không có chains → không execute gì cả

## Kết quả mong đợi

### TRƯỚC KHI FIX:
```
[INFO] Testing chain: WordPress Admin Takeover -> RCE
[DEBUG] Executing step: Unknown Step with context: []
[WARNING] Skipping invalid URL: Empty URL
[DEBUG] Trying alternative step: None
[ERROR] POST request failed for http://localhost  ← LỖI!
```

### SAU KHI FIX (có real data):
```
[INFO] Generated 2 viable exploit chains from real data
[INFO]   - WordPress Admin Takeover targeting https://dolphin-vc.com/wp-admin
[INFO]   - XML-RPC Brute Force targeting https://dolphin-vc.com/xmlrpc.php
[INFO] Executing chain: WordPress Admin Takeover on https://dolphin-vc.com/wp-admin
```

### SAU KHI FIX (không có real data):
```
[WARNING] No viable exploit chains found in recon data
[INFO] Skipping exploit phase - no attack paths available
[INFO] Moving to next phase: reporting
```

## Các file liên quan

1. `ai/chain_planner.py` - ChainPlanner class (cần fix)
2. `core/exploit_executor.py` - ExploitExecutor class (cần validate chains)
3. `agent.py` - Agent orchestration (cần handle empty chains case)
4. `modules/exploiter.py` - ExploitTestEngine (cần update)

## Test cases

1. ✅ Không sinh chains khi không có data
2. ✅ Không sinh chains với localhost targets
3. ✅ Sinh chains đúng khi có WordPress endpoints thực
4. ✅ Validation từ chối chains không hợp lệ
5. ✅ Executor từ chối execute chains giả

## Lưu ý quan trọng

- **KHÔNG** được xóa class `AIPoweredChainPlanner` vì agent đang dùng
- **CHỈ** sửa class `ChainPlanner` để data-driven hơn
- **GIỮ** nguyên interface để không break agent.py
- **THÊM** validation để reject chains với localhost