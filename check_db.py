from models import Session, ScanResult

session = Session()
results = session.query(ScanResult).all()

print("扫描结果记录数:", len(results))
for r in results:
    print(f"ID: {r.id} | 目标: {r.target} | 类型: {r.scan_type} | 时间: {r.created_at}")
    print("结果:", r.result[:100] + "...")  # 只打印前100字符
