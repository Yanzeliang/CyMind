from models import Session, ScanResult

# 测试数据库连接
def test_connection():
    try:
        session = Session()
        count = session.query(ScanResult).count()
        print(f"数据库连接正常，现有记录数: {count}")
        session.close()
        return True
    except Exception as e:
        print(f"数据库连接失败: {str(e)}")
        return False

# 测试插入数据
def test_insert():
    try:
        session = Session()
        test_result = ScanResult(
            target="test.com",
            scan_type="test",
            result='{"test": "data"}'
        )
        session.add(test_result)
        session.commit()
        print("测试数据插入成功")
        session.close()
        return True
    except Exception as e:
        print(f"数据插入失败: {str(e)}")
        session.rollback()
        return False

if __name__ == "__main__":
    print("=== 数据库连接测试 ===")
    test_connection()
    
    print("\n=== 数据插入测试 ===")
    test_insert()
