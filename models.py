from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, scoped_session
from datetime import datetime
import os

Base = declarative_base()

class ScanResult(Base):
    __tablename__ = 'scan_results'
    
    id = Column(Integer, primary_key=True)
    target = Column(String(255), nullable=False)
    scan_type = Column(String(50), nullable=False)
    result = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.now, nullable=False)

# 确保数据库目录存在
db_dir = os.path.dirname(os.path.abspath(__file__))
db_path = os.path.join(db_dir, 'pentest_tool.db')

# 初始化数据库
engine = create_engine(f'sqlite:///{db_path}')
Base.metadata.create_all(engine)
Session = scoped_session(sessionmaker(bind=engine))
