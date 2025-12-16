from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, Float, Boolean, ForeignKey, JSON
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import sessionmaker, scoped_session, relationship
from datetime import datetime
from enum import Enum
import os

Base = declarative_base()

# Enums for type safety
class ProjectStatus(Enum):
    ACTIVE = "active"
    ARCHIVED = "archived"
    COMPLETED = "completed"

class TargetType(Enum):
    DOMAIN = "domain"
    IP = "ip"
    URL = "url"
    NETWORK = "network"

class ScanType(Enum):
    RECON = "recon"
    VULNERABILITY = "vulnerability"
    WEB_APP = "web_app"
    NETWORK = "network"
    CUSTOM = "custom"

class ScanStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

class ResultType(Enum):
    SUBDOMAIN = "subdomain"
    SERVICE = "service"
    VULNERABILITY = "vulnerability"
    MISCONFIGURATION = "misconfiguration"
    INFORMATION = "information"

class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class PluginType(Enum):
    PYTHON = "python"
    BASH = "bash"
    EXTERNAL = "external"

# Enhanced Data Models
class Project(Base):
    __tablename__ = 'projects'
    
    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False, unique=True)
    description = Column(Text)
    created_at = Column(DateTime, default=datetime.now, nullable=False)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now, nullable=False)
    status = Column(String(20), default=ProjectStatus.ACTIVE.value, nullable=False)
    
    # Relationships
    targets = relationship("Target", back_populates="project", cascade="all, delete-orphan")
    scans = relationship("Scan", back_populates="project", cascade="all, delete-orphan")

class Target(Base):
    __tablename__ = 'targets'
    
    id = Column(Integer, primary_key=True)
    project_id = Column(Integer, ForeignKey('projects.id'), nullable=False)
    name = Column(String(255), nullable=False)
    url = Column(String(500))
    ip_address = Column(String(45))  # Support IPv6
    target_type = Column(String(20), nullable=False)
    target_metadata = Column(JSON)  # Store additional target information
    created_at = Column(DateTime, default=datetime.now, nullable=False)
    tags = Column(JSON)  # Store tags as JSON array
    
    # Relationships
    project = relationship("Project", back_populates="targets")
    scans = relationship("Scan", back_populates="target", cascade="all, delete-orphan")

class Scan(Base):
    __tablename__ = 'scans'
    
    id = Column(Integer, primary_key=True)
    project_id = Column(Integer, ForeignKey('projects.id'), nullable=False)
    target_id = Column(Integer, ForeignKey('targets.id'), nullable=False)
    scan_type = Column(String(20), nullable=False)
    status = Column(String(20), default=ScanStatus.PENDING.value, nullable=False)
    started_at = Column(DateTime, default=datetime.now, nullable=False)
    completed_at = Column(DateTime)
    configuration = Column(JSON)  # Store scan configuration
    
    # Relationships
    project = relationship("Project", back_populates="scans")
    target = relationship("Target", back_populates="scans")
    results = relationship("ScanResult", back_populates="scan", cascade="all, delete-orphan")

class ScanResult(Base):
    __tablename__ = 'scan_results'
    
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey('scans.id'), nullable=False)
    result_type = Column(String(20), nullable=False)
    data = Column(JSON, nullable=False)  # Store structured result data
    severity = Column(String(10))
    confidence = Column(Float)  # Confidence score 0.0-1.0
    result_metadata = Column(JSON)  # Additional metadata
    created_at = Column(DateTime, default=datetime.now, nullable=False)
    
    # Relationships
    scan = relationship("Scan", back_populates="results")
    vulnerabilities = relationship("Vulnerability", back_populates="scan_result", cascade="all, delete-orphan")

class Vulnerability(Base):
    __tablename__ = 'vulnerabilities'
    
    id = Column(Integer, primary_key=True)
    scan_result_id = Column(Integer, ForeignKey('scan_results.id'), nullable=False)
    cve_id = Column(String(20))  # CVE identifier
    title = Column(String(500), nullable=False)
    description = Column(Text)
    severity = Column(String(10), nullable=False)
    cvss_score = Column(Float)
    affected_service = Column(String(255))
    remediation = Column(Text)
    is_false_positive = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.now, nullable=False)
    
    # Relationships
    scan_result = relationship("ScanResult", back_populates="vulnerabilities")

class Plugin(Base):
    __tablename__ = 'plugins'
    
    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False, unique=True)
    version = Column(String(50), nullable=False)
    plugin_type = Column(String(20), nullable=False)
    configuration = Column(JSON)
    enabled = Column(Boolean, default=True)
    last_updated = Column(DateTime, default=datetime.now, onupdate=datetime.now, nullable=False)
    description = Column(Text)
    author = Column(String(255))
    
    # Plugin metadata
    capabilities = Column(JSON)  # What the plugin can do
    requirements = Column(JSON)  # System requirements

# 确保数据库目录存在
db_dir = os.path.dirname(os.path.abspath(__file__))
db_path = os.path.join(db_dir, 'pentest_tool.db')

# 初始化数据库
engine = create_engine(f'sqlite:///{db_path}')
Base.metadata.create_all(engine)
Session = scoped_session(sessionmaker(bind=engine))

# Database Migration System
class DatabaseMigration:
    """Handle database schema migrations and version management"""
    
    def __init__(self, engine):
        self.engine = engine
        self.current_version = self._get_current_version()
    
    def _get_current_version(self):
        """Get current database schema version"""
        try:
            # Check if migration table exists
            from sqlalchemy import inspect
            inspector = inspect(self.engine)
            if 'schema_migrations' not in inspector.get_table_names():
                return 0
            
            # Get latest migration version
            from sqlalchemy import text
            with self.engine.connect() as conn:
                result = conn.execute(text("SELECT MAX(version) FROM schema_migrations"))
                version = result.scalar()
                return version if version else 0
        except Exception:
            return 0
    
    def create_migration_table(self):
        """Create migration tracking table"""
        from sqlalchemy import text
        with self.engine.connect() as conn:
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    version INTEGER PRIMARY KEY,
                    applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """))
            conn.commit()
    
    def apply_migration(self, version, migration_sql):
        """Apply a database migration"""
        from sqlalchemy import text
        with self.engine.connect() as conn:
            try:
                # Execute migration
                conn.execute(text(migration_sql))
                
                # Record migration
                conn.execute(
                    text("INSERT INTO schema_migrations (version) VALUES (:version)"),
                    {"version": version}
                )
                conn.commit()
                return True
            except Exception as e:
                conn.rollback()
                raise e

# Data Validation and Integrity Checks
class DataValidator:
    """Validate data integrity and business rules"""
    
    @staticmethod
    def validate_project(project_data):
        """Validate project data"""
        errors = []
        
        if not project_data.get('name'):
            errors.append("Project name is required")
        elif len(project_data['name']) > 255:
            errors.append("Project name must be less than 255 characters")
        
        if project_data.get('status') and project_data['status'] not in [s.value for s in ProjectStatus]:
            errors.append("Invalid project status")
        
        return errors
    
    @staticmethod
    def validate_target(target_data):
        """Validate target data"""
        errors = []
        
        if not target_data.get('name'):
            errors.append("Target name is required")
        
        if not target_data.get('target_type'):
            errors.append("Target type is required")
        elif target_data['target_type'] not in [t.value for t in TargetType]:
            errors.append("Invalid target type")
        
        # Validate based on target type
        target_type = target_data.get('target_type')
        if target_type == TargetType.DOMAIN.value:
            if not target_data.get('url') and not target_data.get('name'):
                errors.append("Domain targets require URL or domain name")
        elif target_type == TargetType.IP.value:
            if not target_data.get('ip_address'):
                errors.append("IP targets require IP address")
        
        return errors
    
    @staticmethod
    def validate_scan(scan_data):
        """Validate scan data"""
        errors = []
        
        if not scan_data.get('scan_type'):
            errors.append("Scan type is required")
        elif scan_data['scan_type'] not in [s.value for s in ScanType]:
            errors.append("Invalid scan type")
        
        if not scan_data.get('target_id'):
            errors.append("Target ID is required")
        
        if scan_data.get('status') and scan_data['status'] not in [s.value for s in ScanStatus]:
            errors.append("Invalid scan status")
        
        return errors
    
    @staticmethod
    def validate_vulnerability(vuln_data):
        """Validate vulnerability data"""
        errors = []
        
        if not vuln_data.get('title'):
            errors.append("Vulnerability title is required")
        
        if not vuln_data.get('severity'):
            errors.append("Vulnerability severity is required")
        elif vuln_data['severity'] not in [s.value for s in Severity]:
            errors.append("Invalid severity level")
        
        if vuln_data.get('cvss_score'):
            score = vuln_data['cvss_score']
            if not isinstance(score, (int, float)) or score < 0 or score > 10:
                errors.append("CVSS score must be between 0 and 10")
        
        return errors

# Database Session Management
class DatabaseManager:
    """Centralized database management"""
    
    def __init__(self, database_url=None):
        if database_url is None:
            # Default to SQLite in project directory
            db_dir = os.path.dirname(os.path.abspath(__file__))
            db_path = os.path.join(db_dir, 'pentest_tool.db')
            database_url = f'sqlite:///{db_path}'
        
        self.engine = create_engine(database_url, echo=False)
        self.Session = scoped_session(sessionmaker(bind=self.engine))
        self.migration_manager = DatabaseMigration(self.engine)
        
        # Initialize database
        self._initialize_database()
    
    def _initialize_database(self):
        """Initialize database with tables and migrations"""
        # Create migration table
        self.migration_manager.create_migration_table()
        
        # Create all tables
        Base.metadata.create_all(self.engine)
    
    def get_session(self):
        """Get database session"""
        return self.Session()
    
    def close_session(self):
        """Close database session"""
        self.Session.remove()
    
    def validate_data_integrity(self):
        """Run comprehensive data integrity checks"""
        session = self.get_session()
        issues = []
        
        try:
            # Check for orphaned records
            orphaned_targets = session.query(Target).filter(
                ~Target.project_id.in_(session.query(Project.id))
            ).count()
            if orphaned_targets > 0:
                issues.append(f"Found {orphaned_targets} orphaned targets")
            
            orphaned_scans = session.query(Scan).filter(
                ~Scan.target_id.in_(session.query(Target.id))
            ).count()
            if orphaned_scans > 0:
                issues.append(f"Found {orphaned_scans} orphaned scans")
            
            orphaned_results = session.query(ScanResult).filter(
                ~ScanResult.scan_id.in_(session.query(Scan.id))
            ).count()
            if orphaned_results > 0:
                issues.append(f"Found {orphaned_results} orphaned scan results")
            
            # Check for invalid enum values
            invalid_project_status = session.query(Project).filter(
                ~Project.status.in_([s.value for s in ProjectStatus])
            ).count()
            if invalid_project_status > 0:
                issues.append(f"Found {invalid_project_status} projects with invalid status")
            
            return issues
            
        finally:
            session.close()

# Initialize default database manager
db_manager = DatabaseManager()
Session = db_manager.Session