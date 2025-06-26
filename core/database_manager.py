from sqlalchemy import create_engine, Column, Integer, String, DateTime, ForeignKey, Text, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from datetime import datetime
import os
import json

Base = declarative_base()

class Scan(Base):
    __tablename__ = 'scans'
    
    id = Column(Integer, primary_key=True)
    tool_name = Column(String(50), nullable=False)
    target = Column(String(255), nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)
    status = Column(String(20), nullable=False)
    results = Column(Text)
    ai_analysis = Column(Text)
    
    vulnerabilities = relationship("Vulnerability", back_populates="scan")
    
class Vulnerability(Base):
    __tablename__ = 'vulnerabilities'
    
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey('scans.id'))
    name = Column(String(255), nullable=False)
    severity = Column(String(20), nullable=False)
    description = Column(Text)
    recommendation = Column(Text)
    
    scan = relationship("Scan", back_populates="vulnerabilities")

class User(Base):
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    is_admin = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime)

class DatabaseManager:
    def __init__(self):
        db_path = os.path.join('data', 'darkpen.db')
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.engine = create_engine(f'sqlite:///{db_path}')
        self.Session = sessionmaker(bind=self.engine)
        # Initialize database tables automatically
        self.init_db()

    def init_db(self):
        """Initialize the database schema"""
        Base.metadata.create_all(self.engine)
        
    def add_scan(self, tool_name, target, status, results, ai_analysis=None):
        """Add a new scan to the database"""
        session = self.Session()
        try:
            scan = Scan(
                tool_name=tool_name,
                target=target,
                status=status,
                results=json.dumps(results) if isinstance(results, dict) else results,
                ai_analysis=ai_analysis
            )
            session.add(scan)
            session.commit()
            return scan.id
        finally:
            session.close()
            
    def add_vulnerability(self, scan_id, name, severity, description, recommendation):
        """Add a vulnerability finding to a scan"""
        session = self.Session()
        try:
            vuln = Vulnerability(
                scan_id=scan_id,
                name=name,
                severity=severity,
                description=description,
                recommendation=recommendation
            )
            session.add(vuln)
            session.commit()
            return vuln.id
        finally:
            session.close()
            
    def get_scan_history(self, limit=None):
        """Get scan history with optional limit"""
        session = self.Session()
        try:
            query = session.query(Scan).order_by(Scan.timestamp.desc())
            if limit:
                query = query.limit(limit)
            return query.all()
        finally:
            session.close()
            
    def get_scan_details(self, scan_id):
        """Get detailed information about a specific scan"""
        session = self.Session()
        try:
            scan = session.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                return {
                    'id': scan.id,
                    'tool_name': scan.tool_name,
                    'target': scan.target,
                    'timestamp': scan.timestamp,
                    'status': scan.status,
                    'results': json.loads(scan.results) if isinstance(scan.results, str) else scan.results,
                    'ai_analysis': scan.ai_analysis,
                    'vulnerabilities': [
                        {
                            'name': v.name,
                            'severity': v.severity,
                            'description': v.description,
                            'recommendation': v.recommendation
                        } for v in scan.vulnerabilities
                    ]
                }
                return None
        finally:
            session.close()
            
    def clear_history(self):
        """Clear all scan history"""
        session = self.Session()
        try:
            session.query(Scan).delete()
            session.query(Vulnerability).delete()
            session.commit()
        finally:
            session.close() 