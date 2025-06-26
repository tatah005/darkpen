from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, ForeignKey, JSON, Table, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from datetime import datetime

Base = declarative_base()

class Scan(Base):
    __tablename__ = 'scans'
    
    id = Column(Integer, primary_key=True)
    target = Column(String, nullable=False)
    scan_type = Column(String, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)
    status = Column(String, default='pending')
    results = Column(JSON)
    risk_level = Column(String)
    risk_score = Column(Float)
    summary = Column(String)
    
    # Relationships
    vulnerabilities = relationship('Vulnerability', back_populates='scan')
    services = relationship('Service', back_populates='scan')
    ai_analysis = relationship('AIAnalysis', back_populates='scan', uselist=False)
    compliance_checks = relationship('ComplianceCheck', back_populates='scan')
    integration_results = relationship('IntegrationResult', back_populates='scan')

class Vulnerability(Base):
    __tablename__ = 'vulnerabilities'
    
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey('scans.id'))
    description = Column(String)
    severity = Column(String)
    cve_id = Column(String)
    impact = Column(String)
    exploit_likelihood = Column(String)
    mitigation = Column(String)
    
    # Relationships
    scan = relationship('Scan', back_populates='vulnerabilities')

class Service(Base):
    __tablename__ = 'services'
    
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey('scans.id'))
    port = Column(Integer)
    name = Column(String)
    version = Column(String)
    state = Column(String)
    risk_level = Column(String)
    
    # Relationships
    scan = relationship('Scan', back_populates='services')
    attack_vectors = relationship('AttackVector', back_populates='service')

class AIAnalysis(Base):
    __tablename__ = 'ai_analysis'
    
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey('scans.id'), unique=True)
    risk_score = Column(Float)
    risk_level = Column(String)
    analysis_data = Column(JSON)
    recommendations = Column(JSON)
    timestamp = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    scan = relationship('Scan', back_populates='ai_analysis')

class AttackVector(Base):
    __tablename__ = 'attack_vectors'
    
    id = Column(Integer, primary_key=True)
    service_id = Column(Integer, ForeignKey('services.id'))
    attack_type = Column(String)
    likelihood = Column(String)
    impact = Column(String)
    mitigation = Column(String)
    
    # Relationships
    service = relationship('Service', back_populates='attack_vectors')

class ComplianceCheck(Base):
    __tablename__ = 'compliance_checks'
    
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey('scans.id'))
    framework = Column(String)  # e.g., 'PCI DSS', 'HIPAA', 'GDPR'
    requirement = Column(String)
    status = Column(String)  # 'pass', 'fail', 'warning'
    details = Column(String)
    
    # Relationships
    scan = relationship('Scan', back_populates='compliance_checks')

class ToolIntegration(Base):
    __tablename__ = 'tool_integrations'
    
    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True)  # e.g., 'burp', 'wireshark', 'metasploit'
    enabled = Column(Boolean, default=True)
    config = Column(JSON)  # Store tool-specific configuration
    last_used = Column(DateTime)
    status = Column(String)

class IntegrationResult(Base):
    __tablename__ = 'integration_results'
    
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey('scans.id'))
    tool_id = Column(Integer, ForeignKey('tool_integrations.id'))
    timestamp = Column(DateTime, default=datetime.utcnow)
    results = Column(JSON)
    status = Column(String)
    
    # Relationships
    scan = relationship('Scan')
    tool = relationship('ToolIntegration') 