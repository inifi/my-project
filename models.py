from datetime import datetime
from app import db
from flask_login import UserMixin
from sqlalchemy import Column, Integer, String, Text, Boolean, DateTime, ForeignKey, Float, JSON
from sqlalchemy.orm import relationship

class User(UserMixin, db.Model):
    """User model - only the owner should be in this table"""
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True)
    username = Column(String(64), unique=True, nullable=False)
    email = Column(String(120), unique=True, nullable=False)
    password_hash = Column(String(256), nullable=False)
    is_owner = Column(Boolean, default=False)
    biometric_data = Column(Text, nullable=True)  # Encoded biometric authentication data
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)
    
    # Relationships
    knowledge_items = relationship("KnowledgeBase", back_populates="creator")
    security_logs = relationship("SecurityLog", back_populates="user")
    learning_sources = relationship("LearningSource", back_populates="added_by")
    
    def __repr__(self):
        return f"<User {self.username}>"

class Instance(db.Model):
    """Represents an instance of the AI system"""
    __tablename__ = 'instances'
    
    id = Column(Integer, primary_key=True)
    instance_id = Column(String(64), unique=True, nullable=False)  # UUID for this instance
    hostname = Column(String(128), nullable=False)  # Hostname where the instance is running
    instance_type = Column(String(32), nullable=False)  # primary, secondary, etc.
    platform = Column(String(64), nullable=True)  # google_colab, aws, local, etc.
    status = Column(String(32), default="active")  # active, inactive, error
    public_key = Column(Text, nullable=True)  # For secure communication
    endpoint_url = Column(String(256), nullable=True)  # URL to reach this instance
    created_at = Column(DateTime, default=datetime.utcnow)
    last_heartbeat = Column(DateTime, nullable=True)
    capabilities = Column(JSON, nullable=True)  # JSON of what this instance can do
    parent_instance_id = Column(String(64), nullable=True)  # ID of instance that created this one
    
    def __repr__(self):
        return f"<Instance {self.instance_id} ({self.instance_type})>"

class KnowledgeBase(db.Model):
    """Knowledge learned by the AI system"""
    __tablename__ = 'knowledge_base'
    
    id = Column(Integer, primary_key=True)
    content = Column(Text, nullable=False)  # The actual knowledge
    source_url = Column(String(512), nullable=True)  # Where this knowledge came from
    source_type = Column(String(32), nullable=False)  # web, api, owner_input, etc.
    confidence = Column(Float, default=0.5)  # How confident we are in this knowledge
    verified = Column(Boolean, default=False)  # Whether this has been verified by the owner
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    creator_id = Column(Integer, ForeignKey('users.id'), nullable=True)
    instance_id = Column(String(64), nullable=True)  # Which instance created this
    
    # Relationships
    creator = relationship("User", back_populates="knowledge_items")
    
    def __repr__(self):
        return f"<KnowledgeBase {self.id}: {self.content[:30]}...>"

class LearningSource(db.Model):
    """Sources to learn from periodically with prioritization"""
    __tablename__ = 'learning_sources'
    
    id = Column(Integer, primary_key=True)
    url = Column(String(512), nullable=False)  # URL to scrape or API to call
    source_type = Column(String(32), nullable=False)  # website, api, research, news, youtube, etc.
    schedule = Column(String(32), default="daily")  # How often to check this source: hourly, daily, weekly
    priority = Column(String(16), default="normal")  # Priority level: highest, high, normal, low
    last_accessed = Column(DateTime, nullable=True)  # When we last accessed this source
    access_count = Column(Integer, default=0)  # How many times we've accessed this source
    status = Column(String(32), default="active")  # active, paused, error, etc.
    created_at = Column(DateTime, default=datetime.utcnow)
    added_by_user_id = Column(Integer, ForeignKey('users.id'))
    source_metadata = Column(JSON, nullable=True)  # Additional data about this source (renamed from metadata)
    
    # Relationships
    added_by = relationship("User", back_populates="learning_sources")
    
    def __repr__(self):
        return f"<LearningSource {self.url} ({self.priority})>"

class SecurityLog(db.Model):
    """Security-related events and potential threats"""
    __tablename__ = 'security_logs'
    
    id = Column(Integer, primary_key=True)
    event_type = Column(String(32), nullable=False)  # login, access_attempt, error, etc.
    description = Column(Text, nullable=False)  # Description of the event
    severity = Column(String(16), default="info")  # info, warning, critical
    ip_address = Column(String(45), nullable=True)  # IP where the event originated
    user_agent = Column(String(256), nullable=True)  # User agent if applicable
    user_id = Column(Integer, ForeignKey('users.id'), nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    resolved = Column(Boolean, default=False)  # Whether this issue has been resolved
    
    # Relationships
    user = relationship("User", back_populates="security_logs")
    
    def __repr__(self):
        return f"<SecurityLog {self.event_type}: {self.description[:30]}...>"

class ModelVersion(db.Model):
    """Tracks different versions of the AI model"""
    __tablename__ = 'model_versions'
    
    id = Column(Integer, primary_key=True)
    version = Column(String(32), nullable=False)  # Semantic version number
    model_path = Column(String(512), nullable=True)  # Path to the model file if local
    model_type = Column(String(32), nullable=False)  # Type of model (local, openai, etc.)
    description = Column(Text, nullable=True)  # Description of this version
    performance_metrics = Column(JSON, nullable=True)  # JSON with performance metrics
    created_at = Column(DateTime, default=datetime.utcnow)
    created_by_instance_id = Column(String(64), nullable=True)
    is_active = Column(Boolean, default=False)  # Whether this is the active version
    
    def __repr__(self):
        return f"<ModelVersion {self.version}>"

class CodeImprovement(db.Model):
    """Tracks improvements made to the system's code"""
    __tablename__ = 'code_improvements'
    
    id = Column(Integer, primary_key=True)
    file_path = Column(String(512), nullable=False)  # Path to the modified file
    description = Column(Text, nullable=False)  # Description of the change
    diff = Column(Text, nullable=True)  # The actual code diff
    improvement_type = Column(String(32), nullable=False)  # bugfix, optimization, feature, etc.
    status = Column(String(32), default="proposed")  # proposed, approved, implemented, rejected
    created_at = Column(DateTime, default=datetime.utcnow)
    implemented_at = Column(DateTime, nullable=True)  # When this change was implemented
    instance_id = Column(String(64), nullable=True)  # Which instance proposed this change
    
    def __repr__(self):
        return f"<CodeImprovement {self.file_path}: {self.description[:30]}...>"
