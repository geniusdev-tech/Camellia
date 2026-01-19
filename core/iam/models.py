from sqlalchemy import Column, Integer, String, Boolean, ForeignKey, JSON
from sqlalchemy.orm import relationship, declarative_base

Base = declarative_base()

class Role(Base):
    __tablename__ = 'roles'
    
    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True, nullable=False) # e.g. "owner", "admin"
    permissions = Column(JSON, default=list) # e.g. ["vault:read", "vault:write"]
    description = Column(String)

    users = relationship("User", back_populates="role")

class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, nullable=False) # email
    password_hash = Column(String, nullable=False)
    
    # Crypto Fields
    wrapped_key = Column(String, nullable=True) # JSON string of wrapped master key
    
    # IAM Fields
    role_id = Column(Integer, ForeignKey('roles.id'))
    role = relationship("Role", back_populates="users")
    
    mfa_secret_enc = Column(String, nullable=True) # Encrypted TOTP secret
    is_active = Column(Boolean, default=True)
    last_login = Column(String, nullable=True) # ISO format
    
    def has_permission(self, permission: str) -> bool:
        if not self.role or not self.role.permissions:
            return False
            
        # Wildcard check (e.g. "vault:*")
        for perm in self.role.permissions:
            if perm == "*" or perm == permission:
                return True
            if perm.endswith("*") and permission.startswith(perm[:-1]):
                return True
        return False
