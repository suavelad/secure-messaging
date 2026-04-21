from sqlalchemy import create_engine, Column, String, Integer
from sqlalchemy.orm import declarative_base, sessionmaker

DATABASE_URL = "sqlite:///./untrusted_relay.db"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

class DBUser(Base):
    __tablename__ = "users"
    user_id = Column(String, primary_key=True, index=True)
    identity_key_pub = Column(String, nullable=False) # Stored as PEM string
    pre_key_pub = Column(String, nullable=False)      # Stored as PEM string

class DBMessage(Base):
    __tablename__ = "messages"
    id = Column(Integer, primary_key=True, index=True)
    recipient_id = Column(String, index=True, nullable=False)
    sender_id = Column(String, nullable=False)
    ciphertext = Column(String, nullable=False)       # Hex encoded
    nonce = Column(String, nullable=False)            # Hex encoded
    signature = Column(String, nullable=False)        # Hex encoded