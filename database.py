from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker


import os

# Try to read from Railway's environment variable
DATABASE_URL = os.getenv("DATABASE_URL")

# Optional: fallback for local development
if not DATABASE_URL:
    DATABASE_URL = "postgresql://postgres:diaz@localhost:5432/student_db"


engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
