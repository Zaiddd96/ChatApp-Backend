from datetime import datetime, timezone
from typing import List
from database import Base
from sqlalchemy import Column, Integer, String, DateTime, Boolean, ForeignKey, Text
from pydantic import BaseModel, EmailStr, constr

# Databases
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    email = Column(String, unique=True, nullable=False)
    password = Column(String, nullable=False)
    role = Column(String, nullable=False)
    otp = Column(String, nullable=True)
    otp_expiry = Column(DateTime, nullable=True)
    token = Column(String, nullable=True)
    last_seen = Column(DateTime, nullable=True)

class Room(Base):
    __tablename__ = "rooms"  # Ensure consistency in ForeignKey references
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, nullable=False)
    created_by = Column(Integer, ForeignKey("users.id"))  # User who created the room
    created_at = Column(DateTime, default=datetime.utcnow)
    is_private = Column(Boolean, default=False)  # True for 1-on-1 chats, False for groups


class RoomMember(Base):
    __tablename__ = "room_members"
    id = Column(Integer, primary_key=True, index=True)
    room_id = Column(Integer, ForeignKey("rooms.id"))  # Links to a room
    user_id = Column(Integer, ForeignKey("users.id"))  # Links to a user
    joined_at = Column(DateTime, default=datetime.utcnow)


class Message(Base):
    __tablename__ = "messages"
    id = Column(Integer, primary_key=True, index=True)
    room_id = Column(Integer, ForeignKey("rooms.id"))  # Messages belong to a room
    user_id = Column(Integer, ForeignKey("users.id"))  # Messages are sent by users
    content = Column(String, nullable=False)
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))



# Request Models
class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class RegisterRequest(BaseModel):
    name: constr(min_length=4)
    email: EmailStr
    password: constr(min_length=6)
    role: constr(min_length=5)


class SendOtpRequest(BaseModel):
    email: EmailStr


class CreateRoomRequest(BaseModel):
    room_name: str
    user_ids: List[int]

class OtpVerifyRequest(BaseModel):
    email: EmailStr
    otp: str

class ResetPasswordRequest(BaseModel):
    email: EmailStr
    new_password: str



