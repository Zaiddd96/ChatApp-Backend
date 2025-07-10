import hashlib
import json
from typing import Dict
from fastapi import FastAPI, Depends, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
import bcrypt
import jwt
from sqlalchemy.orm import Session

from database import engine, Base, get_db
from models import User, LoginRequest, RegisterRequest, SendOtpRequest, CreateRoomRequest, Room, RoomMember, Message, \
    OtpVerifyRequest, ResetPasswordRequest
from utils import send_otp_email
from datetime import datetime, timedelta, timezone
import random

AUTH_KEY = "a4fdef618a20e53d3e344ba4d8b2edce13fee6057099d8c9e08a1053bc1064e2"

app = FastAPI()

Base.metadata.create_all(bind=engine)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Or specific domain
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.post("/register")
def register_user(request: RegisterRequest, db: Session = Depends(get_db)):
    allowed_roles = {"admin", "student"}
    if request.role not in allowed_roles:
        raise HTTPException(status_code=400, detail="Invalid role! Role must be 'admin' or 'student'.")

    # Check for duplicate email
    existing_user = db.query(User).filter(User.email == request.email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already exists!")

    hashed_password = bcrypt.hashpw(request.password.encode('utf-8'), bcrypt.gensalt())
    user = User(name=request.name, email=request.email, password=hashed_password.decode(), role=request.role)
    db.add(user)
    db.commit()
    return {"message": "User registered"}


@app.post("/login")
def login_user(request: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == request.email).first()

    if not user:
        print("User not found")
        return {"error": "Invalid credentials"}

    # Ensure entered password is stripped of extra spaces
    entered_password = request.password.strip().encode('utf-8')
    stored_password = user.password.encode('utf-8')

    if bcrypt.checkpw(entered_password, stored_password):
        print("Password match successful")

        # Remove previous otp and expiry-time
        user.otp = None
        user.otp_expiry = None
        db.commit()

        # Call `send_otp` directly after login
        otp_response = send_otp(SendOtpRequest(email=user.email), db)

        return {
            "message": "Login successful. OTP has been sent to your email.",
            "email": user.email,
            "otp_message": otp_response["message"],
        }
    else:
        print("Password does not match")
        return {"error": "Invalid credentials"}


@app.get("/users")
def get_students(db: Session = Depends(get_db)):
    users = db.query(User).filter(User.role.in_(["student", "admin"])).all()
    return [{"id": user.id, "name": user.name} for user in users]


@app.post("/send-otp")
def send_otp(request: SendOtpRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == request.email).first()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    otp = random.randint(1000, 9999)
    hashed_otp = hashlib.sha256(str(otp).encode()).hexdigest()
    user.otp = hashed_otp
    user.otp_expiry = datetime.utcnow() + timedelta(minutes=1)
    db.commit()

    send_otp_email(request.email, str(otp))

    return {"message": "OTP sent successfully"}


@app.post("/verify-otp")
def verify_otp(request: dict, db: Session = Depends(get_db)):
    email = request.get("email")
    entered_otp = request.get("otp")

    if not email or not entered_otp:
        return {"error": "Email and OTP are required"}

    user = db.query(User).filter(User.email == email).first()

    if not user:
        return {"error": "User not found"}

    # Check if OTP is expired
    if user.otp_expiry and datetime.utcnow() > user.otp_expiry:
        return {"error": "OTP has expired"}

    # Hash entered OTP for comparison (if stored OTP is hashed)
    hashed_entered_otp = hashlib.sha256(entered_otp.encode()).hexdigest()

    if user.otp != hashed_entered_otp:
        return {"error": "Invalid OTP"}

    # Generate JWT Token after successful verification
    token = jwt.encode({"email": user.email, "role": user.role}, AUTH_KEY)

    # Clear OTP after successful verification
    user.otp = None
    user.otp_expiry = None
    user.token = token
    db.commit()

    return {"access_token": token, "role": user.role, "message": "OTP verified successfully",
            "current_user_id": user.id, "username": user.name}


# Chat app functionalities
@app.post("/create-room")
def create_room(request: CreateRoomRequest, db: Session = Depends(get_db)):
    try:
        # Create the room
        new_room = Room(
            name=request.room_name,
            created_by=request.user_ids[0],  # First user is the creator
            created_at=datetime.utcnow(),
            is_private=True if len(request.user_ids) == 2 else False
        )

        db.add(new_room)
        db.commit()
        db.refresh(new_room)

        # Validate room existence before adding members
        if not new_room.id:
            db.rollback()
            raise HTTPException(status_code=500, detail="Failed to create room")

        # Add users to the room
        room_members = [
            RoomMember(room_id=new_room.id, user_id=user_id, joined_at=datetime.utcnow())
            for user_id in request.user_ids
        ]
        db.add_all(room_members)
        db.commit()

        return {"room_id": new_room.id, "message": "Room created successfully"}

    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")


@app.post("/add-user")
def add_user_to_room(request: dict, db: Session = Depends(get_db)):
    room_id = request.get("room_id")
    user_id = request.get("user_id")

    # Check if room exists
    room = db.query(Room).filter(Room.id == room_id).first()
    if not room:
        raise HTTPException(status_code=404, detail="Room not found")

    # Check if user already exists in the room
    existing_member = db.query(RoomMember).filter(
        RoomMember.room_id == room_id,
        RoomMember.user_id == user_id
    ).first()

    if existing_member:
        raise HTTPException(status_code=400, detail="User already in room")

    # Add the user to the room
    db.add(RoomMember(room_id=room_id, user_id=user_id))
    db.commit()

    return {"message": "User added to room successfully"}


@app.get("/rooms")
def get_user_rooms(user_id: int, db: Session = Depends(get_db)):
    # Get rooms where the user is a member
    rooms = db.query(Room).join(RoomMember).filter(
        RoomMember.user_id == user_id
    ).all()

    if not rooms:
        return {"message": "No rooms found for this user"}

    # Format the response
    room_list = [{"room_id": room.id, "room_name": room.name} for room in rooms]

    return room_list


@app.post("/send-message")
def send_message(request: dict, db: Session = Depends(get_db)):
    room_id = request.get("room_id")
    user_id = request.get("user_id")
    content = request.get("content")

    # Validate room existence
    room = db.query(Room).filter(Room.id == room_id).first()
    if not room:
        raise HTTPException(status_code=404, detail="Room not found")

    # Validate if user is in the room
    is_member = db.query(RoomMember).filter(
        RoomMember.room_id == room_id,
        RoomMember.user_id == user_id
    ).first()

    if not is_member:
        raise HTTPException(status_code=403, detail="User is not a member of this room")

    # Save the message
    new_message = Message(
        room_id=room_id,
        user_id=user_id,
        content=content,
        timestamp=datetime.now(timezone.utc)
    )
    db.add(new_message)
    db.commit()

    return {"message": "Message sent successfully"}


@app.get("/get-messages/{room_id}")
def get_room_messages(room_id: int, db: Session = Depends(get_db)):
    # Check if the room exists
    room = db.query(Room).filter(Room.id == room_id).first()
    if not room:
        raise HTTPException(status_code=404, detail="Room not found")

    # Retrieve messages for the room
    messages = db.query(Message).filter(Message.room_id == room_id).order_by(Message.timestamp).all()

    # Format the response
    message_list = [
        {
            "user_id": message.user_id,
            "content": message.content,
            "timestamp": message.timestamp.isoformat()
        }
        for message in messages
    ]

    return message_list if message_list else {"message": "No messages found for this room"}


# Dictionary to track active WebSocket connections
active_connections: Dict[int, list] = {}


@app.websocket("/ws/{room_id}/{user_id}")
async def websocket_endpoint(websocket: WebSocket, room_id: int, user_id: int, db: Session = Depends(get_db)):
    room = db.query(Room).filter(Room.id == room_id).first()
    user = db.query(User).filter(User.id == user_id).first()

    if not room or not user:
        await websocket.close(code=1008)
        return

    await websocket.accept()
    await websocket.send_text(json.dumps({"status": "connected"}))

    # Add to active connections
    if room_id not in active_connections:
        active_connections[room_id] = []
    active_connections[room_id].append(websocket)

    try:
        while True:
            data = await websocket.receive_text()
            print(f"📨 Received: {data}")
            msg_data = json.loads(data)

            # ✅ Save message to DB first (ALWAYS)
            new_msg = Message(
                room_id=msg_data["room_id"],
                user_id=msg_data["user_id"],
                content=msg_data["content"],
                timestamp=datetime.utcnow()
            )
            db.add(new_msg)
            db.commit()

            # ✅ Broadcast only if there are connections
            if room_id in active_connections:
                for conn in active_connections[room_id]:
                    try:
                        await conn.send_text(json.dumps({
                            "room_id": msg_data["room_id"],
                            "user_id": msg_data["user_id"],
                            "content": msg_data["content"],
                            "timestamp": new_msg.timestamp.isoformat()
                        }))
                    except Exception as e:
                        print(f"Broadcast error: {e}")
    except WebSocketDisconnect:
        print(f"⚠️ Disconnected: user {user_id}")
    finally:
        # ✅ Remove from active connections
        if websocket in active_connections[room_id]:
            active_connections[room_id].remove(websocket)
        if not active_connections[room_id]:  # Remove empty room entries
            del active_connections[room_id]



# Update/Reset password functionalities

@app.post("/send-reset-otp")
async def send_reset_otp(request: SendOtpRequest, db: Session = Depends(get_db)):
    email = request.email

    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=404, detail="Email not found")

    otp = random.randint(1000, 9999)
    hashed_otp = hashlib.sha256(str(otp).encode()).hexdigest()
    user.otp = hashed_otp
    user.otp_expiry = datetime.utcnow() + timedelta(minutes=1)
    db.commit()

    send_otp_email(user.email, str(otp))

    return {"message": "OTP sent for password reset"}


@app.post("/verify-reset-otp")
async def verify_reset_otp(request: OtpVerifyRequest, db: Session = Depends(get_db)):

    email = request.email
    otp = request.otp
    hashed_otp = hashlib.sha256(str(otp).encode()).hexdigest()

    user = db.query(User).filter(User.email == email, User.otp == hashed_otp).first()
    if not user:
        raise HTTPException(status_code=400, detail="Invalid OTP")

    return {"message": "OTP Verified"}


@app.post("/reset-password")
async def reset_password(request: ResetPasswordRequest, db: Session = Depends(get_db)):
    email = request.email
    new_password = request.new_password

    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    new_hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    user.password = new_hashed_password
    user.otp = None
    db.commit()

    return {"message": "Password successfully updated"}
