import smtplib


def send_otp_email(email: str, otp: str):
    sender_email = "bluezonetesting7@gmail.com"
    sender_password = "fxbe kpok pnye xief"
    subject = "Your OTP Code"
    body = f"Your OTP code is: {otp}"

    message = f"Subject: {subject}\n\n{body}"

    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, email, message)
        server.quit()
    except Exception as e:
        print(f"Error sending email: {e}")