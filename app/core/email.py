"""
app/core/email.py

Async email dispatch via aiosmtplib.
Sends from the SMTP_FROM address configured in settings.
"""

import logging

import aiosmtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from app.core.config import settings

logger = logging.getLogger(__name__)


async def send_email(to: str, subject: str, body_html: str) -> None:
    """
    Send a single HTML email asynchronously.
    Raises on SMTP failure — callers should handle / log appropriately.
    """
    message = MIMEMultipart("alternative")
    message["Subject"] = subject
    message["From"]    = settings.SMTP_FROM
    message["To"]      = to
    message.attach(MIMEText(body_html, "html"))

    await aiosmtplib.send(
        message,
        hostname=settings.SMTP_HOST,
        port=settings.SMTP_PORT,
        username=settings.SMTP_USER,
        password=settings.SMTP_PASSWORD,
        start_tls=settings.SMTP_STARTTLS,
    )
    logger.info("Email sent to %s | subject: %s", to, subject)