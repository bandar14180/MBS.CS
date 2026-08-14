"""E1 -- SMTP transport for the Email Alert System.

Synchronous stdlib `smtplib` (no new dependency). Kept deliberately small: build a plain-text
message and send it over STARTTLS. Credentials come only from Settings (SMTP_PASSWORD supports
the *_FILE convention) and are NEVER logged. Callers run this off the request/scan path -- it is
invoked from the async provider via a thread and from the Celery delivery task.
"""
import smtplib
from email.message import EmailMessage


class EmailDeliveryError(Exception):
    """A transient or permanent SMTP failure. The Celery task decides retry vs. give-up."""


def smtp_send(settings, recipients: list[str], subject: str, body: str) -> None:
    """Send one plain-text email to `recipients`. Raises EmailDeliveryError on any SMTP/socket
    failure so the caller can retry. Never logs the password or message body."""
    if not recipients:
        return
    msg = EmailMessage()
    msg["From"] = settings.email_from_address
    msg["To"] = ", ".join(recipients)
    msg["Subject"] = subject
    msg.set_content(body or "")

    try:
        with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=settings.smtp_timeout_seconds) as smtp:
            if settings.smtp_use_tls:
                smtp.starttls()
            if settings.smtp_username:
                smtp.login(settings.smtp_username, settings.smtp_password)
            smtp.send_message(msg)
    except (smtplib.SMTPException, OSError) as exc:
        # Message text intentionally omits the SMTP body/recipients/credentials.
        raise EmailDeliveryError(f"SMTP delivery failed: {type(exc).__name__}") from exc
