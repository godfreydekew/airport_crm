import requests
from typing import Optional

from app.config import settings

GOOGLE_REVIEW_URL = "https://g.page/r/Cf9MOqvx-6_1EBM/review"
WHATSAPP_URL = "https://wa.me/27735440774"
PHONE_NUMBER = "+27 73 544 0774"
COMPANY_NAME = "Or Tambo Premium Parking"
SENDER_EMAIL = "noreply@ortambopremiumparking.co.za"


def _build_booking_confirmation_html(
    name: str,
    *,
    departure_date: Optional[str] = None,
    drop_off_time: Optional[str] = None,
    arrival_date: Optional[str] = None,
    pickup_time: Optional[str] = None,
    flight_type: Optional[str] = None,
    vehicle_reg: Optional[str] = None,
    vehicle_make_model: Optional[str] = None,
    vehicle_color: Optional[str] = None,
    payment_method: Optional[str] = None,
    cost: Optional[str] = None,
    special_instructions: Optional[str] = None,
) -> str:
    """Build professional HTML email body. All booking fields are optional."""
    has_details = any(
        [
            departure_date,
            drop_off_time,
            arrival_date,
            pickup_time,
            flight_type,
            vehicle_reg,
            vehicle_make_model,
            vehicle_color,
            payment_method,
            cost,
        ]
    )

    details_rows = []
    if departure_date or drop_off_time:
        details_rows.append(
            f"<tr><td style='padding:8px 12px;border:1px solid #e5e7eb;'>Drop-off</td>"
            f"<td style='padding:8px 12px;border:1px solid #e5e7eb;'>{departure_date or '—'} at {drop_off_time or '—'}</td></tr>"
        )
    if arrival_date or pickup_time:
        details_rows.append(
            f"<tr><td style='padding:8px 12px;border:1px solid #e5e7eb;'>Pick-up</td>"
            f"<td style='padding:8px 12px;border:1px solid #e5e7eb;'>{arrival_date or '—'} at {pickup_time or '—'}</td></tr>"
        )
    if flight_type:
        details_rows.append(
            f"<tr><td style='padding:8px 12px;border:1px solid #e5e7eb;'>Flight type</td>"
            f"<td style='padding:8px 12px;border:1px solid #e5e7eb;'>{flight_type}</td></tr>"
        )
    if vehicle_reg or vehicle_make_model or vehicle_color:
        vehicle_desc = " / ".join(
            x for x in [vehicle_make_model, vehicle_color, vehicle_reg] if x
        )
        details_rows.append(
            f"<tr><td style='padding:8px 12px;border:1px solid #e5e7eb;'>Vehicle</td>"
            f"<td style='padding:8px 12px;border:1px solid #e5e7eb;'>{vehicle_desc or '—'}</td></tr>"
        )
    if payment_method:
        details_rows.append(
            f"<tr><td style='padding:8px 12px;border:1px solid #e5e7eb;'>Payment</td>"
            f"<td style='padding:8px 12px;border:1px solid #e5e7eb;'>{payment_method}</td></tr>"
        )
    if cost:
        details_rows.append(
            f"<tr><td style='padding:8px 12px;border:1px solid #e5e7eb;'>Amount</td>"
            f"<td style='padding:8px 12px;border:1px solid #e5e7eb;'>R {cost}</td></tr>"
        )

    details_table = ""
    if has_details and details_rows:
        details_table = f"""
        <table style='width:100%;max-width:480px;border-collapse:collapse;margin:20px 0;font-size:15px;'>
            <thead>
                <tr style='background:#166534;color:#fff;'>
                    <th style='padding:10px 12px;text-align:left;font-weight:600;'>Booking details</th>
                    <th style='padding:10px 12px;text-align:left;font-weight:600;'></th>
                </tr>
            </thead>
            <tbody>
                {"".join(details_rows)}
            </tbody>
        </table>
        """
    if special_instructions and special_instructions.strip():
        details_table += f"""
        <p style='margin:0 0 16px;color:#475569;font-size:14px;'>
            <strong>Your notes:</strong> {special_instructions.strip()}
        </p>
        """

    return f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Booking confirmation</title>
</head>
<body style="margin:0;padding:0;font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;background:#f1f5f9;color:#1e293b;">
    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background:#f1f5f9;padding:24px 16px;">
        <tr>
            <td align="center">
                <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="max-width:560px;background:#ffffff;border-radius:12px;box-shadow:0 4px 6px rgba(0,0,0,0.06);overflow:hidden;">
                    <tr>
                        <td style="background:#166534;color:#ffffff;padding:24px 24px 20px;text-align:center;">
                            <h1 style="margin:0;font-size:22px;font-weight:700;letter-spacing:-0.02em;">{COMPANY_NAME}</h1>
                            <p style="margin:8px 0 0;font-size:14px;color:#94a3b8;">Booking received</p>
                        </td>
                    </tr>
                    <tr>
                        <td style="padding:28px 24px;">
                            <p style="margin:0 0 16px;font-size:17px;line-height:1.5;">Dear {name},</p>
                            <p style="margin:0 0 16px;font-size:16px;line-height:1.6;color:#334155;">
                                Thank you for your booking. We have <strong>received your request</strong> and confirmed it in our system.
                            </p>
                            <p style="margin:0 0 20px;font-size:15px;line-height:1.6;color:#475569;">
                                We will be in touch shortly via WhatsApp. If you have any questions before then, you can reach us at
                                <a href="tel:{PHONE_NUMBER.replace(' ', '')}" style="color:#22c55e;text-decoration:none;">{PHONE_NUMBER}</a>
                                or on
                                <a href="{WHATSAPP_URL}" style="color:#22c55e;text-decoration:none;">WhatsApp</a>.
                            </p>
                            {details_table}
                            <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="margin-top:24px;padding-top:20px;border-top:1px solid #e2e8f0;">
                                <tr>
                                    <td>
                                        <p style="margin:0 0 8px;font-size:14px;color:#64748b;">We are ready to take care of your vehicle.</p>
                                        <p style="margin:0;font-size:13px;color:#94a3b8;">
                                            <a href="{GOOGLE_REVIEW_URL}" style="color:#22c55e;text-decoration:none;">Leave a review on Google</a> to help us improve.
                                        </p>
                                    </td>
                                </tr>
                            </table>
                        </td>
                    </tr>
                    <tr>
                        <td style="padding:16px 24px;background:#f8fafc;font-size:12px;color:#64748b;text-align:center;">
                            &copy; {COMPANY_NAME}. All rights reserved.
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>
"""


def send_booking_confirmation_email(
    email: str,
    name: str,
    *,
    departure_date: Optional[str] = None,
    drop_off_time: Optional[str] = None,
    arrival_date: Optional[str] = None,
    pickup_time: Optional[str] = None,
    flight_type: Optional[str] = None,
    vehicle_reg: Optional[str] = None,
    vehicle_make_model: Optional[str] = None,
    vehicle_color: Optional[str] = None,
    payment_method: Optional[str] = None,
    cost: Optional[str] = None,
    special_instructions: Optional[str] = None,
):
    html_content = _build_booking_confirmation_html(
        name,
        departure_date=departure_date,
        drop_off_time=drop_off_time,
        arrival_date=arrival_date,
        pickup_time=pickup_time,
        flight_type=flight_type,
        vehicle_reg=vehicle_reg,
        vehicle_make_model=vehicle_make_model,
        vehicle_color=vehicle_color,
        payment_method=payment_method,
        cost=cost,
        special_instructions=special_instructions,
    )
    
    response = requests.post(
        "https://api.brevo.com/v3/smtp/email",
        headers={"api-key": settings.BREVO_API_KEY},
        json={
            "subject": "Booking received – Or Tambo Premium Parking",
            "htmlContent": html_content,
            "sender": {
                "email": SENDER_EMAIL,
                "name": COMPANY_NAME,
            },
            "to": [{"email": email, "name": name}],
            "headers": {"X-Mailer": "Airport CRM"},
        },
    )
    return response

# if __name__ == "__main__":
#   response = send_booking_confirmation_email(
#       "dekewgodfrey@gmail.com",
#       "Jane Smith",
#       departure_date="2025-02-15",
#     #   drop_off_time="06:00",
#       arrival_date="2025-02-20",
#       pickup_time="14:00",
#       flight_type="International",
#       vehicle_reg="ABC 123 GP",
#       vehicle_make_model="Toyota Corolla",
#       vehicle_color="Silver",
#       payment_method="Card",
#       cost="450.00",
#       special_instructions="Please park in shade.",
#   )
#   print(response)