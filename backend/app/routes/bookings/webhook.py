from fastapi import APIRouter, Header, HTTPException, Depends
from sqlalchemy.orm import Session

from app.db import get_db
from app.config import settings
from app.services.csv_importer import CSVImporter  
from app.services.bookings.booking_confirmation import send_booking_confirmation_email

router = APIRouter(prefix="/api/webhooks", tags=["Webhooks"])

def to_importer_row(payload: dict) -> dict:

    return {
        "Timestamp": payload.get("timestamp", ""),  
        "Full Names": payload.get("fullNames", ""),
        "Email": payload.get("email", ""),
        "WhatsApp number": payload.get("cellNumber", ""),  
        "Type of Flight": payload.get("typeOfFlight", ""),
        "Departure Date": payload.get("departureDate", ""),
        "Vehicle Drop off Time ": payload.get("vehicleDropOffTime", ""),   
        "Arrival Date": payload.get("arrivalDate", ""),
        "Vehicle Pick -up Time ": payload.get("vehiclePickUpTime", ""),    
        "Vehicle Make and Model": payload.get("vehicleMakeAndModel", ""),
        "Vehicle Color": payload.get("vehicleColor", ""),
        "Vehicle Registration": payload.get("vehicleRegistration", ""),
        "Payment Method": payload.get("paymentMethod", ""),
        "Special Instructions": payload.get("specialInstructions", ""),
        "cost": str(payload.get("cost", "0")),  
    }


@router.post("/bookings/google-sheets")
def receive_google_sheets_booking(
    payload: dict,
    x_webhook_secret: str | None = Header(default=None),
    db: Session = Depends(get_db),
):
    
    print("Received webhook payload:", payload)
    # 1) Verify secret
    # if x_webhook_secret != settings.WEBHOOK_SECRET:
    #     raise HTTPException(status_code=401, detail="Invalid webhook secret")

    # 2) Validate required webhook fields
    row_number = payload.get("rowNumber")
    if not row_number:
        raise HTTPException(status_code=400, detail="rowNumber is required")

    importer = CSVImporter(db)
    row_dict = to_importer_row(payload)

    success, error = importer.import_row(
        row=row_dict,
        row_number=int(row_number),
        source="google_sheet",   
    )

    if not success:
        db.rollback()
        if error and "already exists" in error.lower():
            return {"status": "ok", "message": "duplicate_ignored", "rowNumber": row_number}

        raise HTTPException(status_code=400, detail=error or "Import failed")
        
    # Brevo function here to send confirmation email to the customer
    try:
        response = send_booking_confirmation_email(
            email=row_dict["Email"], 
            name=row_dict["Full Names"],
            departure_date=row_dict["Departure Date"],
            drop_off_time=row_dict["Vehicle Drop off Time "],
            arrival_date=row_dict["Arrival Date"],
            pickup_time=row_dict["Vehicle Pick -up Time"],
            flight_type=row_dict["Type of Flight"],
            vehicle_reg=row_dict["Vehicle Registration"],
            vehicle_make_model=row_dict["Vehicle Make and Model"],
            vehicle_color=row_dict["Vehicle Color"],
            payment_method=row_dict["Payment Method"],
            cost=row_dict["cost"],
            special_instructions=row_dict["Special Instructions"],
        )
    except Exception as e:
        print(f"Error sending confirmation email: {str(e)}")
    # Save the booking to the database
    print(response)
    db.commit()
    return {"status": "ok", "message": "imported", "rowNumber": row_number}
