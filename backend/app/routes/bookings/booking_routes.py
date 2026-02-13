from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query, Body
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.db import get_db
from ...shemas import BookingUpdate, BookingStatus, FlightType, PaymentMethod
from ...models import Booking as BookingModel, BookingStatus as BookingStatusEnum, FlightType as FlightTypeEnum, PaymentMethod as PaymentMethodEnum
from ...services.bookings.booking_service import BookingService
from ...services.bookings.booking_operations import BookingOperationsService
from ...services.auth.dependencies import get_current_user

class NoteRequest(BaseModel):
    """Request model for adding a note."""
    note: str

router = APIRouter(
    prefix="/api/bookings", 
    tags=["Bookings"],
    dependencies=[Depends(get_current_user)]
    )


def booking_to_out(booking: BookingModel) -> dict:
    """Convert booking model to output format matching frontend expectations."""
    # Parse vehicle make/model (stored as combined string)
    make_model_parts = booking.vehicle.make_model.split(" ", 1)
    vehicle_make = make_model_parts[0] if make_model_parts else ""
    vehicle_model = make_model_parts[1] if len(make_model_parts) > 1 else ""
    
    # Format dates and times
    departure_date = booking.dropoff_at.date()
    departure_time = booking.dropoff_at.strftime("%H:%M")
    arrival_date = booking.pickup_at.date()
    arrival_time = booking.pickup_at.strftime("%H:%M")
    
    # Get audit logs as activity
    activity = []
    for log in booking.audit_logs:
        # Map backend event types to frontend activity types
        event_type_map = {
            "CREATED": "created",
            "CHECK_IN": "check_in",
            "CHECK_OUT": "collected",
            "NOTE": "note_added",
            "STATUS_CHANGE": "status_changed",
            "SYNC": "created",
        }
        activity_type = event_type_map.get(log.event_type.value, "created")
        
        activity.append({
            "id": str(log.id),
            "type": activity_type,
            "description": log.message or "",
            "timestamp": log.created_at.isoformat(),
            "user": log.actor.full_name if log.actor else "System",
        })
    
    # Extract notes from audit logs
    notes = [
        log.message.replace("Note added: ", "")
        for log in booking.audit_logs
        if log.event_type.value == "NOTE" and log.message
    ]
    
    return {
        "id": str(booking.id),
        "customerId": str(booking.customer_id),
        "timestamp": booking.created_at.isoformat(),
        "fullName": booking.customer.full_name,
        "email": booking.customer.email or "",
        "whatsapp": booking.customer.whatsapp_number or "",
        "flightType": booking.flight_type.value.upper(),
        "departureDate": departure_date.isoformat(),
        "departureTime": departure_time,
        "arrivalDate": arrival_date.isoformat(),
        "arrivalTime": arrival_time,
        "vehicleMake": vehicle_make,
        "vehicleModel": vehicle_model,
        "vehicleColor": booking.vehicle.color or "",
        "registration": booking.vehicle.registration,
        "paymentMethod": booking.payment_method.value.upper(),
        "specialInstructions": booking.special_instructions or "",
        "cost": float(booking.cost),
        "status": booking.status.value,
        "checkInTime": booking.checked_in_at.isoformat() if booking.checked_in_at else None,
        "collectedTime": booking.collected_at.isoformat() if booking.collected_at else None,
        "activity": activity,
        "notes": notes,
    }


@router.get("", response_model=List[dict])
def get_bookings(
    status: Optional[str] = Query(None, description="Filter by status"),
    payment_method: Optional[str] = Query(None, description="Filter by payment method"),
    flight_type: Optional[str] = Query(None, description="Filter by flight type"),
    search: Optional[str] = Query(None, description="Search in name, email, phone, or registration"),
    db: Session = Depends(get_db),
):
    """
    Get all bookings with optional filters.
    
    Returns all bookings matching the filters (no pagination limit).
    Frontend handles pagination client-side.
    """
    # Convert string filters to enums
    status_enum = None
    if status and status != "all":
        try:
            status_enum = BookingStatusEnum[status.lower()]
        except KeyError:
            raise HTTPException(status_code=400, detail=f"Invalid status: {status}")
    
    payment_enum = None
    if payment_method and payment_method != "all":
        try:
            payment_enum = PaymentMethodEnum[payment_method.lower()]
        except KeyError:
            raise HTTPException(status_code=400, detail=f"Invalid payment method: {payment_method}")
    
    flight_enum = None
    if flight_type and flight_type != "all":
        try:
            flight_enum = FlightTypeEnum[flight_type.lower()]
        except KeyError:
            raise HTTPException(status_code=400, detail=f"Invalid flight type: {flight_type}")
    
    # Get all bookings without pagination limit
    bookings = BookingService.get_all(
        db=db,
        status=status_enum,
        payment_method=payment_enum,
        flight_type=flight_enum,
        search=search,
        skip=0,
        limit=10000, 
    )
    
    return [booking_to_out(booking) for booking in bookings]


@router.get("/{booking_id}", response_model=dict)
def get_booking(booking_id: int, db: Session = Depends(get_db)):
    """Get a single booking by ID."""
    booking = BookingService.get_by_id(db, booking_id)
    if not booking:
        raise HTTPException(status_code=404, detail="Booking not found")
    return booking_to_out(booking)


@router.patch("/{booking_id}/check-in", response_model=dict)
def check_in_booking(booking_id: int, db: Session = Depends(get_db)):
    """Mark a booking as checked in (ON_SITE)."""
    try:
        booking = BookingOperationsService.check_in(db, booking_id)
        if not booking:
            raise HTTPException(status_code=404, detail="Booking not found")
        return booking_to_out(booking)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.patch("/{booking_id}/collect", response_model=dict)
def collect_booking(booking_id: int, db: Session = Depends(get_db)):
    """Mark a booking as collected (COLLECTED)."""
    try:
        booking = BookingOperationsService.collect(db, booking_id)
        if not booking:
            raise HTTPException(status_code=404, detail="Booking not found")
        return booking_to_out(booking)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.patch("/{booking_id}/status", response_model=dict)
def update_booking_status(
    booking_id: int,
    status: str = Query(..., description="New status"),
    db: Session = Depends(get_db),
):
    """Update booking status."""
    try:
        status_enum = BookingStatusEnum[status.lower()]
    except KeyError:
        raise HTTPException(status_code=400, detail=f"Invalid status: {status}")
    
    booking = BookingOperationsService.update_status(db, booking_id, status_enum)
    if not booking:
        raise HTTPException(status_code=404, detail="Booking not found")
    return booking_to_out(booking)


@router.post("/{booking_id}/notes", response_model=dict)
def add_booking_note(
    booking_id: int,
    request: NoteRequest,
    db: Session = Depends(get_db),
):
    """Add a note to a booking."""
    if not request.note or not request.note.strip():
        raise HTTPException(status_code=400, detail="Note cannot be empty")
    
    booking = BookingOperationsService.add_note(db, booking_id, request.note.strip())
    if not booking:
        raise HTTPException(status_code=404, detail="Booking not found")
    return booking_to_out(booking)


@router.post("/{booking_id}/update", response_model=dict)
def update_booking(
    booking_id: int,
    booking: BookingUpdate,
    db: Session = Depends(get_db),
) -> Optional[dict]:
    """Update a booking."""
    try:
        updated_booking = BookingOperationsService.update_booking(db, booking_id, booking) 
        if not updated_booking:
            raise HTTPException(status_code=404, detail="Booking not found")
        return {"message": "Booking updated successfully"}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
   

    