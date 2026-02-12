"""
Booking operations service for status updates and actions.
"""
from datetime import datetime
from typing import Optional
from sqlalchemy.orm import Session

from ...models import Booking, BookingStatus, AuditLog, AuditEventType


class BookingOperationsService:

    @staticmethod
    def check_in(db: Session, booking_id: int, user_id: Optional[int] = None) -> Optional[Booking]:
        """
        Mark a booking as checked in (ON_SITE).
        
        Args:
            db: Database session
            booking_id: ID of the booking to check in
            user_id: ID of the user performing the action (optional)
        
        Returns:
            Updated booking or None if not found
        """
        booking = db.query(Booking).filter(Booking.id == booking_id).first()
        if not booking:
            return None
        
        # Only allow check-in for BOOKED status
        if booking.status != BookingStatus.booked:
            raise ValueError(f"Cannot check in booking with status {booking.status.value}")
        
        booking.status = BookingStatus.on_site
        booking.checked_in_at = datetime.utcnow()
        
        # Create audit log
        audit_log = AuditLog(
            booking_id=booking_id,
            actor_user_id=user_id,
            event_type=AuditEventType.check_in,
            message="Vehicle checked in",
        )
        db.add(audit_log)
        
        db.commit()
        db.refresh(booking)
        return booking

    @staticmethod
    def collect(db: Session, booking_id: int, user_id: Optional[int] = None) -> Optional[Booking]:
        """
        Mark a booking as collected (COLLECTED).
        
        Args:
            db: Database session
            booking_id: ID of the booking to collect
            user_id: ID of the user performing the action (optional)
        
        Returns:
            Updated booking or None if not found
        """
        booking = db.query(Booking).filter(Booking.id == booking_id).first()
        if not booking:
            return None
        
        # Only allow collection for ON_SITE or OVERSTAY status
        if booking.status not in [BookingStatus.on_site, BookingStatus.overstay]:
            raise ValueError(f"Cannot collect booking with status {booking.status.value}")
        
        booking.status = BookingStatus.collected
        booking.collected_at = datetime.utcnow()
        
        # Create audit log
        audit_log = AuditLog(
            
            booking_id=booking_id,
            actor_user_id=user_id,
            event_type=AuditEventType.check_out,
            message="Vehicle collected by customer",
        )
        db.add(audit_log)
        
        db.commit()
        db.refresh(booking)
        return booking

    @staticmethod
    def update_status(
        db: Session,
        booking_id: int,
        status: BookingStatus,
        user_id: Optional[int] = None,
    ) -> Optional[Booking]:
        """
        Update booking status.
        
        Args:
            db: Database session
            booking_id: ID of the booking
            status: New status
            user_id: ID of the user performing the action (optional)
        
        Returns:
            Updated booking or None if not found
        """
        booking = db.query(Booking).filter(Booking.id == booking_id).first()
        if not booking:
            return None
        
        old_status = booking.status
        booking.status = status
        
        # Create audit log
        audit_log = AuditLog(
            booking_id=booking_id,
            actor_user_id=user_id,
            event_type=AuditEventType.status_change,
            message=f"Status changed from {old_status.value} to {status.value}",
        )
        db.add(audit_log)
        
        db.commit()
        db.refresh(booking)
        return booking

    @staticmethod
    def add_note(
        db: Session,
        booking_id: int,
        note: str,
        user_id: Optional[int] = None,
    ) -> Optional[Booking]:
        """
        Add a note to a booking.
        
        Args:
            db: Database session
            booking_id: ID of the booking
            note: Note text to add
            user_id: ID of the user adding the note (optional)
        
        Returns:
            Updated booking or None if not found
        """
        booking = db.query(Booking).filter(Booking.id == booking_id).first()
        if not booking:
            return None
        
        # Create audit log for note
        audit_log = AuditLog(
            booking_id=booking_id,
            actor_user_id=user_id,
            event_type=AuditEventType.note,
            message=f"Note added: {note}",
        )
        db.add(audit_log)
        
        db.commit()
        db.refresh(booking)
        return booking

