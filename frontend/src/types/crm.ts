export type BookingStatus = 
  | 'BOOKED' 
  | 'ON_SITE' 
  | 'COLLECTED' 
  | 'OVERSTAY' 
  | 'CANCELLED' 
  | 'NO_SHOW';

export type FlightType = 'DOMESTIC' | 'INTERNATIONAL';

export type PaymentMethod = 'CASH' | 'EFT' | 'CARD' | 'PENDING';

export interface ActivityEvent {
  id: string;
  type: 'created' | 'check_in' | 'collected' | 'note_added' | 'status_changed' | 'overstay_marked';
  description: string;
  timestamp: Date;
  user?: string;
}

export interface Booking {
  id: string;
  customerId: string;
  timestamp: Date;
  fullName: string;
  email: string;
  whatsapp: string;
  flightType: FlightType;
  departureDate: Date;
  departureTime: string;
  arrivalDate: Date;
  arrivalTime: string;
  vehicleMake: string;
  vehicleModel: string;
  vehicleColor: string;
  registration: string;
  paymentMethod: PaymentMethod;
  specialInstructions: string;
  cost: number;
  status: BookingStatus;
  checkInTime?: Date;
  collectedTime?: Date;
  activity: ActivityEvent[];
  notes: string[];
}

export interface Customer {
  id: string;
  fullName: string;
  email: string;
  whatsapp: string;
  totalSpend: number;
  bookingCount: number;
  lastVisit?: Date;
  createdAt: Date;
  isRepeat: boolean;
}

export interface DashboardStats {
  carsOnSite: number;
  arrivalsToday: number;
  pickupsToday: number;
  overstays: number;
  revenue7d: number;
}

export interface RevenueDataPoint {
  date: string;
  revenue: number;
  bookings: number;
}

export interface PaymentBreakdown {
  method: PaymentMethod;
  count: number;
  amount: number;
}
export interface LoginResponse {
  access_token: string;
  token_type: string;
}

export interface LoginParams {
  username: string;
  password: string;
}

export interface User {
  id: string;
  fullName: string;
  email: string;
  isActive: boolean;
  createdAt: Date;
  updatedAt: Date;
}