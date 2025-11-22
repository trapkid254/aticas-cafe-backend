const mongoose = require('mongoose');

const ServiceBookingSchema = new mongoose.Schema({
  serviceType: { type: String, enum: ['garage', 'carwash'], required: true },
  serviceName: { type: String, required: true }, // e.g., "Oil Change", "Exterior Wash"
  name: { type: String, required: true },
  phone: { type: String, required: true },
  email: { type: String, required: true },
  vehicleType: { type: String }, // e.g., "Sedan", "SUV"
  vehicleModel: { type: String },
  date: { type: Date, required: true },
  time: { type: String }, // e.g., "10:00 AM"
  notes: { type: String },
  status: { type: String, default: 'pending', enum: ['pending', 'confirmed', 'completed', 'cancelled'] },
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('ServiceBooking', ServiceBookingSchema);