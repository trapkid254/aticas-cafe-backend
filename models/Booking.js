const mongoose = require('mongoose');

const BookingSchema = new mongoose.Schema({
  type: { type: String, enum: ['catering', 'tour'], required: true },
  name: { type: String, required: true },
  phone: { type: String, required: true },
  email: { type: String, required: true },
  eventType: { type: String }, // for catering
  package: { type: String },   // for tour
  date: { type: Date, required: true },
  guests: { type: Number },    // for catering
  people: { type: Number },    // for tour
  location: { type: String },  // for catering
  pickup: { type: String },    // for tour
  notes: { type: String },
  // Payment fields
  totalAmount: { type: Number, required: true },
  depositRequired: { type: Number, required: true }, // 70% of total
  depositPaid: { type: Boolean, default: false },
  depositAmount: { type: Number, default: 0 },
  paymentStatus: { type: String, enum: ['pending', 'deposit_paid', 'fully_paid', 'cancelled'], default: 'pending' },
  // M-Pesa payment identifiers
  merchantRequestId: { type: String },
  checkoutRequestId: { type: String },
  mpesaReceipt: { type: String },
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Booking', BookingSchema); 