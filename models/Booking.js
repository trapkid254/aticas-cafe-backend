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
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Booking', BookingSchema); 