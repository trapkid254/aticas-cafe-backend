const mongoose = require("mongoose");

const BookingFeedbackSchema = new mongoose.Schema({
  from: { type: String, enum: ["admin", "customer"], required: true },
  message: { type: String, required: true },
  proposedAmount: { type: Number }, // Only for admin feedback
  timestamp: { type: Date, default: Date.now },
  adminId: { type: mongoose.Schema.Types.ObjectId, ref: "Admin" },
  adminName: { type: String },
});

const BookingSchema = new mongoose.Schema({
  type: { type: String, enum: ["catering", "tour"], required: true },
  name: { type: String, required: true },
  phone: { type: String, required: true },
  email: { type: String, required: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User" }, // For logged-in users

  // Event details
  eventType: { type: String }, // for catering
  package: { type: String }, // for tour
  date: { type: Date, required: true },
  guests: { type: Number }, // for catering
  people: { type: Number }, // for tour
  location: { type: String }, // for catering
  pickup: { type: String }, // for tour
  notes: { type: String },

  // Status and workflow
  status: {
    type: String,
    enum: [
      "pending",
      "admin_review",
      "price_proposed",
      "customer_accepted",
      "customer_rejected",
      "confirmed",
      "in_progress",
      "completed",
      "cancelled",
    ],
    default: "pending",
  },

  // Payment fields
  originalAmount: { type: Number, default: 0 }, // Customer's initial estimate
  totalAmount: { type: Number, required: true }, // Current total amount (admin can modify)
  finalAmount: { type: Number }, // Final agreed amount after negotiation
  depositRequired: { type: Number, required: true }, // 70% of total
  depositPaid: { type: Boolean, default: false },
  depositAmount: { type: Number, default: 0 },
  paymentStatus: {
    type: String,
    enum: ["pending", "deposit_paid", "fully_paid", "cancelled"],
    default: "pending",
  },

  // Admin feedback and communication
  feedback: [BookingFeedbackSchema],
  adminNotes: { type: String }, // Private admin notes
  lastAdminUpdate: { type: Date },
  lastCustomerResponse: { type: Date },

  // Negotiation tracking
  priceNegotiationRound: { type: Number, default: 0 },
  customerAcceptedPrice: { type: Boolean, default: false },

  // M-Pesa payment identifiers
  merchantRequestId: { type: String },
  checkoutRequestId: { type: String },
  mpesaReceipt: { type: String },

  // File attachments (for admin to share additional details)
  attachments: [
    {
      filename: String,
      originalName: String,
      path: String,
      mimetype: String,
      size: Number,
      uploadedAt: { type: Date, default: Date.now },
      uploadedBy: String, // admin name
    },
  ],

  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
});

// Update the updatedAt field before saving
BookingSchema.pre("save", function (next) {
  this.updatedAt = new Date();
  next();
});

// Instance methods
BookingSchema.methods.addFeedback = function (feedback) {
  this.feedback.push(feedback);
  if (feedback.from === "admin") {
    this.lastAdminUpdate = new Date();
  } else {
    this.lastCustomerResponse = new Date();
  }
  return this.save();
};

BookingSchema.methods.proposePrice = function (
  amount,
  adminMessage,
  adminId,
  adminName,
) {
  this.totalAmount = amount;
  this.finalAmount = amount;
  this.depositRequired = Math.round(amount * 0.7);
  this.status = "price_proposed";
  this.priceNegotiationRound += 1;

  this.feedback.push({
    from: "admin",
    message: adminMessage,
    proposedAmount: amount,
    adminId: adminId,
    adminName: adminName,
  });

  this.lastAdminUpdate = new Date();
  return this.save();
};

BookingSchema.methods.customerAcceptPrice = function (
  customerMessage = "Price accepted",
) {
  this.status = "customer_accepted";
  this.customerAcceptedPrice = true;
  this.finalAmount = this.totalAmount;

  this.feedback.push({
    from: "customer",
    message: customerMessage,
  });

  this.lastCustomerResponse = new Date();
  return this.save();
};

BookingSchema.methods.customerRejectPrice = function (
  customerMessage = "Price rejected",
) {
  this.status = "customer_rejected";
  this.customerAcceptedPrice = false;

  this.feedback.push({
    from: "customer",
    message: customerMessage,
  });

  this.lastCustomerResponse = new Date();
  return this.save();
};

// Static methods
BookingSchema.statics.findByUserId = function (userId) {
  return this.find({ userId: userId }).sort({ createdAt: -1 });
};

BookingSchema.statics.findGuestBookings = function (email, phone) {
  return this.find({
    $and: [
      { userId: { $exists: false } },
      { $or: [{ email: email }, { phone: phone }] },
    ],
  }).sort({ createdAt: -1 });
};

BookingSchema.statics.getPendingReviews = function () {
  return this.find({
    status: { $in: ["pending", "admin_review", "customer_rejected"] },
  }).sort({ createdAt: 1 });
};

module.exports = mongoose.model("Booking", BookingSchema);
