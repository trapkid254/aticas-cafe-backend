const mongoose = require("mongoose");

const EventAttachmentSchema = new mongoose.Schema({
  filename: String,
  originalName: String,
  path: String,
  mimetype: String,
  size: Number,
  uploadedAt: { type: Date, default: Date.now },
  uploadedBy: String, // admin name
});

const EventBookingSchema = new mongoose.Schema({
  bookingId: { type: mongoose.Schema.Types.ObjectId, ref: "Booking" },
  customerName: String,
  customerEmail: String,
  customerPhone: String,
  status: {
    type: String,
    enum: ["pending", "confirmed", "cancelled"],
    default: "pending",
  },
  attendees: Number,
  specialRequests: String,
  bookingDate: { type: Date, default: Date.now },
  paymentStatus: {
    type: String,
    enum: ["pending", "deposit_paid", "fully_paid"],
    default: "pending",
  },
  amountPaid: { type: Number, default: 0 },
});

const EventSchema = new mongoose.Schema({
  title: { type: String, required: true },
  description: { type: String, required: true },
  date: { type: Date, required: true },
  endDate: { type: Date }, // Optional end date for multi-day events
  image: { type: String, required: true },
  type: {
    type: String,
    enum: [
      "catering",
      "tour",
      "graduation",
      "wedding",
      "corporate",
      "conference",
      "workshop",
      "celebration",
    ],
    required: true,
  },
  location: { type: String },
  capacity: { type: Number },
  availableSpots: { type: Number }, // Remaining spots available
  price: { type: Number },
  discountPrice: { type: Number }, // Optional discounted price
  featured: { type: Boolean, default: false },
  active: { type: Boolean, default: true },

  // Event details
  duration: { type: String }, // e.g., "2 hours", "Full day"
  requirements: [String], // List of requirements or what's included
  highlights: [String], // Event highlights or key features
  packageIncludes: [String], // What's included in the package

  // Booking management
  bookingsEnabled: { type: Boolean, default: true },
  requiresApproval: { type: Boolean, default: false },
  maxBookingsPerCustomer: { type: Number, default: 1 },
  bookingDeadline: { type: Date }, // Last date for bookings

  // Event bookings
  bookings: [EventBookingSchema],
  totalBookings: { type: Number, default: 0 },
  confirmedBookings: { type: Number, default: 0 },

  // Payment settings
  depositRequired: { type: Boolean, default: false },
  depositPercentage: { type: Number, default: 30 }, // Percentage of total price
  refundPolicy: { type: String },

  // Contact and organizer info
  organizerName: { type: String },
  organizerEmail: { type: String },
  organizerPhone: { type: String },
  contactInstructions: { type: String },

  // SEO and marketing
  tags: [String],
  metaDescription: { type: String },
  slug: { type: String, unique: true, sparse: true },

  // File attachments (brochures, menus, etc.)
  attachments: [EventAttachmentSchema],

  // Status and visibility
  publishedAt: { type: Date },
  status: {
    type: String,
    enum: ["draft", "published", "cancelled", "completed"],
    default: "draft",
  },

  // Analytics
  viewCount: { type: Number, default: 0 },
  bookingClickCount: { type: Number, default: 0 },

  // Timestamps
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
});

// Indexes for better performance
EventSchema.index({ date: 1, active: 1 });
EventSchema.index({ type: 1, active: 1 });
EventSchema.index({ featured: -1, date: 1 });
EventSchema.index({ status: 1, publishedAt: -1 });
EventSchema.index({ slug: 1 });

// Virtual for available spots calculation
EventSchema.virtual("spotsAvailable").get(function () {
  if (!this.capacity) return null;
  return Math.max(0, this.capacity - this.confirmedBookings);
});

// Virtual for booking rate
EventSchema.virtual("bookingRate").get(function () {
  if (!this.capacity || this.capacity === 0) return 0;
  return (this.confirmedBookings / this.capacity) * 100;
});

// Virtual for event status based on date
EventSchema.virtual("eventStatus").get(function () {
  const now = new Date();
  const eventDate = new Date(this.date);
  const endDate = this.endDate ? new Date(this.endDate) : eventDate;

  if (this.status === "cancelled") return "cancelled";
  if (this.status === "draft") return "draft";
  if (now < eventDate) return "upcoming";
  if (now >= eventDate && now <= endDate) return "ongoing";
  return "completed";
});

// Pre-save middleware
EventSchema.pre("save", function (next) {
  this.updatedAt = new Date();

  // Generate slug from title if not provided
  if (!this.slug && this.title) {
    this.slug = this.title
      .toLowerCase()
      .replace(/[^\w\s-]/g, "")
      .replace(/\s+/g, "-")
      .trim();
  }

  // Update available spots
  if (this.capacity) {
    this.availableSpots = Math.max(0, this.capacity - this.confirmedBookings);
  }

  // Set published date when status changes to published
  if (this.status === "published" && !this.publishedAt) {
    this.publishedAt = new Date();
  }

  next();
});

// Instance methods
EventSchema.methods.addBooking = function (bookingData) {
  // Check if booking is allowed
  if (!this.bookingsEnabled) {
    throw new Error("Bookings are not enabled for this event");
  }

  if (this.bookingDeadline && new Date() > this.bookingDeadline) {
    throw new Error("Booking deadline has passed");
  }

  if (this.capacity && this.confirmedBookings >= this.capacity) {
    throw new Error("Event is fully booked");
  }

  // Add booking
  this.bookings.push(bookingData);
  this.totalBookings += 1;

  if (bookingData.status === "confirmed") {
    this.confirmedBookings += 1;
  }

  return this.save();
};

EventSchema.methods.updateBookingStatus = function (bookingId, status) {
  const booking = this.bookings.id(bookingId);
  if (!booking) {
    throw new Error("Booking not found");
  }

  const oldStatus = booking.status;
  booking.status = status;

  // Update confirmed bookings count
  if (oldStatus !== "confirmed" && status === "confirmed") {
    this.confirmedBookings += 1;
  } else if (oldStatus === "confirmed" && status !== "confirmed") {
    this.confirmedBookings -= 1;
  }

  return this.save();
};

EventSchema.methods.incrementViewCount = function () {
  this.viewCount += 1;
  return this.save();
};

EventSchema.methods.incrementBookingClickCount = function () {
  this.bookingClickCount += 1;
  return this.save();
};

// Static methods
EventSchema.statics.findUpcoming = function (limit = 10) {
  const now = new Date();
  return this.find({
    date: { $gte: now },
    status: "published",
    active: true,
  })
    .sort({ date: 1, featured: -1 })
    .limit(limit);
};

EventSchema.statics.findFeatured = function (limit = 5) {
  const now = new Date();
  return this.find({
    featured: true,
    date: { $gte: now },
    status: "published",
    active: true,
  })
    .sort({ date: 1 })
    .limit(limit);
};

EventSchema.statics.findByType = function (type, limit = 10) {
  const now = new Date();
  return this.find({
    type: type,
    date: { $gte: now },
    status: "published",
    active: true,
  })
    .sort({ date: 1, featured: -1 })
    .limit(limit);
};

EventSchema.statics.searchEvents = function (query, options = {}) {
  const {
    type,
    dateFrom,
    dateTo,
    minPrice,
    maxPrice,
    location,
    limit = 20,
    skip = 0,
  } = options;

  const searchCriteria = {
    status: "published",
    active: true,
  };

  // Text search
  if (query) {
    searchCriteria.$text = { $search: query };
  }

  // Type filter
  if (type) {
    searchCriteria.type = type;
  }

  // Date range
  if (dateFrom || dateTo) {
    searchCriteria.date = {};
    if (dateFrom) searchCriteria.date.$gte = new Date(dateFrom);
    if (dateTo) searchCriteria.date.$lte = new Date(dateTo);
  }

  // Price range
  if (minPrice || maxPrice) {
    searchCriteria.price = {};
    if (minPrice) searchCriteria.price.$gte = minPrice;
    if (maxPrice) searchCriteria.price.$lte = maxPrice;
  }

  // Location filter
  if (location) {
    searchCriteria.location = { $regex: location, $options: "i" };
  }

  return this.find(searchCriteria)
    .sort({ featured: -1, date: 1 })
    .skip(skip)
    .limit(limit);
};

// Text index for search functionality
EventSchema.index({
  title: "text",
  description: "text",
  tags: "text",
  location: "text",
});

module.exports = mongoose.model("Event", EventSchema);
