const express = require('express');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const app = express();

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'uploads/');
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + path.extname(file.originalname));
  }
});

 


const upload = multer({ 
  storage: storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
  fileFilter: function (req, file, cb) {
    const filetypes = /jpeg|jpg|png|gif/;
    const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = filetypes.test(file.mimetype);
    
    if (mimetype && extname) {
      return cb(null, true);
    } else {
      cb('Error: Images only (JPEG, JPG, PNG, GIF)');
    }
  }
});

// Create uploads directory if it doesn't exist
const fs = require('fs');
const uploadsDir = 'uploads';
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

// Serve uploaded files statically
app.use('/uploads', express.static('uploads'));

// CORS configuration - allow specific origins for production and development
const allowedOrigins = [
  'https://cafeaticas.netlify.app',
  'https://www.aticascafe.com',
  'https://aticascafe.com',
  'http://localhost:3000',
  'http://localhost:3001',
  'http://127.0.0.1:3000',
  'http://127.0.0.1:3001',
  // Common dev servers (e.g., Live Server, Vite, etc.)
  'http://localhost:5500',
  'http://127.0.0.1:5500',
  // When pages are opened from file://, browsers send Origin: null
  'null'
];

const corsOptions = {
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);

    // Exact allowlist or wildcard for Netlify subdomains (defensive)
    const allowed =
      allowedOrigins.includes(origin) ||
      /https?:\/\/[\w-]+\.netlify\.app$/i.test(origin);

    if (allowed) {
      return callback(null, true);
    }
    return callback(new Error('Not allowed by CORS'));
  },
  credentials: true, // Allow credentials
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept', 'x-access-token', 'X-Admin-Type', 'x-admin-type'],
  optionsSuccessStatus: 200
};

// Apply CORS to all routes
app.use(cors(corsOptions));

// Ensure preflight requests always receive proper CORS headers
app.options('*', cors(corsOptions));

// Preflight requests are handled by the above cors() middleware

// Admin profile - for debugging current admin token payload (must be after CORS)
app.get('/api/admin/profile', authenticateAdmin, (req, res) => {
  try {
    return res.json({ success: true, admin: req.admin });
  } catch (err) {
    return res.status(500).json({ success: false, error: 'Failed to load admin profile' });
  }
});

require('dotenv').config();
const bodyParser = require('body-parser');
const fetch = require('node-fetch');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
console.log('node-fetch loaded for M-Pesa integration');

const PORT = process.env.PORT || 3000;

// MongoDB Atlas connection
const MONGODB_URI = process.env.MONGODB_URI;

// Connect to MongoDB
const connectDB = async () => {
  try {
    await mongoose.connect(MONGODB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true
    });
    console.log('Connected to MongoDB Atlas');
  } catch (err) {
    console.error('MongoDB connection error:', err);
    process.exit(1);
  }
};

// Initialize database connection
connectDB();

// Handle MongoDB connection events
mongoose.connection.on('error', err => {
  console.error('MongoDB connection error:', err);
});

mongoose.connection.on('disconnected', () => {
  console.log('MongoDB disconnected. Reconnecting...');
  connectDB();
});

// Start server only after MongoDB connection is established
const startServer = async () => {
  try {
    // Wait for MongoDB connection
    await new Promise(resolve => {
      mongoose.connection.once('open', resolve);
    });
    
    app.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
    });
  } catch (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
};

startServer();

// Mongoose Menu model
const menuSchema = new mongoose.Schema({
  name: { type: String, required: true },
  description: String,
  price: { type: Number, required: true },
  category: { type: String, required: true },
  image: String,
  quantity: { type: Number, default: 1000 },
  priceOptions: [{
    size: String,
    price: Number
  }],
  date: { type: Date, default: Date.now },
  adminType: {
    type: String,
    required: true,
    enum: ['cafeteria', 'butchery'],
    default: 'cafeteria'
  }
});
const Menu = mongoose.model('Menu', menuSchema);
const Meat = mongoose.model('Meat', menuSchema, 'menus');

// Mongoose Order model
const orderSchema = new mongoose.Schema({
  items: [
    {
      itemType: { type: String, enum: ['Menu', 'MealOfDay', 'Meat'], required: true },
      menuItem: { type: mongoose.Schema.Types.ObjectId, required: true, refPath: 'items.itemType' },
      quantity: Number,
      selectedSize: {
        size: String,
        price: Number
      }
    }
  ],
  total: Number,
  deliveryFee: { type: Number, default: 0 },
  status: { type: String, default: 'pending' },
  customerName: String,
  customerPhone: String,
  date: { type: Date, default: Date.now },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  paymentMethod: { type: String },
  orderType: { type: String },
  // M-Pesa related identifiers and receipt
  merchantRequestId: { type: String },
  checkoutRequestId: { type: String },
  mpesaReceipt: { type: String },
  deliveryLocation: {
    buildingName: String,
    streetAddress: String,
    additionalInfo: String,
    coordinates: {
      latitude: Number,
      longitude: Number
    }
  },
  viewedByAdmin: { type: Boolean, default: false }
});
const Order = mongoose.model('Order', orderSchema);

// Mongoose MealOfDay model
const mealOfDaySchema = new mongoose.Schema({
   name: String,
  description: String,
  price: Number,
  category: String,
  image: String,
  quantity: { type: Number, default: 1000 },
  priceOptions: [{
    size: String,
    price: Number
  }],
  date: { type: Date, default: Date.now }
});
const MealOfDay = mongoose.model('MealOfDay', mealOfDaySchema);

// Mongoose Admin model
const Admin = require('./models/Admin');

// Mongoose Employee model
const employeeSchema = new mongoose.Schema({
  firstName: String,
  lastName: String,
  employmentNumber: { type: String, unique: true },
  role: String,
  department: String,
  email: String,
  phone: String,
  status: String,
  joinDate: String,
  photo: String,
  password: String
});
const Employee = mongoose.model('Employee', employeeSchema);

// Mongoose User model
const userSchema = new mongoose.Schema({
  name: String,
  phone: String,
  email: { type: String, unique: true },
  password: String
}, { timestamps: true });
const User = mongoose.model('User', userSchema);

// Mongoose Cart model
const cartSchema = new mongoose.Schema({
  userId: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: true 
  },
  items: [
    {
      itemType: {
        type: String,
        enum: ['Menu', 'MealOfDay', 'Meat'],
        required: true
      },
      menuItem: { 
        type: mongoose.Schema.Types.ObjectId, 
        required: true, 
        refPath: 'items.itemType' 
      },
      quantity: { 
        type: Number, 
        default: 1 
      },
      selectedSize: {
        size: String,
        price: Number
      }
    }
  ]
}, {
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Virtual for calculating cart total
cartSchema.virtual('total').get(function() {
  return this.items.reduce((total, item) => {
    const price = item.selectedSize?.price || 
                 (item.menuItem?.price || 0);
    return total + (price * item.quantity);
  }, 0);
});

// Create the Cart model
const Cart = mongoose.model('Cart', cartSchema);

// Import the Booking model
const Booking = require('./models/Booking');

// Import the Event model
const Event = require('./models/Event');

// Import the ServiceBooking model

// Middleware
app.use(bodyParser.json());

// Serve static files from frontend directory
app.use(express.static(path.join(__dirname, '../frontend')));

// User Registration (after body parser)
app.post('/api/users/register',
  body('name').trim().notEmpty().withMessage('Name is required'),
  body('phone').trim().notEmpty().withMessage('Phone is required'),
  body('email').isEmail().withMessage('Valid email is required'),
  body('password').isLength({ min: 8, max: 64 }).withMessage('Password length invalid'),
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ success: false, errors: errors.array() });
      }

      const { name, phone, email, password } = req.body;
      const existing = await User.findOne({ email: email.toLowerCase() });
      if (existing) {
        return res.status(400).json({ success: false, error: 'Email already registered' });
      }
      const hashed = await bcrypt.hash(password, 10);
      const user = new User({ name, phone, email: email.toLowerCase(), password: hashed });
      await user.save();
      return res.json({ success: true, user: { _id: user._id, name: user.name, phone: user.phone, email: user.email, createdAt: user.createdAt } });
    } catch (err) {
      console.error('User registration error:', err);
      return res.status(500).json({ success: false, error: 'Registration failed' });
    }
  }
);

// Admin: List users (for reports)
app.get('/api/users', authenticateAdmin, async (req, res) => {
  try {
    const users = await User.find({}, { name: 1, phone: 1, email: 1, createdAt: 1 }).sort({ createdAt: -1 });
    return res.json({ success: true, users });
  } catch (err) {
    console.error('Fetch users error:', err);
    return res.status(500).json({ success: false, error: 'Failed to fetch users' });
  }
});

// Explicitly serve Cafeteria Admin
app.use('/admin', express.static(path.join(__dirname, '../frontend/admin')));

// Specific route for butchery admin index page
app.get('/butchery-admin', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/butchery-admin/index.html'));
});

// Route for butchery admin login
app.get('/butchery-admin/login', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/butchery-admin/butcheryadmin-login.html'));
});

// Route for butchery admin dashboard
app.get('/butchery-admin/dashboard', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/butchery-admin/butcheryadmins.html'));
});

// Route for butchery admin bookings
app.get('/butchery-admin/bookings', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/butchery-admin/butcherybookings.html'));
});

// Route for meat management
app.get('/butchery-admin/meat-management', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/butchery-admin/meat-management.html'));
});

// Route for orders
app.get('/butchery-admin/orders', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/butchery-admin/orders.html'));
});

// Route for payments
app.get('/butchery-admin/payments', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/butchery-admin/payments.html'));
});

// Route for place order
app.get('/butchery-admin/place-order', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/butchery-admin/place-order.html'));
});

// Route for reports
app.get('/butchery-admin/reports', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/butchery-admin/reports.html'));
});


// JWT Auth Middleware
function authenticateJWT(req, res, next) {
  const authHeader = req.headers['authorization'] || req.headers['Authorization'];
  
  // 1. Enhanced error logging (for debugging)
  if (!authHeader) {
    console.error('No authorization header found');
    return res.status(401).json({ success: false, error: 'No token provided' });
  }

  // 2. Check for Bearer token format
  const parts = authHeader.split(' ');
  if (parts.length !== 2 || parts[0].toLowerCase() !== 'bearer') {
    console.error('Invalid token format');
    return res.status(401).json({ success: false, error: 'Invalid token format' });
  }

  const token = parts[1];
  
  if (!token) {
    return res.status(401).json({ success: false, error: 'No token provided' });
  }
  
  // 3. Verify the token
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      console.error('Token verification failed:', err.message);
      // If token is expired, provide a more specific error message
      if (err.name === 'TokenExpiredError') {
        return res.status(401).json({ success: false, error: 'Token expired' });
      }
      return res.status(403).json({ success: false, error: 'Invalid token' });
    }
    
    // 4. Log successful authentication (debug only)
    console.log(`[Auth] Valid token for user:`, {
      userId: decoded.userId, 
      issuedAt: new Date(decoded.iat * 1000),
      expiresAt: new Date(decoded.exp * 1000)
    });
    
    // 5. Attach user to request object
    req.user = decoded;
    next();
  });
}

// Admin Auth Middleware
function authenticateAdmin(req, res, next) {
  // Accept tokens in either "Bearer <token>" or raw "<token>" format to be robust to client differences
  const authHeader = req.headers['authorization'] || req.headers['Authorization'];
  let token = null;
  if (authHeader) {
    const parts = String(authHeader).split(' ');
    token = (parts.length === 2 && parts[0].toLowerCase() === 'bearer') ? parts[1] : authHeader;
  }
  if (!token) return res.status(401).json({ error: 'No token provided' });
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err || (decoded.role !== 'admin' && decoded.role !== 'superadmin')) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
    req.admin = decoded; // This now includes adminType
    next();
  });
}

// Routes

// Admin login - handles cafeteria and butchery admins
app.post('/api/admin/login',
  body('employmentNumber').notEmpty(),
  body('password').notEmpty(),
  body('adminType').isIn(['cafeteria', 'butchery']).withMessage('Invalid admin type'),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ success: false, errors: errors.array() });
    
    const { employmentNumber, password, adminType } = req.body;
    
    try {
      // Find admin with both employmentNumber and adminType
      const admin = await Admin.findOne({ employmentNumber, adminType });
      
      if (admin && await bcrypt.compare(password, admin.password)) {
        const token = jwt.sign({ 
          employmentNumber: admin.employmentNumber, 
          role: admin.role,
          adminType: admin.adminType
        }, process.env.JWT_SECRET, { expiresIn: '1d' });
        
        res.json({ 
          success: true, 
          token, 
          admin: { 
            employmentNumber: admin.employmentNumber, 
            name: admin.name, 
            role: admin.role,
            adminType: admin.adminType
          } 
        });
      } else {
        res.status(401).json({ success: false, error: 'Invalid credentials' });
      }
    } catch (err) {
      console.error('Admin login error:', err);
      res.status(500).json({ success: false, error: 'Login failed' });
    }
  }
);

// Admin CRUD endpoints (protected)
app.get('/api/admins', authenticateAdmin, async (req, res) => {
  try {
    const admins = await Admin.find();
    res.json(admins);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch admins' });
  }
});

app.post('/api/admins', authenticateAdmin,
  body('employmentNumber').notEmpty(),
  body('password').notEmpty(),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ success: false, errors: errors.array() });
    try {
      const hashedPassword = await bcrypt.hash(req.body.password, 10);
      const newAdmin = new Admin({ ...req.body, password: hashedPassword });
      await newAdmin.save();
      res.json({ success: true, admin: newAdmin });
    } catch (err) {
      console.error('Add admin error:', err);
      res.status(500).json({ success: false, error: 'Failed to add admin' });
    }
  }
);

app.put('/api/admins/:id', authenticateAdmin, async (req, res) => {
  try {
    const updatedAdmin = await Admin.findByIdAndUpdate(req.params.id, req.body, { new: true });
    if (updatedAdmin) {
      res.json({ success: true, admin: updatedAdmin });
    } else {
      res.status(404).json({ success: false, error: 'Admin not found' });
    }
  } catch (err) {
    res.status(500).json({ success: false, error: 'Failed to update admin' });
  }
});

app.delete('/api/admins/:id', authenticateAdmin, async (req, res) => {
  try {
    const admin = await Admin.findById(req.params.id);
    if (!admin) {
      return res.status(404).json({ success: false, error: 'Admin not found' });
    }
    if (admin.employmentNumber === 'AC001' || admin.role === 'superadmin') {
      return res.status(403).json({ success: false, error: 'Cannot delete the super admin.' });
    }
    const deletedAdmin = await Admin.findByIdAndDelete(req.params.id);
    if (deletedAdmin) {
      res.json({ success: true });
    } else {
      res.status(404).json({ success: false, error: 'Admin not found' });
    }
  } catch (err) {
    res.status(500).json({ success: false, error: 'Failed to delete admin' });
  }
});

// Employee CRUD endpoints (protected)
app.get('/api/employees', authenticateAdmin, async (req, res) => {
  try {
    const employees = await Employee.find();
    res.json(employees);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch employees' });
  }
});

app.post('/api/employees', authenticateAdmin, async (req, res) => {
  try {
    const newEmployee = new Employee(req.body);
    await newEmployee.save();
    res.json({ success: true, employee: newEmployee });
  } catch (err) {
    res.status(500).json({ success: false, error: 'Failed to add employee' });
  }
});

app.put('/api/employees/:id', authenticateAdmin, async (req, res) => {
  try {
    const updatedEmployee = await Employee.findByIdAndUpdate(req.params.id, req.body, { new: true });
    if (updatedEmployee) {
      res.json({ success: true, employee: updatedEmployee });
    } else {
      res.status(404).json({ success: false, error: 'Employee not found' });
    }
  } catch (err) {
    res.status(500).json({ success: false, error: 'Failed to update employee' });
  }
});

app.delete('/api/employees/:id', authenticateAdmin, async (req, res) => {
  try {
    const deletedEmployee = await Employee.findByIdAndDelete(req.params.id);
    if (deletedEmployee) {
      res.json({ success: true });
    } else {
      res.status(404).json({ success: false, error: 'Employee not found' });
    }
  } catch (err) {
    res.status(500).json({ success: false, error: 'Failed to delete employee' });
  }
});


// Get all orders (protected) with admin type filtering
app.get('/api/orders', authenticateAdmin, async (req, res) => {
  try {
    const adminType = req.admin?.adminType || 'cafeteria';
    const isSuperAdmin = req.admin && (req.admin.role === 'superadmin');

    // Load all orders and populate items for reliable filtering, then filter in-memory.
    // This ensures legacy orders (without items.adminType) are still shown using menuItem.adminType.
    let orders = await Order.find({})
      .populate('items.menuItem')
      .sort({ date: -1 });

    // Always filter by adminType: show only relevant items and recompute totals
    orders = orders
      // First ensure the order contains at least one matching item
      .filter(order => (order.items || []).some(item => {
        const itemAdminType = item.adminType || (item.menuItem && item.menuItem.adminType) || 'cafeteria';
        return itemAdminType === adminType;
      }))
      // Then project to objects with filtered items and recomputed totals
      .map(order => {
        const o = order.toObject();
        o.items = (o.items || []).filter(item => {
          const itemAdminType = item.adminType || (item.menuItem && item.menuItem.adminType) || 'cafeteria';
          return itemAdminType === adminType;
        });
        // Recompute total based on remaining items only
        o.total = (o.items || []).reduce((sum, item) => {
          const unitPrice = (item.selectedSize && typeof item.selectedSize.price === 'number')
            ? item.selectedSize.price
            : ((item.menuItem && typeof item.menuItem.price === 'number') ? item.menuItem.price : 0);
          const qty = typeof item.quantity === 'number' ? item.quantity : 1;
          return sum + (unitPrice * qty);
        }, 0);
        return o;
      })
      .filter(o => (o.items || []).length > 0);

    res.json(orders);
  } catch (err) {
    console.error('Error fetching orders:', err);
    res.status(500).json({ error: 'Failed to fetch orders' });
  }
});

// GET a single order by ID with admin type check
app.get('/api/orders/:id', authenticateAdmin, async (req, res) => {
  try {
    const adminType = req.admin?.adminType || 'cafeteria';
    const order = await Order.findById(req.params.id).populate('items.menuItem');
    
    if (!order) {
      return res.status(404).json({ error: 'Order not found' });
    }
    
    // Verify admin has access to this order
    const hasAccess = order.items.some(item => {
      const itemAdminType = item.adminType || 
                         (item.menuItem && item.menuItem.adminType) || 
                         'cafeteria';
      return itemAdminType === adminType;
    });
    
    if (!hasAccess) {
      return res.status(403).json({ error: 'Unauthorized to access this order' });
    }
    
    // Filter items to the adminType and recompute totals for consistency across admin pages
    const o = order.toObject();
    o.items = (o.items || []).filter(item => {
      const itemAdminType = item.adminType || (item.menuItem && item.menuItem.adminType) || 'cafeteria';
      return itemAdminType === adminType;
    });
    o.total = (o.items || []).reduce((sum, item) => {
      const unitPrice = (item.selectedSize && typeof item.selectedSize.price === 'number')
        ? item.selectedSize.price
        : ((item.menuItem && typeof item.menuItem.price === 'number') ? item.menuItem.price : 0);
      const qty = typeof item.quantity === 'number' ? item.quantity : 1;
      return sum + (unitPrice * qty);
    }, 0);

    // If all items were filtered out (edge case), treat as not found for that admin
    if (!o.items || o.items.length === 0) {
      return res.status(404).json({ error: 'Order not found' });
    }
    return res.json(o);
  } catch (err) {
      res.status(500).json({ error: 'Failed to fetch order' });
    }
  });

// Customer-facing: Get a single order by ID for a logged-in user
app.get('/api/user/orders/:id', authenticateJWT, async (req, res) => {
  try {
    const order = await Order.findById(req.params.id).populate('items.menuItem');
    if (!order) {
      return res.status(404).json({ error: 'Order not found' });
    }
    // If the order is associated with a user, ensure it belongs to the requester
    if (order.userId) {
      if (!req.user || String(order.userId) !== String(req.user.userId)) {
        return res.status(403).json({ error: 'Unauthorized to access this order' });
      }
    }
    return res.json(order);
  } catch (err) {
    console.error('User order fetch error:', err);
    return res.status(500).json({ error: 'Failed to fetch order' });
  }
});

// Public (guest) access: Get a single order by ID without auth
// Returns essential fields only. Intended for guest order confirmation pages.
app.get('/api/orders/public/:id', async (req, res) => {
  try {
    const order = await Order.findById(req.params.id).populate('items.menuItem');
    if (!order) {
      return res.status(404).json({ error: 'Order not found' });
    }
    // Whitelist fields to expose publicly
    const safe = {
      _id: order._id,
      date: order.date,
      items: (order.items || []).map(i => ({
        itemType: i.itemType,
        quantity: i.quantity,
        selectedSize: i.selectedSize,
        menuItem: i.menuItem ? {
          _id: i.menuItem._id,
          name: i.menuItem.name,
          price: i.menuItem.price,
          priceOptions: i.menuItem.priceOptions,
          adminType: i.menuItem.adminType
        } : undefined
      })),
      total: order.total,
      deliveryFee: order.deliveryFee,
      status: order.status,
      paymentMethod: order.paymentMethod,
      orderType: order.orderType,
      customerName: order.customerName,
      customerPhone: order.customerPhone
    };
    return res.json(safe);
  } catch (err) {
    console.error('Public order fetch error:', err);
    return res.status(500).json({ error: 'Failed to fetch order' });
  }
});

// Add new order
app.post('/api/orders', async (req, res) => {
  // For new orders, we'll add adminType to each item
  // This helps with filtering orders by admin type
  try {
    let userId = null;
    let customerName = req.body.customerName;
    let customerPhone = req.body.customerPhone;
    
    // Try to get userId from JWT if present
    const token = req.headers['authorization'];
    if (token) {
      try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        userId = decoded.userId;
        if (userId) {
          const user = await User.findById(userId);
          if (user) {
            customerName = user.name;
            customerPhone = user.phone;
          }
        }
      } catch (err) {}
    }
    
    // Validate each item and check quantities
    for (const item of req.body.items) {
      if (!item.itemType || !['Menu', 'MealOfDay', 'Meat'].includes(item.itemType)) {
        return res.status(400).json({ success: false, error: 'Invalid itemType for one or more items.' });
      }
      
      let found;
      if (item.itemType === 'Menu' || item.itemType === 'Meat') {
        // Meats are stored in the Menu collection with adminType: 'butchery'
        found = await Menu.findById(item.menuItem);
      } else if (item.itemType === 'MealOfDay') {
        found = await MealOfDay.findById(item.menuItem);
      }
      
      if (!found) {
        return res.status(400).json({ success: false, error: `Invalid menuItem for itemType ${item.itemType}.` });
      }
      
      // Validate selectedSize if provided
      if (item.selectedSize) {
        if (item.itemType === 'Menu' && found.priceOptions) {
          const validSize = found.priceOptions.some(
            option => option.size === item.selectedSize.size && 
                     option.price === item.selectedSize.price
          );
          if (!validSize) {
            return res.status(400).json({ 
              success: false, 
              error: `Invalid size selection for ${found.name}` 
            });
          }
        }
      }
      
      // Check if sufficient quantity is available
      const requestedQuantity = item.quantity || 1;
      if (found.quantity < requestedQuantity) {
        return res.status(400).json({ 
          success: false, 
          error: `Insufficient quantity for ${found.name}. Available: ${found.quantity}, Requested: ${requestedQuantity}` 
        });
      }
    }
    
    // Calculate total price including selected sizes
    const itemsWithPrices = await Promise.all(req.body.items.map(async item => {
      let price;
      if (item.selectedSize) {
        price = item.selectedSize.price;
      } else {
        // Use Menu for both 'Menu' and 'Meat'; MealOfDay uses its own model
        const menuItem = item.itemType === 'MealOfDay'
          ? await MealOfDay.findById(item.menuItem)
          : await Menu.findById(item.menuItem);
        price = menuItem.price;
      }
      return {
        ...item,
        price: price * item.quantity
      };
    }));
    
    const subtotal = itemsWithPrices.reduce((sum, item) => sum + item.price, 0);
    const deliveryFee = req.body.deliveryFee || 0;
    const total = subtotal + deliveryFee;
    
    // Add adminType to each item in the order
    const itemsWithAdminType = await Promise.all(req.body.items.map(async (item) => {
      // For Menu and Meat, read adminType from the Menu document; fallback sensibly
      if (item.itemType === 'Menu' || item.itemType === 'Meat') {
        const menuItem = await Menu.findById(item.menuItem);
        return {
          ...item,
          adminType: menuItem?.adminType || (item.itemType === 'Meat' ? 'butchery' : 'cafeteria')
        };
      }
      // For MealOfDay, default to cafeteria
      return {
        ...item,
        adminType: 'cafeteria' // Default for MealOfDay items
      };
    }));

    // Prepare order data
    const orderData = {
      items: itemsWithAdminType,
      customerName,
      customerPhone,
      deliveryLocation: req.body.deliveryLocation,
      deliveryInstructions: req.body.deliveryInstructions,
      paymentMethod: req.body.paymentMethod,
      status: 'pending',
      total,
      deliveryFee,
      userId,
      viewedByAdmin: false
    };
    
    // Validate delivery location if order type is delivery
    if (req.body.orderType === 'delivery') {
      if (!req.body.deliveryLocation) {
        return res.status(400).json({ 
          success: false, 
          error: 'Delivery location is required for delivery orders' 
        });
      }
      
      const { deliveryLocation } = req.body;
      if (!deliveryLocation.buildingName || !deliveryLocation.streetAddress) {
        return res.status(400).json({ 
          success: false, 
          error: 'Building name and street address are required for delivery' 
        });
      }
      
      if (!deliveryLocation.coordinates || 
          typeof deliveryLocation.coordinates.latitude !== 'number' || 
          typeof deliveryLocation.coordinates.longitude !== 'number') {
        return res.status(400).json({ 
          success: false, 
          error: 'Valid coordinates are required for delivery' 
        });
      }
    }
    
    const newOrder = new Order(orderData);
    await newOrder.save();
    
    // Clear the user's cart if logged in
    if (userId) {
      await Cart.findOneAndUpdate(
        { userId },
        { $set: { items: [] } }
      );
    }
    
    res.json({ success: true, order: newOrder });
  } catch (err) {
    console.error('Order creation error:', err);
    res.status(500).json({ success: false, error: 'Failed to add order' });
  }
});

// Update order status (protected)
app.put('/api/orders/:id', authenticateAdmin, async (req, res) => {
  try {
    const adminType = req.admin?.adminType || 'cafeteria';
    const { status, viewedByAdmin } = req.body;
    const isSuperAdmin = req.admin && (req.admin.role === 'superadmin');
    
    // First get the order to verify admin access
    const order = await Order.findById(req.params.id).populate('items.menuItem');
    if (!order) {
      return res.status(404).json({ error: 'Order not found' });
    }
    
    // Verify admin has access to this order
    const hasAccess = isSuperAdmin || (order.items || []).some(item => {
      const itemAdminType = item.adminType || (item.menuItem && item.menuItem.adminType) || 'cafeteria';
      return itemAdminType === adminType;
    });
    
    if (!hasAccess) {
      return res.status(403).json({ error: 'Unauthorized to update this order' });
    }
    
    if (!order) {
      return res.status(404).json({ success: false, error: 'Order not found' });
    }

    // If status is being changed to 'completed', reduce quantities
    if (typeof status === 'string' && status === 'completed' && order.status !== 'completed') {
      for (const item of order.items) {
        const quantityToReduce = item.quantity || 1;

        if (item.itemType === 'Menu' || item.itemType === 'Meat') {
          const menuItem = await Menu.findById(item.menuItem);
          if (menuItem.quantity < quantityToReduce) {
            return res.status(400).json({
              success: false,
              error: `Cannot complete order: Insufficient quantity for ${menuItem.name}. Available: ${menuItem.quantity}, Required: ${quantityToReduce}`
            });
          }
          await Menu.findByIdAndUpdate(
            item.menuItem,
            { $inc: { quantity: -quantityToReduce } },
            { new: true }
          );
        } else if (item.itemType === 'MealOfDay') {
          const mealItem = await MealOfDay.findById(item.menuItem);
          if (mealItem.quantity < quantityToReduce) {
            return res.status(400).json({
              success: false,
              error: `Cannot complete order: Insufficient quantity for ${mealItem.name}. Available: ${mealItem.quantity}, Required: ${quantityToReduce}`
            });
          }
          await MealOfDay.findByIdAndUpdate(
            item.menuItem,
            { $inc: { quantity: -quantityToReduce } },
            { new: true }
          );
        }
      }
    }
    
    // If status is being changed to 'cancelled' from 'completed', restore quantities
    if (typeof status === 'string' && status === 'cancelled' && order.status === 'completed') {
      for (const item of order.items) {
        const quantityToRestore = item.quantity || 1;

        if (item.itemType === 'Menu' || item.itemType === 'Meat') {
          await Menu.findByIdAndUpdate(
            item.menuItem,
            { $inc: { quantity: quantityToRestore } },
            { new: true }
          );
        } else if (item.itemType === 'MealOfDay') {
          await MealOfDay.findByIdAndUpdate(
            item.menuItem,
            { $inc: { quantity: quantityToRestore } },
            { new: true }
          );
        }
      }
    }

    const updateDoc = {};
    if (typeof status === 'string' && status.length) updateDoc.status = status;
    if (typeof viewedByAdmin === 'boolean') updateDoc.viewedByAdmin = viewedByAdmin;

    const updatedOrder = await Order.findByIdAndUpdate(
      req.params.id,
      updateDoc,
      { new: true }
    );
    
    res.json({ success: true, order: updatedOrder });
  } catch (err) {
    console.error('Order update error:', err);
    res.status(500).json({ success: false, error: 'Failed to update order' });
  }
});

// Get all menu items (public endpoint) - cafeteria items and legacy items for public access
app.get('/api/menu', async (req, res) => {
  try {
    // Return cafeteria menu items OR items without adminType (legacy items treated as cafeteria)
    const menuItems = await Menu.find({
      $or: [
        { adminType: 'cafeteria' },
        { adminType: { $exists: false } },
        { adminType: null }
      ]
    });
    res.json(menuItems);
  } catch (err) {
    console.error('Error fetching menu items:', err);
    res.status(500).json({ error: 'Failed to fetch menu items' });
  }
});

// Get admin menu items (protected) - filtered by admin type
app.get('/api/admin/menu', authenticateAdmin, async (req, res) => {
  try {
    const adminType = req.admin?.adminType || 'cafeteria';
    // Include items with matching adminType OR items without adminType (legacy items)
    const menuItems = await Menu.find({
      $or: [
        { adminType },
        { adminType: { $exists: false } },
        { adminType: null }
      ]
    });
    res.json(menuItems);
  } catch (err) {
    console.error('Error fetching admin menu items:', err);
    res.status(500).json({ error: 'Failed to fetch menu items' });
  }
});

// Get menu item by ID
app.get('/api/menu/:id', async (req, res) => {
  try {
    const item = await Menu.findById(req.params.id);
    if (item) {
      res.json(item);
    } else {
      res.status(404).json({ error: 'Menu item not found' });
    }
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch menu item' });
  }
});

// Add new menu item (protected)
app.post('/api/menu', authenticateAdmin, upload.single('image'), async (req, res) => {
  try {
    // Ensure the admin type is set correctly
    const adminType = req.admin?.adminType || 'cafeteria';
    const menuData = {
      ...req.body,
      adminType
    };
    
    const newItem = new Menu(menuData);
    await newItem.save();
    res.json({ success: true, item: newItem });
  } catch (err) {
    res.status(500).json({ success: false, error: 'Failed to add menu item' });
  }
});

// Update menu item (protected)
app.put('/api/menu/:id', authenticateAdmin, async (req, res) => {
  try {
    // First, get the current item to verify admin type
    const existingItem = await Menu.findById(req.params.id);
    if (!existingItem) {
      return res.status(404).json({ error: 'Menu item not found' });
    }
    
    // Verify admin has permission to modify this item
    if (existingItem.adminType !== req.admin?.adminType) {
      return res.status(403).json({ error: 'Unauthorized to modify this menu item' });
    }

    // Validate priceOptions if provided
    if (req.body.priceOptions) {
      for (const option of req.body.priceOptions) {
        if (!option.size || !option.price) {
          return res.status(400).json({ error: 'Each price option must have both size and price' });
        }
      }
    }

    const updateData = { ...req.body };
    
    // Ensure adminType cannot be changed
    delete updateData.adminType;
    
    // Handle image update if provided
    if (req.body.image) {
      updateData.image = req.body.image;
    } else {
      delete updateData.image;
    }
    
    const updatedItem = await Menu.findByIdAndUpdate(req.params.id, updateData, { new: true });
    if (updatedItem) {
      res.json({ success: true, item: updatedItem });
    } else {
      res.status(404).json({ error: 'Menu item not found' });
    }
  } catch (err) {
    res.status(500).json({ success: false, error: 'Failed to update menu item' });
  }
});

// Delete menu item (protected)
app.delete('/api/menu/:id', authenticateAdmin, async (req, res) => {
  try {
    // First, get the current item to verify admin type
    const existingItem = await Menu.findById(req.params.id);
    if (!existingItem) {
      return res.status(404).json({ error: 'Menu item not found' });
    }
    
    // Verify admin has permission to delete this item
    if (existingItem.adminType !== req.admin?.adminType) {
      return res.status(403).json({ error: 'Unauthorized to delete this menu item' });
    }
    
    const deletedItem = await Menu.findByIdAndDelete(req.params.id);
    if (deletedItem) {
      res.json({ success: true });
    } else {
      res.status(404).json({ error: 'Menu item not found' });
    }
  } catch (err) {
    res.status(500).json({ success: false, error: 'Failed to delete menu item' });
  }
});

// Dashboard statistics endpoint with admin type filtering
app.get('/api/dashboard/stats', authenticateAdmin, async (req, res) => {
    try {
        const adminType = req.admin?.adminType || 'cafeteria';
        const today = new Date();
        today.setHours(0, 0, 0, 0);

        // Load orders and populate items to allow robust filtering
        let orders = await Order.find({})
            .sort({ createdAt: -1, date: -1 })
            .populate('items.menuItem');

        // Filter orders that belong to this admin type
        orders = orders.filter(order =>
            (order.items || []).some(item => {
                const itemAdminType = item.adminType || (item.menuItem && item.menuItem.adminType) || 'cafeteria';
                return itemAdminType === adminType;
            })
        );

        // Filter today's orders
        const todayOrders = orders.filter(order => {
            const orderDate = new Date(order.createdAt || order.date);
            return orderDate >= today;
        });

        // Calculate stats (use order.total primarily, with fallbacks)
        const getTotal = (o) => {
            return (
                (typeof o.total === 'number' ? o.total : 0) ||
                (typeof o.totalAmount === 'number' ? o.totalAmount : 0)
            );
        };

        const stats = {
            todayOrders: todayOrders.length,
            todayRevenue: todayOrders.reduce((sum, o) => sum + getTotal(o), 0),
            pendingOrders: orders.filter(o => o.status === 'pending').length,
            completedOrders: orders.filter(o => o.status === 'completed').length
        };

        // Recent orders (last 5) from the filtered list
        const recentOrders = orders
            .slice(0, 5)
            .map(o => o); // already populated

        res.json({
            success: true,
            stats,
            recentOrders
        });

    } catch (err) {
        console.error('Dashboard stats error:', err);
        res.status(500).json({ success: false, error: 'Failed to fetch dashboard stats' });
    }
});

// M-Pesa Daraja Sandbox Credentials
const consumerKey = process.env.MPESA_CONSUMER_KEY;
const consumerSecret = process.env.MPESA_CONSUMER_SECRET;
const shortcode = process.env.MPESA_SHORTCODE;
const passkey = process.env.MPESA_PASSKEY;

app.post('/api/mpesa/payment', async (req, res) => {
    return res.status(410).json({
        error: 'M-Pesa STK is temporarily disabled. Please pay manually to Till 634536.'
    });
});

// M-Pesa Payment Confirmation Callback
app.post('/api/mpesa/callback', async (req, res) => {
    return res.status(410).json({
        success: false,
        error: 'M-Pesa STK callback is disabled. Manual payments to Till 634536.'
    });
});

// Poll order by MerchantRequestID (used by payment waiting page)
app.get('/api/orders/by-merchant-request/:merchantRequestId', async (req, res) => {
  try {
    const { merchantRequestId } = req.params;
    const order = await Order.findOne({ merchantRequestId });
    if (!order) return res.status(404).json({ success: false, error: 'Order not found' });
    return res.json(order);
  } catch (err) {
    console.error('Lookup by merchantRequestId error:', err);
    return res.status(500).json({ success: false, error: 'Failed to lookup order' });
  }
});

// Optional cancel endpoint for timed-out/aborted payments (no-op if order not created yet)
app.post('/api/orders/cancel', async (req, res) => {
  try {
    const { merchantRequestId } = req.body || {};
    if (!merchantRequestId) {
      return res.status(400).json({ success: false, error: 'merchantRequestId is required' });
    }
    const order = await Order.findOne({ merchantRequestId });
    if (!order) {
      // No order created yet; return success so client can proceed to cancelled page
      return res.json({ success: true });
    }
    if (order.status !== 'paid') {
      order.status = 'cancelled';
      await order.save();
    }
    return res.json({ success: true, order });
  } catch (err) {
    console.error('Cancel by merchantRequestId error:', err);
    return res.status(500).json({ success: false, error: 'Failed to cancel order' });
  }
});

// Get all meats (butchery items) (public endpoint)
app.get('/api/meats', async (req, res) => {
  try {
    // Get meat items for butchery admin type
    const meatItems = await Menu.find({ adminType: 'butchery' });
    res.json(meatItems);
  } catch (err) {
    console.error('Error fetching meat items:', err);
    res.status(500).json({ error: 'Failed to fetch meat items' });
  }
});

// Get meat item by ID
app.get('/api/meats/:id', async (req, res) => {
  try {
    const item = await Menu.findOne({ _id: req.params.id, adminType: 'butchery' });
    if (item) {
      res.json(item);
    } else {
      res.status(404).json({ error: 'Meat item not found' });
    }
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch meat item' });
  }
});

// Add new meat (butchery menu item) (protected)
app.post('/api/meats', authenticateAdmin, async (req, res) => {
  try {
    // Only butchery admins can create meats
    const adminType = req.admin?.adminType || 'cafeteria';
    const role = req.admin?.role || 'admin';
    if (adminType !== 'butchery' && role !== 'superadmin') {
      return res.status(403).json({ success: false, error: 'Unauthorized: butchery admin required', detected: { adminType, role } });
    }

    const { name, price, image, description, quantity, category } = req.body || {};
    if (!name || typeof price !== 'number' || !image) {
      return res.status(400).json({ success: false, error: 'Name, numeric price, and image are required.' });
    }

    const meatData = {
      name: String(name),
      price: Number(price),
      image: String(image),
      description: String(description || ''),
      quantity: Number(quantity || 0),
      category: String(category || 'beef'),
      adminType: 'butchery'
    };

    const newMeat = new Menu(meatData);
    await newMeat.save();
    return res.json({ success: true, item: newMeat });
  } catch (err) {
    console.error('Add meat error:', err);
    return res.status(500).json({ success: false, error: 'Failed to add meat' });
  }
});

// Update meat (protected)
app.put('/api/meats/:id', authenticateAdmin, async (req, res) => {
  try {
    // Verify item exists and is a butchery item
    const existing = await Menu.findById(req.params.id);
    if (!existing) return res.status(404).json({ success: false, error: 'Meat item not found' });
    const role = req.admin?.role || 'admin';
    if (existing.adminType !== 'butchery' && role !== 'superadmin') {
      return res.status(403).json({ success: false, error: 'Unauthorized to modify this item', detected: { adminType: req.admin?.adminType, role } });
    }

    // Only allow certain fields to be updated; never allow adminType change
    const update = {};
    if (typeof req.body.name === 'string') update.name = req.body.name;
    if (typeof req.body.price === 'number') update.price = req.body.price;
    if (typeof req.body.image === 'string') update.image = req.body.image;
    if (typeof req.body.description === 'string') update.description = req.body.description;
    if (typeof req.body.quantity === 'number') update.quantity = req.body.quantity;
    if (typeof req.body.category === 'string') update.category = req.body.category;

    const updated = await Menu.findByIdAndUpdate(req.params.id, update, { new: true });
    if (!updated) return res.status(404).json({ success: false, error: 'Meat item not found' });
    return res.json({ success: true, item: updated });
  } catch (err) {
    console.error('Update meat error:', err);
    return res.status(500).json({ success: false, error: 'Failed to update meat' });
  }
});

// Delete meat (protected)
app.delete('/api/meats/:id', authenticateAdmin, async (req, res) => {
  try {
    const existing = await Menu.findById(req.params.id);
    if (!existing) return res.status(404).json({ success: false, error: 'Meat item not found' });
    const role = req.admin?.role || 'admin';
    if (existing.adminType !== 'butchery' && role !== 'superadmin') {
      return res.status(403).json({ success: false, error: 'Unauthorized to delete this item', detected: { adminType: req.admin?.adminType, role } });
    }

    await Menu.findByIdAndDelete(req.params.id);
    return res.json({ success: true });
  } catch (err) {
    console.error('Delete meat error:', err);
    return res.status(500).json({ success: false, error: 'Failed to delete meat' });
  }
});
// Get all meals of the day (public endpoint)
app.get('/api/meals', async (req, res) => {
  try {
    // Get meals for both admin types by default, including legacy items
    const meals = await MealOfDay.find({
      $or: [
        { adminType: { $exists: false } },
        { adminType: null },
        { adminType: { $ne: null } }
      ]
    });
    res.json(meals);
  } catch (err) {
    console.error('Error fetching meals of the day:', err);
    res.status(500).json({ error: 'Failed to fetch meals of the day' });
  }
});

// Add new meal of the day (protected)
app.post('/api/meals', authenticateAdmin, async (req, res) => {
  try {
    const { name, price, image, quantity } = req.body;
    const adminType = req.admin?.adminType || 'cafeteria';
    
    const mealData = {
      name,
      price,
      image,
      quantity: quantity || 0,
      adminType
    };
    if (!name || !price || !image) {
      return res.status(400).json({ success: false, error: 'Name, price, and image are required.' });
    }
    const newMeal = new MealOfDay(mealData);
    await newMeal.save();
    res.json({ success: true, meal: newMeal });
  } catch (err) {
    res.status(500).json({ success: false, error: 'Failed to add meal of the day' });
  }
});

// Update meal of the day (protected)
app.put('/api/meals/:id', authenticateAdmin, async (req, res) => {
  try {
    // First, get the current item to verify admin type
    const existingMeal = await MealOfDay.findById(req.params.id);
    if (!existingMeal) {
      return res.status(404).json({ error: 'Meal not found' });
    }
    
    // Verify admin has permission to modify this item
    if (existingMeal.adminType !== req.admin?.adminType) {
      return res.status(403).json({ error: 'Unauthorized to modify this meal' });
    }
    
    // Don't allow changing adminType through update
    const updateData = { ...req.body };
    delete updateData.adminType;
    
    const updatedMeal = await MealOfDay.findByIdAndUpdate(req.params.id, updateData, { new: true });
    if (updatedMeal) {
      res.json({ success: true, meal: updatedMeal });
    } else {
      res.status(404).json({ success: false, error: 'Meal not found' });
    }
  } catch (err) {
    res.status(500).json({ success: false, error: 'Failed to update meal of the day' });
  }
});

// Delete meal of the day (protected)
app.delete('/api/meals/:id', authenticateAdmin, async (req, res) => {
  try {
    // First, get the current item to verify admin type
    const existingMeal = await MealOfDay.findById(req.params.id);
    if (!existingMeal) {
      return res.status(404).json({ error: 'Meal not found' });
    }
    
    // Verify admin has permission to delete this item
    if (existingMeal.adminType !== req.admin?.adminType) {
      return res.status(403).json({ error: 'Unauthorized to delete this meal' });
    }
    
    const deletedMeal = await MealOfDay.findByIdAndDelete(req.params.id);
    if (deletedMeal) {
      res.json({ success: true });
    } else {
      res.status(404).json({ success: false, error: 'Meal not found' });
    }
  } catch (err) {
    res.status(500).json({ success: false, error: 'Failed to delete meal of the day' });
  }
});

// User registration
app.post('/api/users/register',
  body('name').notEmpty(),
  body('phone').notEmpty(),
  body('email').isEmail(),
  body('password').isLength({ min: 6 }),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ success: false, errors: errors.array() });
    try {
      const { name, phone, email, password } = req.body;
      const existing = await User.findOne({ email });
      if (existing) return res.status(400).json({ success: false, error: 'Email already exists' });
      const hashedPassword = await bcrypt.hash(password, 10);
      const user = new User({ name, phone, email, password: hashedPassword });
      await user.save();
      res.json({ success: true, user });
    } catch (err) {
      console.error('User registration error:', err);
      res.status(500).json({ success: false, error: 'Registration failed' });
    }
  }
);

// User login
app.post('/api/users/login',
  body('phone').notEmpty(),
  body('password').notEmpty(),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ success: false, errors: errors.array() });
    }

    try {
      // Destructure phone and password from req.body
      const { phone, password } = req.body;
      
      const user = await User.findOne({ phone });
      if (user && await bcrypt.compare(password, user.password)) {
        const token = jwt.sign({ 
          userId: user._id,
          name: user.name, 
          phone: user.phone 
        }, process.env.JWT_SECRET, { expiresIn: '1d' });
        
        res.json({ 
          success: true, 
          token, 
          user: { 
            _id: user._id, 
            name: user.name, 
            phone: user.phone, 
            email: user.email 
          } 
        });
      } else {
        res.status(401).json({ success: false, error: 'Invalid credentials' });
      }
    } catch (err) {
      console.error('User login error:', err);
      res.status(500).json({ success: false, error: 'Login failed' });
    }
  }
);

// Get cart for user
app.get('/api/cart/:userId', async (req, res) => {
  try {
    let cart = await Cart.findOne({ userId: req.params.userId }).lean();
    
    if (!cart) {
      return res.json({ userId: req.params.userId, items: [] });
    }

    // Manually populate each item
    for (let item of cart.items) {
      if (item.itemType === 'Menu' || item.itemType === 'Meat') {
        item.menuItem = await Menu.findById(item.menuItem)
          .select('name price image priceOptions category adminType');

        // Ensure selectedSize matches a valid option for Menu items only.
        // For Meat, allow dynamic sizes (e.g., "0.50 kg") so do not invalidate.
        if (item.itemType !== 'Meat' && item.selectedSize && item.menuItem.priceOptions) {
          const validSize = item.menuItem.priceOptions.some(
            opt => opt.size === item.selectedSize.size
          );
          if (!validSize) {
            item.selectedSize = null;
          }
        }
      } else if (item.itemType === 'MealOfDay') {
        item.menuItem = await MealOfDay.findById(item.menuItem)
          .select('name price image');
      }
    }
    
    res.json(cart);
  } catch (err) {
    console.error('Cart fetch error:', err);
    res.status(500).json({ error: 'Failed to fetch cart' });
  }
});

// Update cart item - use authenticated user's ID from JWT
app.patch('/api/cart/items', authenticateJWT, async (req, res) => {
  console.log('--- PATCH /api/cart/items ---');
  console.log('Request body:', JSON.stringify(req.body, null, 2));

  try {
    const { menuItemId, quantity, itemType, selectedSize } = req.body;

    const menuItemIdStr = String(menuItemId);
    console.log(`Looking for item: ${menuItemIdStr}, type: ${itemType}, size: ${selectedSize?.size}`);
    
    // Validate input
    if (!mongoose.Types.ObjectId.isValid(menuItemId)) {
      return res.status(400).json({ error: 'Invalid menuItemId' });
    }
    if (typeof quantity !== 'number' || quantity < 0) {
      return res.status(400).json({ error: 'Invalid quantity' });
    }
    if (!['Menu', 'MealOfDay', 'Meat'].includes(itemType)) {
      return res.status(400).json({ error: 'Invalid itemType' });
    }

    // Use the authenticated user's ID from JWT
    const userId = req.user.userId;
    
    // Find or create cart
    let cart = await Cart.findOne({ userId }) || 
               new Cart({ userId, items: [] });

    // Find existing item index - simplified matching logic
    const existingItemIndex = cart.items.findIndex(item => 
      String(item.menuItem) === menuItemIdStr && 
      item.itemType === itemType &&
      (
        (!selectedSize && !item.selectedSize) ||
        (selectedSize?.size === item.selectedSize?.size)
      )
    );

    if (existingItemIndex >= 0) {
      console.log(`Found existing item at index ${existingItemIndex}, current quantity: ${cart.items[existingItemIndex].quantity}`);
      
      if (quantity <= 0) {
        console.log(`Removing item (quantity ${quantity})`);
        cart.items.splice(existingItemIndex, 1);
      } else {
        console.log(`Updating quantity from ${cart.items[existingItemIndex].quantity} to ${quantity}`);
        cart.items[existingItemIndex].quantity = quantity;
        
        // Update size if changed
        if (selectedSize && JSON.stringify(cart.items[existingItemIndex].selectedSize) !== JSON.stringify(selectedSize)) {
          console.log(`Updating size from ${JSON.stringify(cart.items[existingItemIndex].selectedSize)} to ${JSON.stringify(selectedSize)}`);
          cart.items[existingItemIndex].selectedSize = selectedSize;
        }
      }
    } else if (quantity > 0) {
      console.log(`Adding new item with quantity ${quantity}`);
      cart.items.push({
        menuItem: menuItemId,
        quantity,
        itemType,
        selectedSize: selectedSize || undefined
      });
    }

    // Save the cart
    await cart.save();
    
    // Populate the menu items for response
    const populatedCart = await Cart.findById(cart._id)
      .populate({
        path: 'items.menuItem',
        select: 'name price image priceOptions category'
      });
      
    res.json(populatedCart);
  } catch (err) {
    console.error('Cart update error:', err);
    res.status(500).json({ error: 'Failed to update cart' });
  }
});

// Remove item from cart - use authenticated user's ID from JWT
app.delete('/api/cart/items/:itemId', authenticateJWT, async (req, res) => {
  try {
    const { itemType } = req.query;
    const { itemId } = req.params;
    const userId = req.user.userId;

    // Validate input
    if (!mongoose.Types.ObjectId.isValid(itemId)) {
      return res.status(400).json({ error: 'Invalid item ID' });
    }
    if (!['Menu', 'MealOfDay', 'Meat'].includes(itemType)) {
      return res.status(400).json({ error: 'Invalid item type' });
    }

    // Find the user's cart
    const cart = await Cart.findOne({ userId });
    if (!cart) {
      return res.status(404).json({ error: 'Cart not found' });
    }

    // Remove the item
    const initialItemCount = cart.items.length;
    cart.items = cart.items.filter(item => 
      !(item.menuItem.toString() === itemId && 
        item.itemType === itemType)
    );

    // Check if item was actually removed
    if (cart.items.length === initialItemCount) {
      return res.status(404).json({ error: 'Item not found in cart' });
    }

    await cart.save();
    res.json({ success: true });
  } catch (err) {
    console.error('Error removing cart item:', err);
    res.status(500).json({ error: 'Failed to remove item from cart' });
  }
});

// Clear cart - use authenticated user's ID from JWT
app.delete('/api/cart', authenticateJWT, async (req, res) => {
  try {
    const result = await Cart.findOneAndUpdate(
      { userId: req.user.userId },
      { $set: { items: [] } },
      { new: true, upsert: true }
    );
    
    if (!result) {
      return res.status(404).json({ error: 'Cart not found' });
    }
    
    res.json({ success: true });
  } catch (err) {
    console.error('Clear cart error:', err);
    res.status(500).json({ error: 'Failed to clear cart' });
  }
});

// Get all orders for a specific user (user-facing)
app.get('/api/user-orders', authenticateJWT, async (req, res) => {
  try {
    const userId = req.user.userId;
    let orders = [];
    if (userId) {
      orders = await Order.find({ userId })
        .populate('items.menuItem')
        .sort({ date: -1 });
    } else {
      const userPhone = req.user.phone;
      orders = await Order.find({ customerPhone: userPhone })
        .populate('items.menuItem')
        .sort({ date: -1 });
    }
    res.json(orders);
  } catch (err) {
    console.error('User orders fetch error:', err);
    res.status(500).json({ error: 'Failed to fetch user orders' });
  }
});

// Bookings endpoints
app.post('/api/bookings', async (req, res) => {
  try {
    const bookingData = { ...req.body };
    // Calculate deposit if totalAmount is provided
    if (bookingData.totalAmount) {
      bookingData.depositRequired = Math.round(bookingData.totalAmount * 0.7);
    }
    const booking = new Booking(bookingData);
    await booking.save();
    res.status(201).json({ success: true, booking });
  } catch (err) {
    console.error('Error creating booking:', err);
    res.status(500).json({ success: false, error: 'Failed to create booking' });
  }
});

app.get('/api/bookings', async (req, res) => {
  try {
    const bookings = await Booking.find().sort({ createdAt: -1 });
    res.json({ success: true, bookings });
  } catch (err) {
    res.status(500).json({ success: false, error: 'Failed to fetch bookings' });
  }
});

app.put('/api/bookings/:id', authenticateAdmin, async (req, res) => {
  try {
    const { paymentStatus } = req.body;
    const updatedBooking = await Booking.findByIdAndUpdate(
      req.params.id,
      { paymentStatus },
      { new: true }
    );
    if (updatedBooking) {
      res.json({ success: true, booking: updatedBooking });
    } else {
      res.status(404).json({ success: false, error: 'Booking not found' });
    }
  } catch (err) {
    res.status(500).json({ success: false, error: 'Failed to update booking' });
  }
});

// Events endpoints
// Get upcoming events (public)
app.get('/api/events', async (req, res) => {
  try {
    const now = new Date();
    const events = await Event.find({
      active: true,
      date: { $gte: now }
    }).sort({ date: 1, featured: -1 });
    res.json({ success: true, events });
  } catch (err) {
    console.error('Error fetching events:', err);
    res.status(500).json({ success: false, error: 'Failed to fetch events' });
  }
});

// Get all events (admin)
app.get('/api/admin/events', authenticateAdmin, async (req, res) => {
  try {
    const events = await Event.find().sort({ date: -1 });
    res.json({ success: true, events });
  } catch (err) {
    console.error('Error fetching admin events:', err);
    res.status(500).json({ success: false, error: 'Failed to fetch events' });
  }
});

// Create event (admin)
app.post('/api/admin/events', authenticateAdmin, async (req, res) => {
  try {
    const eventData = { ...req.body };
    const event = new Event(eventData);
    await event.save();
    res.status(201).json({ success: true, event });
  } catch (err) {
    console.error('Error creating event:', err);
    res.status(500).json({ success: false, error: 'Failed to create event' });
  }
});

// Update event (admin)
app.put('/api/admin/events/:id', authenticateAdmin, async (req, res) => {
  try {
    const updatedEvent = await Event.findByIdAndUpdate(
      req.params.id,
      req.body,
      { new: true }
    );
    if (updatedEvent) {
      res.json({ success: true, event: updatedEvent });
    } else {
      res.status(404).json({ success: false, error: 'Event not found' });
    }
  } catch (err) {
    console.error('Error updating event:', err);
    res.status(500).json({ success: false, error: 'Failed to update event' });
  }
});

// Delete event (admin)
app.delete('/api/admin/events/:id', authenticateAdmin, async (req, res) => {
  try {
    const deletedEvent = await Event.findByIdAndDelete(req.params.id);
    if (deletedEvent) {
      res.json({ success: true });
    } else {
      res.status(404).json({ success: false, error: 'Event not found' });
    }
  } catch (err) {
    console.error('Error deleting event:', err);
    res.status(500).json({ success: false, error: 'Failed to delete event' });
  }
});


// Server startup is now handled by startServer() after MongoDB connection

process.on('unhandledRejection', (reason, promise) => {
    console.error('Unhandled Rejection:', reason);
});
process.on('uncaughtException', (err) => {
    console.error('Uncaught Exception:', err);
    // Exit with failure
    process.exit(1);
});