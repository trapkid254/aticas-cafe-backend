const express = require('express');
const cors = require('cors');
const app = express();
// For development, allow all origins (CORS) - MUST be first
app.use(cors());

require('dotenv').config();
const bodyParser = require('body-parser');
const fetch = require('node-fetch');
const path = require('path');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
console.log('node-fetch loaded for M-Pesa integration');

const PORT = process.env.PORT || 3000;

// MongoDB Atlas connection
const MONGODB_URI = process.env.MONGODB_URI;
mongoose.connect(MONGODB_URI)
  .then(() => console.log('Connected to MongoDB Atlas'))
  .catch(err => console.error('MongoDB connection error:', err));

// Mongoose Menu model
const menuSchema = new mongoose.Schema({
  name: String,
  description: String,
  price: Number,
  category: String,
  image: String,
  quantity: { type: Number, default: 10 }
});
const Menu = mongoose.model('Menu', menuSchema);

// Mongoose Order model
const orderSchema = new mongoose.Schema({
  items: [
    {
      itemType: { type: String, enum: ['Menu', 'MealOfDay'], required: true },
      menuItem: { type: mongoose.Schema.Types.ObjectId, required: true, refPath: 'items.itemType' },
      quantity: Number
    }
  ],
  total: Number,
  status: { type: String, default: 'pending' },
  customerName: String,
  customerPhone: String,
  date: { type: Date, default: Date.now },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  paymentMethod: { type: String },
  orderType: { type: String },
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
  price: Number,
  image: String,
  quantity: { type: Number, default: 10 },
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
});
const User = mongoose.model('User', userSchema);

// Mongoose Cart model
const cartSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  items: [
    {
      itemType: { type: String, enum: ['Menu', 'MealOfDay'], required: true },
      menuItem: { type: mongoose.Schema.Types.ObjectId, required: true, refPath: 'items.itemType' },
      quantity: { type: Number, default: 1 }
    }
  ]
});
const Cart = mongoose.model('Cart', cartSchema);

// Middleware
app.use(bodyParser.json());

// Serve static files from frontend directory
app.use(express.static(path.join(__dirname, '../frontend')));

// JWT Auth Middleware
function authenticateJWT(req, res, next) {
  const token = req.headers['authorization'];
  if (!token) return res.status(401).json({ error: 'No token provided' });
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ error: 'Invalid token' });
    req.user = decoded;
    next();
  });
}

// Admin Auth Middleware
function authenticateAdmin(req, res, next) {
  const token = req.headers['authorization'];
  if (!token) return res.status(401).json({ error: 'No token provided' });
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err || (decoded.role !== 'admin' && decoded.role !== 'superadmin')) return res.status(401).json({ error: 'Unauthorized' });
    req.admin = decoded;
    next();
  });
}

// Routes

// Admin login
app.post('/api/admin/login',
  body('employmentNumber').notEmpty(),
  body('password').notEmpty(),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ success: false, errors: errors.array() });
    const { employmentNumber, password } = req.body;
    try {
      const admin = await Admin.findOne({ employmentNumber });
      if (admin && await bcrypt.compare(password, admin.password)) {
        const token = jwt.sign({ employmentNumber: admin.employmentNumber, role: admin.role }, process.env.JWT_SECRET, { expiresIn: '1d' });
        res.json({ success: true, token, admin: { employmentNumber: admin.employmentNumber, name: admin.name, role: admin.role } });
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

// Get all orders (protected)
app.get('/api/orders', authenticateAdmin, async (req, res) => {
  try {
    const orders = await Order.find().populate('items.menuItem');
    res.json(orders);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch orders' });
  }
});

// GET a single order by ID
app.get('/api/orders/:id', async (req, res) => {
  try {
    const order = await Order.findById(req.params.id).populate('items.menuItem');
    console.log('Fetched order:', JSON.stringify(order, null, 2)); // Debug log
    if (!order) {
      return res.status(404).json({ error: 'Order not found' });
    }
    // Optional: Add check to ensure the user requesting the order is the one who owns it
    res.json(order);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch order' });
  }
});

// Add new order
app.post('/api/orders', async (req, res) => {
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
          // Fetch user details from DB
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
      if (!item.itemType || !['Menu', 'MealOfDay'].includes(item.itemType)) {
        return res.status(400).json({ success: false, error: 'Invalid itemType for one or more items.' });
      }
      
      let found;
      if (item.itemType === 'Menu') {
        found = await Menu.findById(item.menuItem);
      } else if (item.itemType === 'MealOfDay') {
        found = await MealOfDay.findById(item.menuItem);
      }
      
      if (!found) {
        return res.status(400).json({ success: false, error: `Invalid menuItem for itemType ${item.itemType}.` });
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
    
    // Prepare order data
    const orderData = {
      ...req.body,
      userId,
      customerName,
      customerPhone,
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
    res.json({ success: true, order: newOrder });
  } catch (err) {
    console.error('Order creation error:', err);
    res.status(500).json({ success: false, error: 'Failed to add order' });
  }
});

// Update order status (protected)
app.put('/api/orders/:id', authenticateAdmin, async (req, res) => {
  try {
    const { status } = req.body;
    const order = await Order.findById(req.params.id);
    
    if (!order) {
      return res.status(404).json({ success: false, error: 'Order not found' });
    }

    // If status is being changed to 'completed', reduce quantities
    if (status === 'completed' && order.status !== 'completed') {
      for (const item of order.items) {
        const quantityToReduce = item.quantity || 1;
        
        if (item.itemType === 'Menu') {
          // Check current quantity before reducing
          const menuItem = await Menu.findById(item.menuItem);
          if (menuItem.quantity < quantityToReduce) {
            return res.status(400).json({ 
              success: false, 
              error: `Cannot complete order: Insufficient quantity for ${menuItem.name}. Available: ${menuItem.quantity}, Required: ${quantityToReduce}` 
            });
          }
          // Reduce quantity for menu items
          await Menu.findByIdAndUpdate(
            item.menuItem,
            { $inc: { quantity: -quantityToReduce } },
            { new: true }
          );
        } else if (item.itemType === 'MealOfDay') {
          // Check current quantity before reducing
          const mealItem = await MealOfDay.findById(item.menuItem);
          if (mealItem.quantity < quantityToReduce) {
            return res.status(400).json({ 
              success: false, 
              error: `Cannot complete order: Insufficient quantity for ${mealItem.name}. Available: ${mealItem.quantity}, Required: ${quantityToReduce}` 
            });
          }
          // Reduce quantity for meals of the day
          await MealOfDay.findByIdAndUpdate(
            item.menuItem,
            { $inc: { quantity: -quantityToReduce } },
            { new: true }
          );
        }
      }
    }
    
    // If status is being changed to 'cancelled' from 'completed', restore quantities
    if (status === 'cancelled' && order.status === 'completed') {
      for (const item of order.items) {
        const quantityToRestore = item.quantity || 1;
        
        if (item.itemType === 'Menu') {
          // Restore quantity for menu items
          await Menu.findByIdAndUpdate(
            item.menuItem,
            { $inc: { quantity: quantityToRestore } },
            { new: true }
          );
        } else if (item.itemType === 'MealOfDay') {
          // Restore quantity for meals of the day
          await MealOfDay.findByIdAndUpdate(
            item.menuItem,
            { $inc: { quantity: quantityToRestore } },
            { new: true }
          );
        }
      }
    }

    // Update the order status
    const updatedOrder = await Order.findByIdAndUpdate(
      req.params.id, 
      req.body, 
      { new: true }
    );
    
    res.json({ success: true, order: updatedOrder });
  } catch (err) {
    console.error('Order update error:', err);
    res.status(500).json({ success: false, error: 'Failed to update order' });
  }
});

// Get all menu items
app.get('/api/menu', async (req, res) => {
  try {
    const menuItems = await Menu.find();
    res.json(menuItems);
  } catch (err) {
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
app.post('/api/menu', authenticateAdmin, async (req, res) => {
  try {
    const newItem = new Menu(req.body);
    await newItem.save();
    res.json({ success: true, item: newItem });
  } catch (err) {
    res.status(500).json({ success: false, error: 'Failed to add menu item' });
  }
});

// Update menu item (protected)
app.put('/api/menu/:id', authenticateAdmin, async (req, res) => {
  try {
    const updatedItem = await Menu.findByIdAndUpdate(req.params.id, req.body, { new: true });
    if (updatedItem) {
      res.json({ success: true, item: updatedItem });
    } else {
      res.status(404).json({ success: false, error: 'Item not found' });
    }
  } catch (err) {
    res.status(500).json({ success: false, error: 'Failed to update menu item' });
  }
});

// Delete menu item (protected)
app.delete('/api/menu/:id', authenticateAdmin, async (req, res) => {
  try {
    const deletedItem = await Menu.findByIdAndDelete(req.params.id);
    if (deletedItem) {
      res.json({ success: true });
    } else {
      res.status(404).json({ success: false, error: 'Item not found' });
    }
  } catch (err) {
    res.status(500).json({ success: false, error: 'Failed to delete menu item' });
  }
});

// M-Pesa Daraja Sandbox Credentials
const consumerKey = process.env.MPESA_CONSUMER_KEY;
const consumerSecret = process.env.MPESA_CONSUMER_SECRET;
const shortcode = process.env.MPESA_SHORTCODE;
const passkey = process.env.MPESA_PASSKEY;

app.post('/api/mpesa/payment', async (req, res) => {
    let { phone, amount, orderId } = req.body;
    // Sanitize and format phone number
    phone = String(phone).replace(/[-\s]/g, '');
    if (phone.length === 9 && (phone.startsWith('7') || phone.startsWith('1'))) {
        phone = '254' + phone;
    } else if (phone.startsWith('0')) {
        phone = '254' + phone.slice(1);
    }
    // If phone already starts with 254 and is 12 digits, use as is
    try {
        console.log('Received M-Pesa payment request:', { phone, amount, orderId });
        // 1. Get access token
        const auth = Buffer.from(`${consumerKey}:${consumerSecret}`).toString('base64');
        console.log('Requesting access token...');
        const tokenRes = await fetch('https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials', {
            headers: { Authorization: `Basic ${auth}` }
        });
        console.log('Token response status:', tokenRes.status);
        const tokenData = await tokenRes.json();
        console.log('Token data:', tokenData);
        const accessToken = tokenData.access_token;
        if (!accessToken) throw new Error('Failed to get M-Pesa access token');

        // 2. Prepare STK push payload
        const timestamp = new Date().toISOString().replace(/[-T:.Z]/g, '').slice(0, 14);
        const password = Buffer.from(shortcode + passkey + timestamp).toString('base64');
        const payload = {
            BusinessShortCode: shortcode,
            Password: password,
            Timestamp: timestamp,
            TransactionType: 'CustomerPayBillOnline',
            Amount: amount,
            PartyA: phone,
            PartyB: shortcode,
            PhoneNumber: phone,
            CallBackURL: 'https://my-cafe-sandbox-callback.com/mpesa', // Dummy for sandbox
            AccountReference: orderId || 'AticasCafe',
            TransactionDesc: 'Aticas Cafe Order'
        };
        console.log('Sending STK push payload:', payload);

        // 3. Send STK push
        const stkRes = await fetch('https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest', {
            method: 'POST',
            headers: {
                Authorization: `Bearer ${accessToken}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(payload)
        });
        console.log('STK push response status:', stkRes.status);
        const stkData = await stkRes.json();
        console.log('STK push response data:', stkData);
        res.json(stkData);
    } catch (err) {
        console.error('M-Pesa Payment Error:', err);
        res.status(500).json({ error: err.message });
    }
});

// Get all meals of the day
app.get('/api/meals', async (req, res) => {
  try {
    const meals = await MealOfDay.find();
    res.json(meals);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch meals of the day' });
  }
});

// Add new meal of the day (protected)
app.post('/api/meals', authenticateAdmin, async (req, res) => {
  try {
    const { name, price, image, quantity } = req.body;
    if (!name || !price || !image) {
      return res.status(400).json({ success: false, error: 'Name, price, and image are required.' });
    }
    const newMeal = new MealOfDay({ name, price, image, quantity });
    await newMeal.save();
    res.json({ success: true, meal: newMeal });
  } catch (err) {
    res.status(500).json({ success: false, error: 'Failed to add meal of the day' });
  }
});

// Update meal of the day (protected)
app.put('/api/meals/:id', authenticateAdmin, async (req, res) => {
  try {
    const updatedMeal = await MealOfDay.findByIdAndUpdate(req.params.id, req.body, { new: true });
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
    if (!errors.isEmpty()) return res.status(400).json({ success: false, errors: errors.array() });
    const { phone, password } = req.body;
    try {
      const user = await User.findOne({ phone });
      if (user && await bcrypt.compare(password, user.password)) {
        const token = jwt.sign({ userId: user._id, name: user.name, phone: user.phone }, process.env.JWT_SECRET, { expiresIn: '1d' });
        res.json({ success: true, token, user: { _id: user._id, name: user.name, phone: user.phone, email: user.email } });
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
    const cart = await Cart.findOne({ userId: req.params.userId }).populate('items.menuItem');
    if (cart) {
      console.log('Cart items:', cart.items.map(i => ({ itemType: i.itemType, menuItem: i.menuItem })));
    }
    res.json(cart || { userId: req.params.userId, items: [] });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch cart' });
  }
});

// Add or update a single item in the user's cart
app.post('/api/cart/:userId/items', async (req, res) => {
  try {
    const { menuItemId, quantity, itemType } = req.body;
    let cart = await Cart.findOne({ userId: req.params.userId });
    if (!cart) {
      cart = new Cart({ userId: req.params.userId, items: [] });
    }
    // Find by both menuItem and itemType
    const existingItem = cart.items.find(item => item.menuItem.toString() === menuItemId && item.itemType === itemType);
    if (existingItem) {
      existingItem.quantity = quantity;
    } else {
      cart.items.push({ menuItem: menuItemId, quantity, itemType });
    }
    await cart.save();
    res.json({ success: true, cart });
  } catch (err) {
    res.status(500).json({ success: false, error: 'Failed to update cart item' });
  }
});

// Delete a single item from the user's cart
app.delete('/api/cart/:userId/items/:itemType/:menuItemId', async (req, res) => {
  try {
    const { userId, itemType, menuItemId } = req.params;
    let cart = await Cart.findOne({ userId });
    if (!cart) {
      return res.status(404).json({ success: false, error: 'Cart not found' });
    }
    cart.items = cart.items.filter(item => !(item.menuItem.toString() === menuItemId && item.itemType === itemType));
    await cart.save();
    res.json({ success: true, cart });
  } catch (err) {
    res.status(500).json({ success: false, error: 'Failed to remove cart item' });
  }
});

// Clear all items from a user's cart
app.delete('/api/cart/:userId', async (req, res) => {
  try {
    let cart = await Cart.findOne({ userId: req.params.userId });
    if (!cart) {
      return res.status(404).json({ success: false, error: 'Cart not found' });
    }
    cart.items = [];
    await cart.save();
    res.json({ success: true, cart });
  } catch (err) {
    res.status(500).json({ success: false, error: 'Failed to clear cart' });
  }
});

// Get all orders for a specific user (user-facing)
app.get('/api/user-orders', authenticateJWT, async (req, res) => {
  try {
    // userId and phone are in req.user from the JWT
    const userId = req.user.userId;
    let orders = [];
    if (userId) {
      orders = await Order.find({ userId }).populate('items.menuItem');
    } else {
      const userPhone = req.user.phone;
      orders = await Order.find({ customerPhone: userPhone }).populate('items.menuItem');
    }
    res.json(orders);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch user orders' });
  }
});

// Start server
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('Unhandled Rejection:', reason);
});
process.on('uncaughtException', (err) => {
    console.error('Uncaught Exception:', err);
});