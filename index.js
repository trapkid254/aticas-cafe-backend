const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const fs = require('fs');
const path = require('path');
const http = require('http');
const { Server } = require('socket.io');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app =express();
const port = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*", methods: ["GET", "POST"] } });

const dataDir = path.join(__dirname, 'data');
const uploadsDir = path.join(__dirname, 'uploads');
const usersFilePath = path.join(dataDir, 'users.json');
const menuItemsFilePath = path.join(dataDir, 'menuItems.json');
const mealsOfDayFilePath = path.join(dataDir, 'mealsOfDay.json');
const ordersFilePath = path.join(dataDir, 'orders.json');
const cartFilePath = path.join(dataDir, 'cart.json');
const employeesFilePath = path.join(dataDir, 'employees.json');

// Ensure directories and files exist
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });

const initializeFile = (filePath, initialContent = '[]') => {
    if (!fs.existsSync(filePath)) {
        fs.writeFileSync(filePath, initialContent);
    }
};

initializeFile(usersFilePath, '[]');
initializeFile(menuItemsFilePath, '[]');
initializeFile(mealsOfDayFilePath, '[]');
initializeFile(ordersFilePath, '[]');
initializeFile(cartFilePath, '{}');
initializeFile(employeesFilePath, '[]');

// Helper functions
const readData = (filePath) => {
    try {
        const data = fs.readFileSync(filePath, 'utf8');
        return JSON.parse(data);
    } catch (error) {
        if (error.code === 'ENOENT') return filePath.includes('cart') ? {} : [];
        throw error;
    }
};

const writeData = (filePath, data) => {
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2), 'utf8');
};

// Multer setup for file uploads
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/')
    },
    filename: function (req, file, cb) {
        cb(null, Date.now() + path.extname(file.originalname))
    }
});
const upload = multer({ storage: storage });

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'your-default-super-secret-key-that-is-long';
if (JWT_SECRET === 'your-default-super-secret-key-that-is-long') {
    console.warn('Warning: Using default JWT_SECRET. Please set a secure secret in your environment variables.');
}

// Middleware to protect routes
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.sendStatus(401);

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

// Middleware to check for admin role
const isAdmin = (req, res, next) => {
    if (req.user && req.user.role === 'admin') {
        next();
    } else {
        res.status(403).json({ message: 'Forbidden: Requires admin privileges' });
    }
};

// --- API Endpoints ---

// Auth
app.post('/api/register', async (req, res) => {
    const { name, phone, password } = req.body;
    if (!name || !phone || !password) {
        return res.status(400).json({ message: 'Name, phone, and password are required' });
    }
    const users = readData(usersFilePath);
    if (users.find(u => u.phone === phone)) {
        return res.status(400).json({ message: 'User with this phone number already exists' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = {
        id: `user-${Date.now()}`,
        username: name,
        phone,
        password: hashedPassword,
        role: users.length === 0 ? 'admin' : 'customer' // First user is an admin
    };
    users.push(newUser);
    writeData(usersFilePath, users);
    res.status(201).json({ message: 'User registered successfully' });
});

app.post('/api/login', async (req, res) => {
    const { phone, password } = req.body;
    const users = readData(usersFilePath);
    const user = users.find(u => u.phone === phone);
    if (!user) {
        return res.status(400).json({ message: 'Invalid credentials' });
    }
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
        return res.status(400).json({ message: 'Invalid credentials' });
    }
    const accessToken = jwt.sign({ id: user.id, role: user.role, name: user.username }, JWT_SECRET, { expiresIn: '1d' });
    res.json({ accessToken, user: { id: user.id, name: user.username, role: user.role } });
});

app.get('/api/user', authenticateToken, (req, res) => {
    res.json(req.user);
});

// Menu Items
app.get('/api/menuItems', (req, res) => res.json(readData(menuItemsFilePath)));
app.post('/api/menuItems', upload.single('image'), (req, res) => {
    const items = readData(menuItemsFilePath);
    const newItem = {
        id: `menu-${Date.now()}`,
        name: req.body.itemName,
        price: parseFloat(req.body.itemPrice),
        category: req.body.itemCategory,
        available: req.body.itemAvailable === 'on',
        image: req.file ? `/uploads/${req.file.filename}` : req.body.itemImage || null,
    };
    items.push(newItem);
    writeData(menuItemsFilePath, items);
    res.status(201).json(newItem);
});
app.put('/api/menuItems/:id', upload.single('image'), (req, res) => {
    const items = readData(menuItemsFilePath);
    const index = items.findIndex(i => i.id === req.params.id);
    if (index === -1) return res.status(404).json({ message: "Menu item not found" });
    const updatedItem = {
        ...items[index],
        name: req.body.itemName,
        price: parseFloat(req.body.itemPrice),
        category: req.body.itemCategory,
        available: req.body.itemAvailable === 'on',
    };
    if(req.file) {
        updatedItem.image = `/uploads/${req.file.filename}`;
    }
    items[index] = updatedItem;
    writeData(menuItemsFilePath, items);
    res.json(updatedItem);
});
app.delete('/api/menuItems/:id', (req, res) => {
    let items = readData(menuItemsFilePath);
    items = items.filter(i => i.id !== req.params.id);
    writeData(menuItemsFilePath, items);
    res.status(204).send();
});

// Meals of the Day
app.get('/api/mealsOfDay', (req, res) => res.json(readData(mealsOfDayFilePath)));
app.post('/api/mealsOfDay', upload.single('image'), (req, res) => {
    const meals = readData(mealsOfDayFilePath);
    const newMeal = {
        id: `meal-${Date.now()}`,
        name: req.body.mealName,
        description: req.body.mealDescription,
        price: parseFloat(req.body.mealPrice),
        image: req.file ? `/uploads/${req.file.filename}` : req.body.mealImage || null
    };
    meals.push(newMeal);
    writeData(mealsOfDayFilePath, meals);
    res.status(201).json(newMeal);
});
app.delete('/api/mealsOfDay/:id', (req, res) => {
    let meals = readData(mealsOfDayFilePath);
    meals = meals.filter(m => m.id !== req.params.id);
    writeData(mealsOfDayFilePath, meals);
    res.status(204).send();
});

// Orders
app.get('/api/orders', (req, res) => res.json(readData(ordersFilePath)));
app.post('/api/orders', (req, res) => {
    const orders = readData(ordersFilePath);
    const newOrder = { id: `order-${Date.now()}`, ...req.body, status: 'Pending', date: new Date().toISOString() };
    orders.unshift(newOrder);
    writeData(ordersFilePath, orders);
    io.emit('newOrder', newOrder);
    res.status(201).json(newOrder);
});
app.put('/api/orders/:id', (req, res) => {
    const orders = readData(ordersFilePath);
    const index = orders.findIndex(o => o.id === req.params.id);
    if (index === -1) return res.status(404).json({ message: "Order not found" });
    orders[index].status = req.body.status;
    writeData(ordersFilePath, orders);
    io.emit('orderUpdate', orders[index]);
    res.json(orders[index]);
});

// Cart
app.get('/api/cart/:userId', (req, res) => {
    const allCarts = readData(cartFilePath);
    const userCart = allCarts[req.params.userId] || [];
    res.json(userCart);
});
app.post('/api/cart/:userId', (req, res) => {
    const allCarts = readData(cartFilePath);
    const { item } = req.body;
    if (!allCarts[req.params.userId]) {
        allCarts[req.params.userId] = [];
    }
    const cart = allCarts[req.params.userId];
    const existingItem = cart.find(cartItem => cartItem.id === item.id);
    if (existingItem) {
        existingItem.quantity++;
    } else {
        cart.push({ ...item, quantity: 1 });
    }
    writeData(cartFilePath, allCarts);
    res.status(200).json(cart);
});
app.put('/api/cart/:userId/:itemId', (req, res) => {
    const allCarts = readData(cartFilePath);
    const { quantity } = req.body;
    const cart = allCarts[req.params.userId] || [];
    const itemIndex = cart.findIndex(item => item.id === req.params.itemId);
    if (itemIndex > -1) {
        cart[itemIndex].quantity = quantity;
        writeData(cartFilePath, allCarts);
        res.json(cart);
    } else {
        res.status(404).json({ message: 'Item not found in cart' });
    }
});
app.delete('/api/cart/:userId/clear', (req, res) => {
    const allCarts = readData(cartFilePath);
    allCarts[req.params.userId] = [];
    writeData(cartFilePath, allCarts);
    res.status(204).send();
});
app.delete('/api/cart/:userId/:itemId', (req, res) => {
    const allCarts = readData(cartFilePath);
    let cart = allCarts[req.params.userId] || [];
    cart = cart.filter(item => item.id !== req.params.itemId);
    allCarts[req.params.userId] = cart;
    writeData(cartFilePath, allCarts);
    res.status(204).send();
});

// Employee Management CRUD
app.get('/api/employees', (req, res) => {
    const employees = readData(employeesFilePath);
    res.json(employees);
});
app.get('/api/employees/:id', (req, res) => {
    const employees = readData(employeesFilePath);
    const employee = employees.find(e => e.id === req.params.id);
    if (employee) {
        res.json(employee);
    } else {
        res.status(404).json({ message: 'Employee not found' });
    }
});
app.post('/api/employees', (req, res) => {
    const employees = readData(employeesFilePath);
    const { name, role, email, phone } = req.body;
    const newEmployee = { id: `emp-${Date.now()}`, name, role, email, phone };
    employees.push(newEmployee);
    writeData(employeesFilePath, employees);
    res.status(201).json(newEmployee);
});
app.put('/api/employees/:id', (req, res) => {
    const employees = readData(employeesFilePath);
    const index = employees.findIndex(e => e.id === req.params.id);
    if (index !== -1) {
        employees[index] = { ...employees[index], ...req.body };
        writeData(employeesFilePath, employees);
        res.json(employees[index]);
    } else {
        res.status(404).json({ message: 'Employee not found' });
    }
});
app.delete('/api/employees/:id', (req, res) => {
    let employees = readData(employeesFilePath);
    const initialLength = employees.length;
    employees = employees.filter(e => e.id !== req.params.id);
    if (employees.length < initialLength) {
        writeData(employeesFilePath, employees);
        res.status(204).send();
    } else {
        res.status(404).json({ message: 'Employee not found' });
    }
});

// User & Admin Management (Admin only)
app.get('/api/users', authenticateToken, isAdmin, (req, res) => {
    const users = readData(usersFilePath).map(({ password, ...user }) => user); // Exclude passwords from list
    res.json(users);
});

app.get('/api/users/:id', authenticateToken, isAdmin, (req, res) => {
    const users = readData(usersFilePath);
    const user = users.find(u => u.id === req.params.id);
    if (!user) {
        return res.status(404).json({ message: 'User not found' });
    }
    const { password, ...userToReturn } = user;
    res.json(userToReturn);
});

app.post('/api/users', authenticateToken, isAdmin, async (req, res) => {
    const { username, email, password, role } = req.body;
    if (!username || !email || !password || !role) {
        return res.status(400).json({ message: 'Username, email, password, and role are required' });
    }
    const users = readData(usersFilePath);
    if (users.find(u => u.email === email)) {
        return res.status(400).json({ message: 'Email already in use' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = { id: `user-${Date.now()}`, username, email, password: hashedPassword, role };
    users.push(newUser);
    writeData(usersFilePath, users);
    const { password: _, ...userToReturn } = newUser;
    res.status(201).json(userToReturn);
});

app.put('/api/users/:id', authenticateToken, isAdmin, async (req, res) => {
    const { role, password } = req.body;
    const users = readData(usersFilePath);
    const userIndex = users.findIndex(u => u.id === req.params.id);
    if (userIndex === -1) {
        return res.status(404).json({ message: 'User not found' });
    }
    if (role) {
        users[userIndex].role = role;
    }
    if (password) {
        users[userIndex].password = await bcrypt.hash(password, 10);
    }
    writeData(usersFilePath, users);
    const { password: _, ...updatedUser } = users[userIndex];
    res.json(updatedUser);
});

app.delete('/api/users/:id', authenticateToken, isAdmin, (req, res) => {
    if (req.user.id === req.params.id) {
        return res.status(400).json({ message: 'Action forbidden: You cannot delete your own account.' });
    }
    let users = readData(usersFilePath);
    const usersFiltered = users.filter(u => u.id !== req.params.id);
    if (users.length === usersFiltered.length) {
        return res.status(404).json({ message: 'User not found' });
    }
    writeData(usersFilePath, usersFiltered);
    res.status(204).send();
});

// M-Pesa STK Push
app.post('/stkpush', (req, res) => {
    // M-Pesa logic here...
    // This is a placeholder for your actual M-Pesa implementation
    console.log('STK Push initiated:', req.body);
    const { orderId } = req.body;
    
    // Simulate a successful payment notification after a few seconds
    setTimeout(() => {
        console.log('Simulating M-Pesa callback for order:', orderId);
        io.emit('mpesa-payment-notification', {
            success: true,
            message: 'Payment completed successfully.',
            orderId: orderId,
            transactionId: `MPESA-${Date.now()}`
        });
    }, 5000);

    res.json({ message: 'STK push initiated. Please check your phone.' });
});

// Socket.io connection
io.on('connection', (socket) => {
    console.log('a user connected');
    socket.on('disconnect', () => {
        console.log('user disconnected');
    });
});

server.listen(port, () => {
    console.log(`Server listening on port ${port}`);
});