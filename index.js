const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { initiateSTKPush, handleCallback } = require('./mpesa');
const fs = require('fs');
const path = require('path');

const app = express();
const port = process.env.PORT || 3000; // Use environment variable for port

// CORS configuration
const corsOptions = {
    origin: '*', // Allow all origins for development
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Accept', 'Authorization'],
    credentials: true
};

// Middleware
app.use(cors(corsOptions));
app.use(express.json());

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({ status: 'ok' });
});

// M-Pesa routes
app.post('/api/mpesa/stkpush', async (req, res) => {
    try {
        console.log('Received payment request:', req.body);
        const { phoneNumber, amount, orderId } = req.body;
        
        if (!phoneNumber || !amount || !orderId) {
            return res.status(400).json({
                success: false,
                message: 'Missing required fields: phoneNumber, amount, or orderId'
            });
        }

        console.log('Initiating M-Pesa payment:', { phoneNumber, amount, orderId });
        
        const result = await initiateSTKPush(phoneNumber, amount, orderId);
        console.log('M-Pesa initiation result:', result);
        
        return res.json(result);
    } catch (error) {
        console.error('Error in M-Pesa initiation:', error);
        return res.status(500).json({
            success: false,
            message: error.message || 'Failed to initiate M-Pesa payment'
        });
    }
});

app.post('/api/mpesa/callback', async (req, res) => {
    try {
        const result = await handleCallback(req, res);
        return result;
    } catch (error) {
        console.error('Error in M-Pesa callback:', error);
        return res.status(500).json({
            success: false,
            message: 'Error processing M-Pesa callback'
        });
    }
});

// Payment status endpoint
app.get('/api/mpesa/status/:orderId', (req, res) => {
    try {
        const { orderId } = req.params;
        // TODO: Implement actual status check from database
        return res.json({
            status: 'pending',
            message: 'Payment status check not implemented'
        });
    } catch (error) {
        console.error('Error checking payment status:', error);
        return res.status(500).json({
            success: false,
            message: 'Error checking payment status'
        });
    }
});

// Order status update endpoint
app.post('/api/orders/status', (req, res) => {
    try {
        const { orderId, status } = req.body;
        console.log('Updating order status:', { orderId, status });
        
        if (!orderId || !status) {
            return res.status(400).json({
                success: false,
                message: 'Missing required fields: orderId or status'
            });
        }

        // TODO: Update order status in database
        // For now, just return success
        return res.json({
            success: true,
            message: 'Order status updated successfully',
            data: {
                orderId,
                status,
                updatedAt: new Date().toISOString()
            }
        });
    } catch (error) {
        console.error('Error updating order status:', error);
        return res.status(500).json({
            success: false,
            message: 'Error updating order status'
        });
    }
});

function getDataFilePath(type) {
    return path.join(__dirname, 'data', `${type}.json`);
}

function readData(type) {
    const file = getDataFilePath(type);
    if (!fs.existsSync(file)) return [];
    return JSON.parse(fs.readFileSync(file, 'utf8'));
}

function writeData(type, data) {
    const file = getDataFilePath(type);
    fs.writeFileSync(file, JSON.stringify(data, null, 2));
}

const dataTypes = ['orders', /*'cart',*/ 'menuItems', 'mealsOfDay', 'employees', 'admins', 'payments', 'contacts'];

// IMPORTANT: The generic /api/users endpoint is now adjusted for security.
// We no longer want a generic POST to /api/users. Registration is handled by /api/register.
dataTypes.forEach(type => {
    // GET all
    app.get(`/api/${type}`, (req, res) => {
        try {
            const data = readData(type);
            // For users, never send back passwords
            if (type === 'users') {
                const safeUsers = data.map(({ password, ...user }) => user);
                return res.json(safeUsers);
            }
            res.json(data);
        } catch (err) {
            res.status(500).json({ error: err.message });
        }
    });

    // POST (add new) - We are disabling this for 'users' type
    if (type !== 'users') {
        app.post(`/api/${type}`, (req, res) => {
            try {
                const data = readData(type);
                // For orders, ensure orderId exists
                if (type === 'orders') {
                    if (!req.body.orderId && !req.body.id) {
                        // Generate orderId if missing
                        req.body.orderId = 'ORD' + Date.now();
                    }
                }
                data.push(req.body);
                writeData(type, data);
                res.status(201).json(req.body);
            } catch (err) {
                res.status(500).json({ error: err.message });
            }
        });
    }

    // PUT (update all)
    app.put(`/api/${type}`, (req, res) => {
        try {
            writeData(type, req.body);
            res.json({ success: true });
        } catch (err) {
            res.status(500).json({ error: err.message });
        }
    });
});

// Specific endpoints for individual item management by ID
['menuItems'].forEach(type => {
    // POST - Add a new item
    app.post(`/api/${type}`, (req, res) => {
        try {
            const data = readData(type);
            const newItem = {
                id: `${type.slice(0, -1)}-${Date.now()}`,
                ...req.body
            };
            data.push(newItem);
            writeData(type, data);
            res.status(201).json(newItem);
        } catch (err) {
            res.status(500).json({ error: err.message });
        }
    });

    // GET one by id
    app.get(`/api/${type}/:id`, (req, res) => {
        try {
            const data = readData(type);
            const item = data.find(i => i.id == req.params.id);
            if (item) {
                res.json(item);
            } else {
                res.status(404).json({ error: 'Item not found' });
            }
        } catch (err) {
            res.status(500).json({ error: err.message });
        }
    });

    // PUT (update one by id)
    app.put(`/api/${type}/:id`, (req, res) => {
        try {
            let data = readData(type);
            const index = data.findIndex(i => i.id == req.params.id);
            if (index !== -1) {
                data[index] = { ...data[index], ...req.body };
                writeData(type, data);
                res.json(data[index]);
            } else {
                res.status(404).json({ error: 'Item not found' });
            }
        } catch (err) {
            res.status(500).json({ error: err.message });
        }
    });

    // DELETE one by id
    app.delete(`/api/${type}/:id`, (req, res) => {
        try {
            let data = readData(type);
            const newData = data.filter(i => i.id != req.params.id);
            if (data.length !== newData.length) {
                writeData(type, newData);
                res.status(204).send();
            } else {
                res.status(404).json({ error: 'Item not found' });
            }
        } catch (err) {
            res.status(500).json({ error: err.message });
        }
    });
});

// Employee Management Endpoints
app.post('/api/employees', (req, res) => {
    try {
        const employees = readData('employees');
        const newEmployee = {
            id: `emp-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
            ...req.body
        };
        employees.push(newEmployee);
        writeData('employees', employees);
        res.status(201).json(newEmployee);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.put('/api/employees/:id', (req, res) => {
    try {
        let employees = readData('employees');
        const index = employees.findIndex(emp => emp.id === req.params.id);
        if (index !== -1) {
            employees[index] = { ...employees[index], ...req.body };
            writeData('employees', employees);
            res.json(employees[index]);
        } else {
            res.status(404).json({ error: 'Employee not found' });
        }
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/employees/:id', (req, res) => {
    try {
        let employees = readData('employees');
        const newEmployees = employees.filter(emp => emp.id !== req.params.id);
        if (employees.length !== newEmployees.length) {
            writeData('employees', newEmployees);
            res.status(204).send();
        } else {
            res.status(404).json({ error: 'Employee not found' });
        }
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Cart endpoints (user-specific, server-side storage)
app.get('/api/cart', (req, res) => {
    const userId = req.query.userId;
    if (!userId) return res.status(400).json({ error: 'Missing userId' });
    const allCarts = readData('cart');
    const userCart = allCarts.find(c => c.userId === userId);
    res.json(userCart ? userCart.items : []);
});

// Add or update item in cart
app.post('/api/cart/item', (req, res) => {
    const userId = req.body.userId;
    const item = req.body.item;
    if (!userId || !item) return res.status(400).json({ error: 'Missing userId or item' });
    let allCarts = readData('cart');
    let userCart = allCarts.find(c => c.userId === userId);
    if (!userCart) {
        userCart = { userId, items: [] };
        allCarts.push(userCart);
    }
    const existing = userCart.items.find(i => i.id === item.id);
    if (existing) {
        existing.quantity += item.quantity;
    } else {
        userCart.items.push(item);
    }
    writeData('cart', allCarts);
    res.json({ success: true, cart: userCart.items });
});

// Update quantity of an item
app.put('/api/cart/item', (req, res) => {
    const userId = req.body.userId;
    const itemId = req.body.itemId;
    const quantity = req.body.quantity;
    if (!userId || !itemId || typeof quantity !== 'number') return res.status(400).json({ error: 'Missing userId, itemId, or quantity' });
    let allCarts = readData('cart');
    let userCart = allCarts.find(c => c.userId === userId);
    if (!userCart) return res.status(404).json({ error: 'Cart not found' });
    const item = userCart.items.find(i => i.id === itemId);
    if (!item) return res.status(404).json({ error: 'Item not found' });
    item.quantity = quantity;
    writeData('cart', allCarts);
    res.json({ success: true, cart: userCart.items });
});

// Remove item from cart
app.delete('/api/cart/item', (req, res) => {
    const userId = req.body.userId;
    const itemId = req.body.itemId;
    if (!userId || !itemId) return res.status(400).json({ error: 'Missing userId or itemId' });
    let allCarts = readData('cart');
    let userCart = allCarts.find(c => c.userId === userId);
    if (!userCart) return res.status(404).json({ error: 'Cart not found' });
    userCart.items = userCart.items.filter(i => i.id !== itemId);
    writeData('cart', allCarts);
    res.json({ success: true, cart: userCart.items });
});

// Clear cart
app.delete('/api/cart', (req, res) => {
    const userId = req.query.userId;
    if (!userId) return res.status(400).json({ error: 'Missing userId' });
    let allCarts = readData('cart');
    allCarts = allCarts.filter(c => c.userId !== userId);
    writeData('cart', allCarts);
    res.json({ success: true });
});

// === AUTHENTICATION ROUTES ===

app.post('/api/register', async (req, res) => {
    try {
        const { name, phone, password } = req.body;
        if (!name || !phone || !password) {
            return res.status(400).json({ message: 'Name, phone, and password are required.' });
        }

        const users = readData('users');
        if (users.some(u => u.phone === phone)) {
            return res.status(409).json({ message: 'A user with this phone number already exists.' });
        }

        const hashedPassword = await bcrypt.hash(password, 10); // Hash the password

        const newUser = {
            id: 'user_' + Date.now(),
            name,
            phone,
            password: hashedPassword, // Store the hashed password
            role: 'user', // Default role
            dateCreated: new Date().toISOString()
        };

        users.push(newUser);
        writeData('users', users);

        res.status(201).json({ message: 'User registered successfully.' });
    } catch (error) {
        res.status(500).json({ message: 'Server error during registration.', error: error.message });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { phone, password } = req.body;
        if (!phone || !password) {
            return res.status(400).json({ message: 'Phone and password are required.' });
        }

        const users = readData('users');
        const user = users.find(u => u.phone === phone);

        if (!user) {
            return res.status(401).json({ message: 'Invalid credentials.' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ message: 'Invalid credentials.' });
        }

        // Passwords match, create JWT
        const payload = {
            id: user.id,
            role: user.role
        };

        const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1d' });

        // Send back user info (without password) and token
        res.json({
            token,
            user: {
                id: user.id,
                name: user.name,
                phone: user.phone,
                role: user.role
            }
        });

    } catch (error) {
        res.status(500).json({ message: 'Server error during login.', error: error.message });
    }
});

app.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
}); 