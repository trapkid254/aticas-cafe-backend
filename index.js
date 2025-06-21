const express = require('express');
const cors = require('cors');
const { initiateSTKPush, handleCallback } = require('./mpesa');
const fs = require('fs');
const path = require('path');

const app = express();
const port = 3000;

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

const dataTypes = ['users', 'orders', /*'cart',*/ 'menuItems', 'mealsOfDay', 'employees', 'admins', 'payments', 'contacts'];

dataTypes.forEach(type => {
    // GET all
    app.get(`/api/${type}`, (req, res) => {
        try {
            const data = readData(type);
            res.json(data);
        } catch (err) {
            res.status(500).json({ error: err.message });
        }
    });

    // POST (add new)
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

app.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
}); 