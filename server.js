const express = require('express');
const cors = require('cors');
const axios = require('axios');
const app = express();

// Middleware
const corsOptions = {
    origin: '*', // Allow all origins for development
    credentials: true
};
app.use(cors(corsOptions));
app.use(express.json());

// Add request logging
app.use((req, res, next) => {
    console.log(`${new Date().toISOString()} - ${req.method} ${req.url}`);
    next();
});

// M-Pesa Configuration
const MPESA_CONFIG = {
    consumerKey: '054TZRXJNbDmPjhJBD8fVnJGhqVc3aI8aicf8USfapFfqEBO',
    consumerSecret: 'e7FmKAQqMmyjT0bGP7tOEpfnvn0chC6fuMsmilF8vJtoi3QPNMnGEjChJybQnCbt',
    passkey: 'bfb279f9aa9bdbcf158e97dd71a467cd2e0c893059b10f78e6b72ada1ed2c919',
    shortcode: '174379',
    env: 'sandbox',
    callbackUrl: 'https://4626-41-204-18.ngrok-free.app/api/mpesa/callback'
};

// Generate timestamp
function getTimestamp() {
    const date = new Date();
    const year = date.getFullYear();
    const month = String(date.getMonth() + 1).padStart(2, '0');
    const day = String(date.getDate()).padStart(2, '0');
    const hour = String(date.getHours()).padStart(2, '0');
    const minute = String(date.getMinutes()).padStart(2, '0');
    const second = String(date.getSeconds()).padStart(2, '0');
    return `${year}${month}${day}${hour}${minute}${second}`;
}

// Generate password
function generatePassword() {
    const timestamp = getTimestamp();
    const str = MPESA_CONFIG.shortcode + MPESA_CONFIG.passkey + timestamp;
    return Buffer.from(str).toString('base64');
}

// Get access token
async function getAccessToken() {
    try {
        const auth = Buffer.from(`${MPESA_CONFIG.consumerKey}:${MPESA_CONFIG.consumerSecret}`).toString('base64');
        const response = await axios.get('https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials', {
            headers: {
                'Authorization': `Basic ${auth}`
            }
        });
        return response.data.access_token;
    } catch (error) {
        console.error('Error getting access token:', error.response?.data || error.message);
        throw error;
    }
}

// Initiate STK Push
app.post('/api/mpesa/stkpush', async (req, res) => {
    try {
        console.log('\n=== M-PESA PAYMENT INITIATION ===');
        const { phoneNumber, amount, orderId } = req.body;
        console.log('Request body:', { phoneNumber, amount, orderId });
        
        // Validate input
        if (!phoneNumber || !amount || !orderId) {
            console.log('Missing required parameters');
            return res.status(400).json({ error: 'Missing required parameters' });
        }

        // Format phone number if needed
        let formattedPhone = phoneNumber;
        if (phoneNumber.startsWith('0')) {
            formattedPhone = '254' + phoneNumber.substring(1);
        } else if (phoneNumber.startsWith('7')) {
            formattedPhone = '254' + phoneNumber;
        }
        console.log('Formatted phone number:', formattedPhone);

        // Get access token
        console.log('Getting access token...');
        const accessToken = await getAccessToken();
        console.log('Access token obtained successfully');
        
        // Prepare STK Push request
        const timestamp = getTimestamp();
        const password = generatePassword();
        
        const requestBody = {
            BusinessShortCode: MPESA_CONFIG.shortcode,
            Password: password,
            Timestamp: timestamp,
            TransactionType: "CustomerPayBillOnline",
            Amount: Math.round(amount),
            PartyA: formattedPhone,
            PartyB: MPESA_CONFIG.shortcode,
            PhoneNumber: formattedPhone,
            CallBackURL: MPESA_CONFIG.callbackUrl,
            AccountReference: "Atikas Cafe",
            TransactionDesc: `Payment for order ${orderId}`
        };

        console.log('Sending STK Push request to M-Pesa...');
        console.log('Request body:', JSON.stringify(requestBody, null, 2));

        // Make STK Push request
        const response = await axios.post(
            'https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest',
            requestBody,
            {
                headers: {
                    'Authorization': `Bearer ${accessToken}`,
                    'Content-Type': 'application/json'
                }
            }
        );

        console.log('STK Push Response:', JSON.stringify(response.data, null, 2));
        console.log('=== END OF PAYMENT INITIATION ===\n');
        res.json(response.data);
    } catch (error) {
        console.error('\n=== STK PUSH ERROR ===');
        console.error('Error details:', error.response?.data || error.message);
        console.error('Full error:', error);
        console.error('=== END OF ERROR ===\n');
        res.status(500).json({ 
            error: 'Failed to initiate payment',
            details: error.response?.data || error.message
        });
    }
});

// Check M-Pesa payment status
app.get('/api/mpesa/status/:checkoutRequestId', async (req, res) => {
    try {
        const { checkoutRequestId } = req.params;
        
        // Get access token
        const accessToken = await getAccessToken();
        
        // Prepare request body
        const requestBody = {
            BusinessShortCode: MPESA_CONFIG.shortcode,
            Password: generatePassword(),
            Timestamp: getTimestamp(),
            CheckoutRequestID: checkoutRequestId
        };

        // Make request to check status
        const response = await axios.post(
            'https://sandbox.safaricom.co.ke/mpesa/stkpushquery/v1/query',
            requestBody,
            {
                headers: {
                    'Authorization': `Bearer ${accessToken}`,
                    'Content-Type': 'application/json'
                }
            }
        );

        console.log('Payment Status Response:', response.data);
        res.json(response.data);
    } catch (error) {
        console.error('Payment Status Error:', error.response?.data || error.message);
        res.status(500).json({ 
            error: 'Failed to check payment status',
            details: error.response?.data || error.message
        });
    }
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});