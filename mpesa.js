const axios = require('axios');
const crypto = require('crypto');

// M-Pesa Configuration
const MPESA_CONFIG = {
    env: 'sandbox',
    shortcode: '174379', // Sandbox shortcode
    consumerKey: '054TZRXJNbDmPjhJBD8fVnJGhqVc3aI8aicf8USfapFfqEBO',
    consumerSecret: 'e7FmKAQqMmyjT0bGP7tOEpfnvn0chC6fuMsmilF8vJtoi3QPNMnGEjChJybQnCbt',
    passkey: 'bfb279f9aa9bdbcf158e97dd71a467cd2e0c893059b10f78e6b72ada1ed2c919', // Sandbox passkey
    callbackUrl: 'https://76a9-102-0-8-22.ngrok-free.app/api/mpesa/callback' // ngrok callback URL
};

let accessToken = null;
let tokenExpiry = null;

// Get M-Pesa access token
async function getAccessToken() {
    try {
        // Check if we have a valid token
        if (accessToken && tokenExpiry && Date.now() < tokenExpiry) {
            console.log('Using existing access token');
            return accessToken;
        }

        console.log('Getting new access token...');
        const auth = Buffer.from(`${MPESA_CONFIG.consumerKey}:${MPESA_CONFIG.consumerSecret}`).toString('base64');
        
        const response = await axios.get('https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials', {
            headers: {
                'Authorization': `Basic ${auth}`
            }
        });

        console.log('Access token response:', response.data);

        if (!response.data.access_token) {
            throw new Error('No access token in response');
        }

        accessToken = response.data.access_token;
        // Set token expiry to 55 minutes from now (tokens are valid for 1 hour)
        tokenExpiry = Date.now() + (55 * 60 * 1000);
        
        console.log('New access token obtained successfully');
        return accessToken;
    } catch (error) {
        console.error('Error getting access token:', error.response?.data || error.message);
        throw new Error(`Failed to get access token: ${error.response?.data?.error_description || error.message}`);
    }
}

// Generate M-Pesa password
function generatePassword(timestamp) {
    const str = MPESA_CONFIG.shortcode + MPESA_CONFIG.passkey + timestamp;
    return Buffer.from(str).toString('base64');
}

// Initiate STK Push
async function initiateSTKPush(phoneNumber, amount, orderId) {
    try {
        console.log('\n=== M-PESA PAYMENT INITIATION ===');
        console.log('Starting STK Push process...');
        console.log('Input parameters:', { phoneNumber, amount, orderId });

        // Format phone number to 254 format
        let formattedPhone = phoneNumber;
        if (phoneNumber.startsWith('0')) {
            // Convert 07XXXXXXXX to 2547XXXXXXXX
            formattedPhone = '254' + phoneNumber.substring(1);
        } else if (phoneNumber.startsWith('7')) {
            // Convert 7XXXXXXXX to 2547XXXXXXXX
            formattedPhone = '254' + phoneNumber;
        } else if (!phoneNumber.startsWith('254')) {
            // If number doesn't start with 254, add it
            formattedPhone = '254' + phoneNumber;
        }
        console.log('Formatted phone number:', formattedPhone);

        // Ensure amount is a whole number
        const amountInt = Math.round(amount);
        console.log('Amount:', amountInt);

        const timestamp = new Date().toISOString().replace(/[^0-9]/g, '').slice(0, -3);
        const password = generatePassword(timestamp);
        
        const requestBody = {
            BusinessShortCode: MPESA_CONFIG.shortcode,
            Password: password,
            Timestamp: timestamp,
            TransactionType: "CustomerPayBillOnline",
            Amount: amountInt,
            PartyA: formattedPhone,
            PartyB: MPESA_CONFIG.shortcode,
            PhoneNumber: formattedPhone,
            CallBackURL: MPESA_CONFIG.callbackUrl,
            AccountReference: orderId,
            TransactionDesc: "Payment for order " + orderId
        };

        console.log('\nSending request to M-Pesa...');
        console.log('Request body:', JSON.stringify(requestBody, null, 2));
        console.log('Callback URL:', MPESA_CONFIG.callbackUrl);

        const token = await getAccessToken();
        console.log('Access token obtained successfully');

        const response = await axios.post(
            'https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest',
            requestBody,
            {
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                }
            }
        );

        console.log('\nM-Pesa Response:');
        console.log(JSON.stringify(response.data, null, 2));

        if (!response.data.CheckoutRequestID) {
            throw new Error('No CheckoutRequestID in response');
        }

        if (response.data.ResponseCode !== '0') {
            throw new Error(response.data.ResponseDescription || 'Failed to initiate STK Push');
        }

        console.log('\nPayment initiated successfully!');
        console.log('CheckoutRequestID:', response.data.CheckoutRequestID);
        console.log('Customer Message:', response.data.CustomerMessage);
        console.log('=== END OF PAYMENT INITIATION ===\n');

        return {
            success: true,
            checkoutRequestId: response.data.CheckoutRequestID,
            merchantRequestId: response.data.MerchantRequestID,
            responseCode: response.data.ResponseCode,
            responseDescription: response.data.ResponseDescription,
            customerMessage: response.data.CustomerMessage
        };
    } catch (error) {
        console.error('\n=== PAYMENT ERROR ===');
        console.error('Error details:', error.response?.data || error.message);
        console.error('Full error:', error);
        console.error('=== END OF ERROR ===\n');
        throw new Error(`Failed to initiate STK Push: ${error.response?.data?.errorMessage || error.message}`);
    }
}

// Check transaction status
async function checkTransactionStatus(checkoutRequestId) {
    try {
        console.log('Checking transaction status for:', checkoutRequestId);
        
        const timestamp = new Date().toISOString().replace(/[^0-9]/g, '').slice(0, -3);
        const password = generatePassword(timestamp);

        const requestBody = {
            BusinessShortCode: MPESA_CONFIG.shortcode,
            Password: password,
            Timestamp: timestamp,
            CheckoutRequestID: checkoutRequestId
        };

        console.log('Status check request body:', requestBody);

        const token = await getAccessToken();
        const response = await axios.post(
            'https://sandbox.safaricom.co.ke/mpesa/stkpushquery/v1/query',
            requestBody,
            {
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                }
            }
        );

        console.log('Transaction status response:', response.data);

        return {
            success: true,
            status: response.data.ResultDesc,
            resultCode: response.data.ResultCode,
            orderId: response.data.AccountReference
        };
    } catch (error) {
        console.error('Transaction status check error:', error.response?.data || error.message);
        throw new Error(`Failed to check transaction status: ${error.response?.data?.errorMessage || error.message}`);
    }
}

// Handle callback
async function handleCallback(req, res) {
    try {
        console.log('\n=== M-PESA CALLBACK RECEIVED ===');
        console.log('Callback data:', JSON.stringify(req.body, null, 2));
        
        const { Body: { stkCallback: { MerchantRequestID, CheckoutRequestID, ResultCode, ResultDesc, CallbackMetadata } } } = req.body;

        if (ResultCode === 0) {
            // Payment successful
            const { Amount, MpesaReceiptNumber, TransactionDate, PhoneNumber } = CallbackMetadata;
            
            console.log('\nPayment Successful!');
            console.log('Amount:', Amount);
            console.log('Receipt Number:', MpesaReceiptNumber);
            console.log('Transaction Date:', TransactionDate);
            console.log('Phone Number:', PhoneNumber);
            console.log('=== END OF CALLBACK ===\n');
            
            return res.status(200).json({
                success: true,
                message: 'Payment processed successfully',
                data: {
                    amount: Amount,
                    receiptNumber: MpesaReceiptNumber,
                    transactionDate: TransactionDate,
                    phoneNumber: PhoneNumber
                }
            });
        } else {
            console.log('\nPayment Failed!');
            console.log('Result Description:', ResultDesc);
            console.log('=== END OF CALLBACK ===\n');
            
            return res.status(400).json({
                success: false,
                message: ResultDesc
            });
        }
    } catch (error) {
        console.error('\n=== CALLBACK ERROR ===');
        console.error('Error details:', error);
        console.error('=== END OF ERROR ===\n');
        return res.status(500).json({
            success: false,
            message: 'Error processing payment callback'
        });
    }
}

module.exports = {
    initiateSTKPush,
    checkTransactionStatus,
    handleCallback
}; 