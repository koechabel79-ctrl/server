require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const axios = require('axios');
const PDFDocument = require('pdfkit');
const { v4: uuidv4 } = require('uuid');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const pgSession = require('connect-pg-simple')(session);
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 5000;

// Database connection
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Test database connection
pool.connect((err, client, release) => {
    if (err) {
        console.error('Error connecting to database:', err.stack);
    } else {
        console.log('Connected to Railway PostgreSQL database');
        release();
    }
});

// Middleware
app.use(helmet({ contentSecurityPolicy: false }));

// CORS - Allow your static frontend site
const allowedOrigins = [
    'https://airtimetest.onrender.com',
    'https://airtimekenya.onrender.com',  // Replace with your actual static site URL
    process.env.FRONTEND_ORIGIN
].filter(Boolean);

app.use(cors({
    origin: function(origin, callback) {
        // Allow requests with no origin (mobile apps, curl, etc)
        if (!origin) return callback(null, true);
        if (allowedOrigins.includes(origin)) {
            return callback(null, true);
        }
        return callback(null, false);
    },
    credentials: true
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Root route - API info (no static files needed since frontend is separate)
app.get('/', (req, res) => {
    res.json({
        name: 'Airtime Solution Kenya API',
        status: 'running',
        version: '1.0',
        endpoints: {
            users: '/api/users',
            payments: '/api/payments',
            transactions: '/api/transactions'
        }
    });
});

// Session configuration
app.use(session({
    store: new pgSession({
        pool: pool,
        tableName: 'session'
    }),
    secret: process.env.SESSION_SECRET || 'airtime-solution-kenya-secret-2024',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
    }
}));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: { success: false, message: 'Too many requests, please try again later.' }
});
app.use('/api/', limiter);

// Strict rate limiting for admin login (prevent brute force)
const adminLoginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: { success: false, message: 'Too many login attempts. Please try again in 15 minutes.' },
    standardHeaders: true,
    legacyHeaders: false
});

// Environment variables
const PAYNECTA_API_KEY = process.env.PAYNECTA_API_KEY;
const PAYNECTA_EMAIL = process.env.PAYNECTA_EMAIL;
const STATUM_CONSUMER_KEY = process.env.STATUM_CONSUMER_KEY;
const STATUM_CONSUMER_SECRET = process.env.STATUM_CONSUMER_SECRET;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '3462Abel@#';
const CALLBACK_BASE_URL = process.env.CALLBACK_BASE_URL || 'https://airtimeserver.onrender.com';
const PAYHERO_LINK = 'https://short.payhero.co.ke/s/oEvAxA8Xx6cDoBLxntShmF';

// Bonus calculation for deposits
function calculateBonus(amount) {
    if (amount >= 50) {
        return 6;
    }
    return 0;
}

// Airtime cost calculation (user pays 20, gets 18 worth of airtime)
function calculateAirtimeCost(amount) {
    return Math.floor(amount * 0.9);
}

// ===================== USER ROUTES =====================

// Check if username exists
app.get('/api/users/check-username/:username', async (req, res) => {
    try {
        const { username } = req.params;
        const result = await pool.query('SELECT id FROM users WHERE LOWER(username) = LOWER($1)', [username]);
        res.json({ exists: result.rows.length > 0 });
    } catch (error) {
        console.error('Check username error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Check if email has connected username
app.get('/api/users/check-email/:email', async (req, res) => {
    try {
        const { email } = req.params;
        const result = await pool.query('SELECT username FROM users WHERE LOWER(email) = LOWER($1)', [email]);
        if (result.rows.length > 0) {
            res.json({ exists: true, username: result.rows[0].username });
        } else {
            res.json({ exists: false });
        }
    } catch (error) {
        console.error('Check email error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Register new user
app.post('/api/users/register', async (req, res) => {
    try {
        const { username, email, phone, firebase_uid } = req.body;
        
        // Check if username already exists
        const usernameCheck = await pool.query('SELECT id FROM users WHERE LOWER(username) = LOWER($1)', [username]);
        if (usernameCheck.rows.length > 0) {
            return res.status(400).json({ success: false, message: 'Username already taken' });
        }
        
        // Check if email already exists
        const emailCheck = await pool.query('SELECT id FROM users WHERE LOWER(email) = LOWER($1)', [email]);
        if (emailCheck.rows.length > 0) {
            return res.status(400).json({ success: false, message: 'Email already registered' });
        }
        
        const id = uuidv4();
        const formattedPhone = phone.startsWith('254') ? phone : `254${phone.replace(/^0/, '')}`;
        
        await pool.query(
            `INSERT INTO users (id, username, email, phone, firebase_uid, balance, bonus_balance, is_disabled, created_at)
             VALUES ($1, $2, $3, $4, $5, 0, 0, false, NOW())`,
            [id, username, email, formattedPhone, firebase_uid]
        );
        
        // Create welcome notification
        await pool.query(
            `INSERT INTO notifications (id, user_id, scope, title, message, is_read, created_at)
             VALUES ($1, $2, 'user', 'Welcome to Airtime Solution Kenya! 🎉', 'Thank you for joining us. Start by depositing funds to buy airtime.', false, NOW())`,
            [uuidv4(), id]
        );
        
        res.json({ success: true, message: 'User registered successfully', userId: id });
    } catch (error) {
        console.error('Register error:', error);
        res.status(500).json({ success: false, message: 'Registration failed' });
    }
});

// Get user by email (for login)
app.get('/api/users/by-email/:email', async (req, res) => {
    try {
        const { email } = req.params;
        const result = await pool.query(
            'SELECT id, username, email, phone, balance, bonus_balance, is_disabled FROM users WHERE LOWER(email) = LOWER($1)',
            [email]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }
        
        if (result.rows[0].is_disabled) {
            return res.status(403).json({ success: false, message: 'Account is disabled. Contact support.' });
        }
        
        // Update last login
        await pool.query('UPDATE users SET last_login_at = NOW() WHERE id = $1', [result.rows[0].id]);
        
        res.json({ success: true, user: result.rows[0] });
    } catch (error) {
        console.error('Get user error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Get user balance by username (for auto-refresh)
app.get('/api/users/balance/:username', async (req, res) => {
    try {
        const { username } = req.params;
        const result = await pool.query(
            'SELECT balance, bonus_balance FROM users WHERE LOWER(username) = LOWER($1)',
            [username]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }
        
        res.json({
            success: true,
            balance: parseFloat(result.rows[0].balance),
            bonus: parseFloat(result.rows[0].bonus_balance),
            total: parseFloat(result.rows[0].balance) + parseFloat(result.rows[0].bonus_balance)
        });
    } catch (error) {
        console.error('Get balance error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Get user profile
app.get('/api/users/profile/:username', async (req, res) => {
    try {
        const { username } = req.params;
        const result = await pool.query(
            `SELECT id, username, email, phone, balance, bonus_balance, created_at, last_login_at 
             FROM users WHERE LOWER(username) = LOWER($1)`,
            [username]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }
        
        res.json({ success: true, user: result.rows[0] });
    } catch (error) {
        console.error('Get profile error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// ===================== PAYNECTA PAYMENT ROUTES =====================

// Initialize STK Push deposit
app.post('/api/payments/deposit', async (req, res) => {
    try {
        const { phone, amount, username } = req.body;
        
        if (!phone || !amount || !username) {
            return res.status(400).json({ success: false, message: 'Phone, amount, and username are required' });
        }
        
        if (parseFloat(amount) < 10) {
            return res.status(400).json({ success: false, message: 'Minimum deposit is KES 10' });
        }
        
        // Get user
        const userResult = await pool.query('SELECT id FROM users WHERE LOWER(username) = LOWER($1)', [username]);
        if (userResult.rows.length === 0) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }
        
        const userId = userResult.rows[0].id;
        const formattedPhone = phone.startsWith('254') ? phone : `254${phone.replace(/^0/, '')}`;
        const reference = `DEP-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
        
        // Create pending transaction
        const transactionId = uuidv4();
        await pool.query(
            `INSERT INTO transactions (id, user_id, type, amount, fee, bonus, status, external_provider, phone, reference, created_at)
             VALUES ($1, $2, 'deposit', $3, 0, $4, 'pending', 'paynecta', $5, $6, NOW())`,
            [transactionId, userId, amount, calculateBonus(parseFloat(amount)), formattedPhone, reference]
        );
        
        // Call Paynecta STK Push API
        const paynectaResponse = await axios.post('https://paynecta.co.ke/api/v1/payments/initiate', {
            phone: formattedPhone,
            amount: parseFloat(amount),
            reference: reference,
            callback_url: `${CALLBACK_BASE_URL}/api/payments/paynecta/callback`
        }, {
            headers: {
                'X-API-Key': PAYNECTA_API_KEY,
                'X-User-Email': PAYNECTA_EMAIL,
                'Content-Type': 'application/json'
            }
        });
        
        if (paynectaResponse.data.success) {
            res.json({
                success: true,
                message: 'STK Push sent. Please enter your M-Pesa PIN.',
                reference: reference,
                transactionId: transactionId
            });
        } else {
            // Update transaction to failed
            await pool.query('UPDATE transactions SET status = $1 WHERE id = $2', ['failed', transactionId]);
            res.status(400).json({ success: false, message: paynectaResponse.data.message || 'Payment initiation failed' });
        }
    } catch (error) {
        console.error('Deposit error:', error.response?.data || error);
        res.status(500).json({ success: false, message: 'Payment service error. Please try again.' });
    }
});

// Paynecta callback
app.post('/api/payments/paynecta/callback', async (req, res) => {
    try {
        console.log('Paynecta callback received:', JSON.stringify(req.body));
        console.log('Callback from IP:', req.ip);
        
        const { reference, status, mpesa_code, amount } = req.body;
        
        if (!reference) {
            return res.status(400).json({ success: false, message: 'Reference required' });
        }
        
        // Validate reference format (must start with DEP- and be our format)
        if (!reference.startsWith('DEP-')) {
            console.warn('Invalid reference format:', reference);
            return res.status(400).json({ success: false, message: 'Invalid reference format' });
        }
        
        // Find transaction - must exist and be pending
        const transactionResult = await pool.query(
            'SELECT id, user_id, amount, bonus, status FROM transactions WHERE reference = $1',
            [reference]
        );
        
        if (transactionResult.rows.length === 0) {
            console.warn('Transaction not found for reference:', reference);
            return res.status(404).json({ success: false, message: 'Transaction not found' });
        }
        
        const transaction = transactionResult.rows[0];
        
        // Prevent double-processing - only process pending transactions
        if (transaction.status !== 'pending') {
            console.log('Transaction already processed:', reference, transaction.status);
            return res.json({ success: true, message: 'Transaction already processed' });
        }
        
        if (status === 'success' || status === 'completed') {
            // Update transaction
            await pool.query(
                `UPDATE transactions SET status = 'completed', metadata = $1 WHERE id = $2`,
                [JSON.stringify({ mpesa_code }), transaction.id]
            );
            
            // Credit user balance
            const totalAmount = parseFloat(transaction.amount);
            const bonus = parseFloat(transaction.bonus);
            
            await pool.query(
                'UPDATE users SET balance = balance + $1, bonus_balance = bonus_balance + $2 WHERE id = $3',
                [totalAmount, bonus, transaction.user_id]
            );
            
            // Check for pending airtime purchases
            const pendingPurchase = await pool.query(
                `SELECT id, target_phone, amount FROM pending_purchases 
                 WHERE user_id = $1 AND status = 'awaiting_funds' 
                 ORDER BY initiated_at ASC LIMIT 1`,
                [transaction.user_id]
            );
            
            if (pendingPurchase.rows.length > 0) {
                const purchase = pendingPurchase.rows[0];
                // Auto-fulfill the pending purchase
                await processPendingAirtimePurchase(purchase.id, transaction.user_id);
            }
            
            console.log(`Deposit successful for user ${transaction.user_id}: KES ${totalAmount} + ${bonus} bonus`);
        } else {
            // Update transaction to failed
            await pool.query('UPDATE transactions SET status = $1 WHERE id = $2', ['failed', transaction.id]);
        }
        
        res.json({ success: true, message: 'Callback processed' });
    } catch (error) {
        console.error('Callback error:', error);
        res.status(500).json({ success: false, message: 'Callback processing error' });
    }
});

// Query payment status
app.get('/api/payments/status/:reference', async (req, res) => {
    try {
        const { reference } = req.params;
        const result = await pool.query(
            'SELECT status, amount, bonus, created_at FROM transactions WHERE reference = $1',
            [reference]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({ success: false, message: 'Transaction not found' });
        }
        
        res.json({ success: true, transaction: result.rows[0] });
    } catch (error) {
        console.error('Status query error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Verify deposit with M-Pesa code
app.post('/api/payments/verify-deposit', async (req, res) => {
    try {
        const { mpesa_code, username, amount } = req.body;
        
        if (!mpesa_code || !username) {
            return res.status(400).json({ success: false, message: 'M-Pesa code and username are required' });
        }
        
        // Get user
        const userResult = await pool.query('SELECT id FROM users WHERE LOWER(username) = LOWER($1)', [username]);
        if (userResult.rows.length === 0) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }
        const userId = userResult.rows[0].id;
        
        // Check if already verified
        const existingVerification = await pool.query(
            'SELECT id, status FROM deposit_verifications WHERE UPPER(mpesa_code) = UPPER($1)',
            [mpesa_code]
        );
        
        if (existingVerification.rows.length > 0) {
            const verification = existingVerification.rows[0];
            if (verification.status === 'validated') {
                return res.status(400).json({ success: false, message: 'This M-Pesa code has already been used' });
            }
            return res.json({ success: true, message: 'Verification already submitted, awaiting review' });
        }
        
        // Check if already received
        const existingTransaction = await pool.query(
            `SELECT id FROM transactions WHERE metadata->>'mpesa_code' = $1 AND status = 'completed'`,
            [mpesa_code.toUpperCase()]
        );
        
        if (existingTransaction.rows.length > 0) {
            return res.status(400).json({ success: false, message: 'This deposit has already been credited to your account' });
        }
        
        // Create verification request
        await pool.query(
            `INSERT INTO deposit_verifications (id, user_id, mpesa_code, amount_claimed, status, submitted_at)
             VALUES ($1, $2, $3, $4, 'pending', NOW())`,
            [uuidv4(), userId, mpesa_code.toUpperCase(), amount || 0]
        );
        
        res.json({ success: true, message: 'Verification submitted. Admin will review shortly.' });
    } catch (error) {
        console.error('Verify deposit error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Generate PayHero payment link
app.post('/api/payments/payhero-link', async (req, res) => {
    try {
        const { phone, amount, username } = req.body;
        
        const formattedPhone = phone.startsWith('254') ? phone : `254${phone.replace(/^0/, '')}`;
        
        // PayHero link with autofill parameters
        const payHeroUrl = `${PAYHERO_LINK}?phone=${formattedPhone}&amount=${amount}&name=${encodeURIComponent(username)}&reference=${encodeURIComponent('#airtime deposit')}`;
        
        res.json({ success: true, paymentLink: payHeroUrl });
    } catch (error) {
        console.error('PayHero link error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// ===================== STATUM AIRTIME ROUTES =====================

// Check float balance
app.get('/api/airtime/float-status', async (req, res) => {
    try {
        // This would check Statum float balance - for now return a flag from settings
        const result = await pool.query("SELECT value FROM settings WHERE key = 'float_low'");
        const isLow = result.rows.length > 0 && result.rows[0].value === 'true';
        res.json({ success: true, floatLow: isLow });
    } catch (error) {
        console.error('Float status error:', error);
        res.json({ success: true, floatLow: false });
    }
});

// Buy airtime (using balance)
app.post('/api/airtime/buy', async (req, res) => {
    try {
        const { phone, amount, username } = req.body;
        
        if (!phone || !amount || !username) {
            return res.status(400).json({ success: false, message: 'Phone, amount, and username are required' });
        }
        
        if (parseFloat(amount) < 5) {
            return res.status(400).json({ success: false, message: 'Minimum airtime is KES 5' });
        }
        
        // Check float status
        const floatResult = await pool.query("SELECT value FROM settings WHERE key = 'float_low'");
        if (floatResult.rows.length > 0 && floatResult.rows[0].value === 'true') {
            return res.status(503).json({ success: false, message: 'Airtime service temporarily unavailable. Please try again later.' });
        }
        
        // Get user
        const userResult = await pool.query(
            'SELECT id, balance, bonus_balance FROM users WHERE LOWER(username) = LOWER($1)',
            [username]
        );
        
        if (userResult.rows.length === 0) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }
        
        const user = userResult.rows[0];
        const totalBalance = parseFloat(user.balance) + parseFloat(user.bonus_balance);
        const airtimeAmount = parseFloat(amount);
        
        if (totalBalance < airtimeAmount) {
            return res.status(400).json({
                success: false,
                message: 'Insufficient balance',
                balance: totalBalance,
                required: airtimeAmount,
                shortfall: airtimeAmount - totalBalance
            });
        }
        
        const formattedPhone = phone.startsWith('254') ? phone : `254${phone.replace(/^0/, '')}`;
        const reference = `AIR-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
        
        // Calculate actual airtime (user pays 20, gets 18 worth)
        const actualAirtime = calculateAirtimeCost(airtimeAmount);
        
        // Deduct from balance (use bonus first)
        let remainingAmount = airtimeAmount;
        let bonusUsed = 0;
        let balanceUsed = 0;
        
        if (parseFloat(user.bonus_balance) > 0) {
            bonusUsed = Math.min(parseFloat(user.bonus_balance), remainingAmount);
            remainingAmount -= bonusUsed;
        }
        balanceUsed = remainingAmount;
        
        // Create transaction
        const transactionId = uuidv4();
        await pool.query(
            `INSERT INTO transactions (id, user_id, type, amount, fee, bonus, status, external_provider, phone, reference, metadata, created_at)
             VALUES ($1, $2, 'airtime', $3, $4, 0, 'pending', 'statum', $5, $6, $7, NOW())`,
            [transactionId, user.id, airtimeAmount, airtimeAmount - actualAirtime, formattedPhone, reference, JSON.stringify({ actual_airtime: actualAirtime })]
        );
        
        // Call Statum API
        const statumAuth = Buffer.from(`${STATUM_CONSUMER_KEY}:${STATUM_CONSUMER_SECRET}`).toString('base64');
        
        const statumResponse = await axios.post('https://api.statum.co.ke/api/v2/airtime', {
            phone_number: formattedPhone,
            amount: actualAirtime.toString()
        }, {
            headers: {
                'Authorization': `Basic ${statumAuth}`,
                'Content-Type': 'application/json'
            }
        });
        
        if (statumResponse.data.status_code === 200) {
            // Update user balance
            await pool.query(
                'UPDATE users SET balance = balance - $1, bonus_balance = bonus_balance - $2 WHERE id = $3',
                [balanceUsed, bonusUsed, user.id]
            );
            
            // Update transaction
            await pool.query(
                `UPDATE transactions SET status = 'completed', metadata = $1 WHERE id = $2`,
                [JSON.stringify({ actual_airtime: actualAirtime, statum_request_id: statumResponse.data.request_id }), transactionId]
            );
            
            res.json({
                success: true,
                message: `KES ${actualAirtime} airtime sent to ${formattedPhone}`,
                reference: reference,
                airtimeSent: actualAirtime
            });
        } else {
            await pool.query('UPDATE transactions SET status = $1 WHERE id = $2', ['failed', transactionId]);
            res.status(400).json({ success: false, message: 'Airtime purchase failed. Please try again.' });
        }
    } catch (error) {
        console.error('Airtime error:', error.response?.data || error);
        res.status(500).json({ success: false, message: 'Airtime service error. Please try again.' });
    }
});

// Buy airtime directly with payment
app.post('/api/airtime/buy-direct', async (req, res) => {
    try {
        const { phone_to_receive, phone_to_pay, amount, username } = req.body;
        
        if (!phone_to_receive || !phone_to_pay || !amount) {
            return res.status(400).json({ success: false, message: 'All fields are required' });
        }
        
        // Check float status
        const floatResult = await pool.query("SELECT value FROM settings WHERE key = 'float_low'");
        if (floatResult.rows.length > 0 && floatResult.rows[0].value === 'true') {
            return res.status(503).json({ success: false, message: 'Airtime service temporarily unavailable. Please try again later.' });
        }
        
        const formattedPayPhone = phone_to_pay.startsWith('254') ? phone_to_pay : `254${phone_to_pay.replace(/^0/, '')}`;
        const formattedReceivePhone = phone_to_receive.startsWith('254') ? phone_to_receive : `254${phone_to_receive.replace(/^0/, '')}`;
        const reference = `DAIR-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
        
        // Get user if logged in
        let userId = null;
        if (username) {
            const userResult = await pool.query('SELECT id FROM users WHERE LOWER(username) = LOWER($1)', [username]);
            if (userResult.rows.length > 0) {
                userId = userResult.rows[0].id;
            }
        }
        
        const actualAirtime = calculateAirtimeCost(parseFloat(amount));
        
        // Create pending purchase
        const purchaseId = uuidv4();
        await pool.query(
            `INSERT INTO pending_purchases (id, user_id, target_phone, amount, status, deposit_reference, initiated_at)
             VALUES ($1, $2, $3, $4, 'awaiting_funds', $5, NOW())`,
            [purchaseId, userId, formattedReceivePhone, actualAirtime, reference]
        );
        
        // Initiate STK push
        const paynectaResponse = await axios.post('https://paynecta.co.ke/api/v1/payments/initiate', {
            phone: formattedPayPhone,
            amount: parseFloat(amount),
            reference: reference,
            callback_url: `${CALLBACK_BASE_URL}/api/payments/direct-airtime/callback`
        }, {
            headers: {
                'X-API-Key': PAYNECTA_API_KEY,
                'X-User-Email': PAYNECTA_EMAIL,
                'Content-Type': 'application/json'
            }
        });
        
        if (paynectaResponse.data.success) {
            res.json({
                success: true,
                message: 'STK Push sent. Complete payment to receive airtime.',
                reference: reference
            });
        } else {
            await pool.query('UPDATE pending_purchases SET status = $1 WHERE id = $2', ['expired', purchaseId]);
            res.status(400).json({ success: false, message: 'Payment initiation failed' });
        }
    } catch (error) {
        console.error('Direct airtime error:', error.response?.data || error);
        res.status(500).json({ success: false, message: 'Service error. Please try again.' });
    }
});

// Direct airtime payment callback
app.post('/api/payments/direct-airtime/callback', async (req, res) => {
    try {
        console.log('Direct airtime callback received:', req.body);
        
        const { reference, status } = req.body;
        
        if (!reference) {
            return res.status(400).json({ success: false, message: 'Reference required' });
        }
        
        const purchaseResult = await pool.query(
            'SELECT id, target_phone, amount FROM pending_purchases WHERE deposit_reference = $1',
            [reference]
        );
        
        if (purchaseResult.rows.length === 0) {
            return res.status(404).json({ success: false, message: 'Purchase not found' });
        }
        
        const purchase = purchaseResult.rows[0];
        
        if (status === 'success' || status === 'completed') {
            // Send airtime via Statum
            const statumAuth = Buffer.from(`${STATUM_CONSUMER_KEY}:${STATUM_CONSUMER_SECRET}`).toString('base64');
            
            const statumResponse = await axios.post('https://api.statum.co.ke/api/v2/airtime', {
                phone_number: purchase.target_phone,
                amount: purchase.amount.toString()
            }, {
                headers: {
                    'Authorization': `Basic ${statumAuth}`,
                    'Content-Type': 'application/json'
                }
            });
            
            if (statumResponse.data.status_code === 200) {
                await pool.query('UPDATE pending_purchases SET status = $1 WHERE id = $2', ['completed', purchase.id]);
            } else {
                await pool.query('UPDATE pending_purchases SET status = $1 WHERE id = $2', ['processing', purchase.id]);
            }
        } else {
            await pool.query('UPDATE pending_purchases SET status = $1 WHERE id = $2', ['expired', purchase.id]);
        }
        
        res.json({ success: true, message: 'Callback processed' });
    } catch (error) {
        console.error('Direct airtime callback error:', error);
        res.status(500).json({ success: false, message: 'Callback processing error' });
    }
});

// Store pending purchase for insufficient balance
app.post('/api/airtime/pending', async (req, res) => {
    try {
        const { phone, amount, username } = req.body;
        
        const userResult = await pool.query('SELECT id FROM users WHERE LOWER(username) = LOWER($1)', [username]);
        if (userResult.rows.length === 0) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }
        
        const userId = userResult.rows[0].id;
        const formattedPhone = phone.startsWith('254') ? phone : `254${phone.replace(/^0/, '')}`;
        
        const purchaseId = uuidv4();
        await pool.query(
            `INSERT INTO pending_purchases (id, user_id, target_phone, amount, status, initiated_at)
             VALUES ($1, $2, $3, $4, 'awaiting_funds', NOW())`,
            [purchaseId, userId, formattedPhone, calculateAirtimeCost(parseFloat(amount))]
        );
        
        res.json({ success: true, purchaseId: purchaseId });
    } catch (error) {
        console.error('Pending purchase error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Process pending airtime purchase
async function processPendingAirtimePurchase(purchaseId, userId) {
    try {
        const purchaseResult = await pool.query(
            'SELECT id, target_phone, amount FROM pending_purchases WHERE id = $1 AND user_id = $2 AND status = $3',
            [purchaseId, userId, 'awaiting_funds']
        );
        
        if (purchaseResult.rows.length === 0) return;
        
        const purchase = purchaseResult.rows[0];
        const userResult = await pool.query('SELECT balance, bonus_balance FROM users WHERE id = $1', [userId]);
        
        if (userResult.rows.length === 0) return;
        
        const user = userResult.rows[0];
        const totalBalance = parseFloat(user.balance) + parseFloat(user.bonus_balance);
        
        if (totalBalance >= parseFloat(purchase.amount)) {
            // Process the purchase
            const statumAuth = Buffer.from(`${STATUM_CONSUMER_KEY}:${STATUM_CONSUMER_SECRET}`).toString('base64');
            
            const statumResponse = await axios.post('https://api.statum.co.ke/api/v2/airtime', {
                phone_number: purchase.target_phone,
                amount: purchase.amount.toString()
            }, {
                headers: {
                    'Authorization': `Basic ${statumAuth}`,
                    'Content-Type': 'application/json'
                }
            });
            
            if (statumResponse.data.status_code === 200) {
                // Deduct balance
                await pool.query(
                    'UPDATE users SET balance = balance - $1 WHERE id = $2',
                    [purchase.amount, userId]
                );
                
                await pool.query('UPDATE pending_purchases SET status = $1 WHERE id = $2', ['completed', purchaseId]);
            }
        }
    } catch (error) {
        console.error('Process pending purchase error:', error);
    }
}

// Statum callback
app.post('/api/airtime/statum/callback', async (req, res) => {
    try {
        console.log('Statum callback received:', req.body);
        res.json({ success: true, message: 'Callback received' });
    } catch (error) {
        console.error('Statum callback error:', error);
        res.status(500).json({ success: false, message: 'Callback error' });
    }
});

// ===================== TRANSACTION ROUTES =====================

// Get user transactions
app.get('/api/transactions/:username', async (req, res) => {
    try {
        const { username } = req.params;
        const limit = parseInt(req.query.limit) || 50;
        const offset = parseInt(req.query.offset) || 0;
        
        const userResult = await pool.query('SELECT id FROM users WHERE LOWER(username) = LOWER($1)', [username]);
        if (userResult.rows.length === 0) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }
        
        const userId = userResult.rows[0].id;
        
        const transactions = await pool.query(
            `SELECT id, type, amount, fee, bonus, status, phone, reference, created_at 
             FROM transactions WHERE user_id = $1 
             ORDER BY created_at DESC LIMIT $2 OFFSET $3`,
            [userId, limit, offset]
        );
        
        res.json({ success: true, transactions: transactions.rows });
    } catch (error) {
        console.error('Get transactions error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Download transactions as PDF
app.get('/api/transactions/:username/pdf', async (req, res) => {
    try {
        const { username } = req.params;
        
        const userResult = await pool.query(
            'SELECT id, username, email, phone FROM users WHERE LOWER(username) = LOWER($1)',
            [username]
        );
        
        if (userResult.rows.length === 0) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }
        
        const user = userResult.rows[0];
        
        const transactions = await pool.query(
            `SELECT type, amount, fee, bonus, status, phone, reference, created_at 
             FROM transactions WHERE user_id = $1 ORDER BY created_at DESC`,
            [user.id]
        );
        
        // Create PDF
        const doc = new PDFDocument({ margin: 50 });
        
        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', `attachment; filename=transactions_${username}_${Date.now()}.pdf`);
        
        doc.pipe(res);
        
        // Header
        doc.fontSize(20).text('Airtime Solution Kenya', { align: 'center' });
        doc.fontSize(12).text('Transaction History', { align: 'center' });
        doc.moveDown();
        
        // User info
        doc.fontSize(10);
        doc.text(`Username: ${user.username}`);
        doc.text(`Email: ${user.email}`);
        doc.text(`Phone: ${user.phone}`);
        doc.text(`Generated: ${new Date().toLocaleString()}`);
        doc.moveDown();
        
        // Transactions table
        doc.fontSize(9);
        const tableTop = doc.y;
        const headers = ['Date', 'Type', 'Amount', 'Status', 'Phone', 'Reference'];
        const colWidths = [80, 60, 60, 60, 90, 130];
        
        let x = 50;
        headers.forEach((header, i) => {
            doc.text(header, x, tableTop, { width: colWidths[i], align: 'left' });
            x += colWidths[i];
        });
        
        doc.moveTo(50, tableTop + 15).lineTo(530, tableTop + 15).stroke();
        
        let y = tableTop + 20;
        transactions.rows.forEach((t, index) => {
            if (y > 700) {
                doc.addPage();
                y = 50;
            }
            
            x = 50;
            doc.text(new Date(t.created_at).toLocaleDateString(), x, y, { width: colWidths[0] });
            x += colWidths[0];
            doc.text(t.type, x, y, { width: colWidths[1] });
            x += colWidths[1];
            doc.text(`KES ${t.amount}`, x, y, { width: colWidths[2] });
            x += colWidths[2];
            doc.text(t.status, x, y, { width: colWidths[3] });
            x += colWidths[3];
            doc.text(t.phone || '-', x, y, { width: colWidths[4] });
            x += colWidths[4];
            doc.text(t.reference || '-', x, y, { width: colWidths[5] });
            
            y += 15;
        });
        
        // Footer
        doc.moveDown(2);
        doc.fontSize(8).text('This document is auto-generated. For queries, contact support.', { align: 'center' });
        
        doc.end();
    } catch (error) {
        console.error('PDF generation error:', error);
        res.status(500).json({ success: false, message: 'PDF generation failed' });
    }
});

// ===================== NOTIFICATION ROUTES =====================

// Get user notifications
app.get('/api/notifications/:username', async (req, res) => {
    try {
        const { username } = req.params;
        
        const userResult = await pool.query('SELECT id FROM users WHERE LOWER(username) = LOWER($1)', [username]);
        if (userResult.rows.length === 0) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }
        
        const userId = userResult.rows[0].id;
        
        const notifications = await pool.query(
            `SELECT id, title, message, is_read, created_at FROM notifications 
             WHERE (user_id = $1 OR scope = 'system') 
             ORDER BY created_at DESC LIMIT 20`,
            [userId]
        );
        
        res.json({ success: true, notifications: notifications.rows });
    } catch (error) {
        console.error('Get notifications error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Mark notification as read
app.put('/api/notifications/:id/read', async (req, res) => {
    try {
        const { id } = req.params;
        await pool.query('UPDATE notifications SET is_read = true WHERE id = $1', [id]);
        res.json({ success: true });
    } catch (error) {
        console.error('Mark read error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// ===================== ADMIN ROUTES =====================

// Admin login
app.post('/api/admin/login', adminLoginLimiter, (req, res) => {
    const { password } = req.body;
    
    if (!password) {
        return res.status(400).json({ success: false, message: 'Password required' });
    }
    
    if (password === ADMIN_PASSWORD) {
        req.session.isAdmin = true;
        console.log(`Admin login from IP: ${req.ip}`);
        res.json({ success: true, message: 'Admin logged in' });
    } else {
        res.status(401).json({ success: false, message: 'Invalid password' });
    }
});

// Admin auth middleware
function adminAuth(req, res, next) {
    if (req.session && req.session.isAdmin) {
        next();
    } else {
        res.status(401).json({ success: false, message: 'Unauthorized' });
    }
}

// Get all users (admin)
app.get('/api/admin/users', adminAuth, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT id, username, email, phone, balance, bonus_balance, is_disabled, created_at, last_login_at 
             FROM users ORDER BY created_at DESC`
        );
        res.json({ success: true, users: result.rows });
    } catch (error) {
        console.error('Admin get users error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Toggle user status (admin)
app.put('/api/admin/users/:id/toggle', adminAuth, async (req, res) => {
    try {
        const { id } = req.params;
        await pool.query('UPDATE users SET is_disabled = NOT is_disabled WHERE id = $1', [id]);
        
        // Log action
        await pool.query(
            `INSERT INTO admin_audit_logs (id, admin_identifier, action, target_user, created_at)
             VALUES ($1, 'admin', 'toggle_user_status', $2, NOW())`,
            [uuidv4(), id]
        );
        
        res.json({ success: true, message: 'User status updated' });
    } catch (error) {
        console.error('Toggle user error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Adjust user balance (admin)
app.put('/api/admin/users/:id/balance', adminAuth, async (req, res) => {
    try {
        const { id } = req.params;
        const { amount, type } = req.body; // type: 'add' or 'deduct'
        
        if (type === 'add') {
            await pool.query('UPDATE users SET balance = balance + $1 WHERE id = $2', [Math.abs(amount), id]);
        } else {
            await pool.query('UPDATE users SET balance = GREATEST(0, balance - $1) WHERE id = $2', [Math.abs(amount), id]);
        }
        
        // Create transaction record
        await pool.query(
            `INSERT INTO transactions (id, user_id, type, amount, status, external_provider, reference, created_at)
             VALUES ($1, $2, 'adjustment', $3, 'completed', 'manual', $4, NOW())`,
            [uuidv4(), id, type === 'add' ? amount : -amount, `ADJ-${Date.now()}`]
        );
        
        // Log action
        await pool.query(
            `INSERT INTO admin_audit_logs (id, admin_identifier, action, target_user, metadata, created_at)
             VALUES ($1, 'admin', 'balance_adjustment', $2, $3, NOW())`,
            [uuidv4(), id, JSON.stringify({ amount, type })]
        );
        
        res.json({ success: true, message: 'Balance updated' });
    } catch (error) {
        console.error('Adjust balance error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Get all transactions (admin)
app.get('/api/admin/transactions', adminAuth, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT t.id, t.type, t.amount, t.fee, t.status, t.phone, t.reference, t.created_at, u.username
             FROM transactions t 
             LEFT JOIN users u ON t.user_id = u.id 
             ORDER BY t.created_at DESC LIMIT 500`
        );
        res.json({ success: true, transactions: result.rows });
    } catch (error) {
        console.error('Admin get transactions error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Get deposit verifications (admin)
app.get('/api/admin/verifications', adminAuth, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT dv.id, dv.mpesa_code, dv.amount_claimed, dv.status, dv.submitted_at, u.username
             FROM deposit_verifications dv
             LEFT JOIN users u ON dv.user_id = u.id
             ORDER BY dv.submitted_at DESC`
        );
        res.json({ success: true, verifications: result.rows });
    } catch (error) {
        console.error('Admin get verifications error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Process verification (admin)
app.put('/api/admin/verifications/:id', adminAuth, async (req, res) => {
    try {
        const { id } = req.params;
        const { status, amount } = req.body; // status: 'validated' or 'rejected'
        
        const verificationResult = await pool.query(
            'SELECT user_id, amount_claimed FROM deposit_verifications WHERE id = $1',
            [id]
        );
        
        if (verificationResult.rows.length === 0) {
            return res.status(404).json({ success: false, message: 'Verification not found' });
        }
        
        const verification = verificationResult.rows[0];
        
        await pool.query(
            'UPDATE deposit_verifications SET status = $1, reviewed_by = $2 WHERE id = $3',
            [status, 'admin', id]
        );
        
        if (status === 'validated' && amount > 0) {
            // Credit user
            await pool.query('UPDATE users SET balance = balance + $1 WHERE id = $2', [amount, verification.user_id]);
            
            // Create transaction
            await pool.query(
                `INSERT INTO transactions (id, user_id, type, amount, status, external_provider, reference, created_at)
                 VALUES ($1, $2, 'deposit', $3, 'completed', 'manual', $4, NOW())`,
                [uuidv4(), verification.user_id, amount, `VERIFY-${Date.now()}`]
            );
        }
        
        res.json({ success: true, message: 'Verification processed' });
    } catch (error) {
        console.error('Process verification error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Set float status (admin)
app.put('/api/admin/float-status', adminAuth, async (req, res) => {
    try {
        const { isLow } = req.body;
        
        await pool.query(
            `INSERT INTO settings (key, value) VALUES ('float_low', $1)
             ON CONFLICT (key) DO UPDATE SET value = $1`,
            [isLow.toString()]
        );
        
        res.json({ success: true, message: 'Float status updated' });
    } catch (error) {
        console.error('Set float status error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Send system notification (admin)
app.post('/api/admin/notifications', adminAuth, async (req, res) => {
    try {
        const { title, message, userId } = req.body;
        
        await pool.query(
            `INSERT INTO notifications (id, user_id, scope, title, message, is_read, created_at)
             VALUES ($1, $2, $3, $4, $5, false, NOW())`,
            [uuidv4(), userId || null, userId ? 'user' : 'system', title, message]
        );
        
        res.json({ success: true, message: 'Notification sent' });
    } catch (error) {
        console.error('Send notification error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Get dashboard stats (admin)
app.get('/api/admin/stats', adminAuth, async (req, res) => {
    try {
        const users = await pool.query('SELECT COUNT(*) FROM users');
        const totalDeposits = await pool.query("SELECT COALESCE(SUM(amount), 0) as total FROM transactions WHERE type = 'deposit' AND status = 'completed'");
        const totalAirtime = await pool.query("SELECT COALESCE(SUM(amount), 0) as total FROM transactions WHERE type = 'airtime' AND status = 'completed'");
        const pendingVerifications = await pool.query("SELECT COUNT(*) FROM deposit_verifications WHERE status = 'pending'");
        
        res.json({
            success: true,
            stats: {
                totalUsers: parseInt(users.rows[0].count),
                totalDeposits: parseFloat(totalDeposits.rows[0].total),
                totalAirtime: parseFloat(totalAirtime.rows[0].total),
                pendingVerifications: parseInt(pendingVerifications.rows[0].count)
            }
        });
    } catch (error) {
        console.error('Get stats error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Admin logout
app.post('/api/admin/logout', (req, res) => {
    req.session.destroy();
    res.json({ success: true, message: 'Logged out' });
});

// ===================== AIRTIME TO CASH (Coming Soon) =====================

app.post('/api/airtime-to-cash/initiate', async (req, res) => {
    // Feature coming soon
    res.status(503).json({ 
        success: false, 
        message: 'Airtime to Cash feature coming soon!',
        comingSoon: true
    });
});

// ===================== HEALTH CHECK =====================

app.get('/api/health', (req, res) => {
    res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// ===================== STATIC FILES =====================

// Serve static files
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// ===================== START SERVER =====================

app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`Frontend origin: ${process.env.FRONTEND_ORIGIN || 'https://airtimetest.onrender.com'}`);
    console.log(`Callback URL: ${CALLBACK_BASE_URL}`);
});

// Handle graceful shutdown
process.on('SIGTERM', () => {
    console.log('SIGTERM received, shutting down gracefully');
    pool.end(() => {
        console.log('Database pool closed');
        process.exit(0);
    });
});
