import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import compression from 'compression';
import bodyParser from 'body-parser';
import multer from 'multer';
import path from 'path';
import { fileURLToPath } from 'url';
import { sql } from './config/db.js';
import rateLimiter from './middleware/rateLimiter.js';
import { AIService } from './services/AIService.js';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import nodemailer from 'nodemailer';
import 'dotenv/config';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 5001;

// Middleware
app.use(helmet());
app.use(compression());
app.use(cors({
  origin: ['http://localhost:3000', 'http://localhost:3001'],
  credentials: true
}));
app.use(bodyParser.json({ limit: '50mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '50mb' }));
app.use(rateLimiter);

// File upload configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    cb(null, `${Date.now()}-${file.originalname}`);
  }
});
const upload = multer({ storage });

// Email configuration
const transporter = nodemailer.createTransporter({
  host: process.env.MAILERSEND_SMTP_HOST,
  port: process.env.MAILERSEND_SMTP_PORT,
  secure: false,
  auth: {
    user: process.env.MAILERSEND_SMTP_USER,
    pass: process.env.MAILERSEND_SMTP_PASS
  }
});

// Helper functions
const generateOTP = () => Math.floor(100000 + Math.random() * 900000).toString();

const sendOTP = async (phoneNumber, otp) => {
  // Mock OTP sending - replace with actual SMS service
  console.log(`Sending OTP ${otp} to ${phoneNumber}`);
  return true;
};

// Database initialization
const initializeDatabase = async () => {
  try {
    // Create users table
    await sql`
      CREATE TABLE IF NOT EXISTS users (
        id VARCHAR(255) PRIMARY KEY,
        full_name VARCHAR(255) NOT NULL,
        aadhaar_number VARCHAR(12) UNIQUE NOT NULL,
        phone_number VARCHAR(15) NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        address TEXT NOT NULL,
        role VARCHAR(20) DEFAULT 'USER',
        password_hash VARCHAR(255),
        is_verified BOOLEAN DEFAULT FALSE,
        otp VARCHAR(6),
        otp_expires_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `;

    // Create reports table
    await sql`
      CREATE TABLE IF NOT EXISTS reports (
        id VARCHAR(255) PRIMARY KEY,
        user_id VARCHAR(255) REFERENCES users(id),
        category VARCHAR(100) NOT NULL,
        subcategory VARCHAR(100),
        description TEXT NOT NULL,
        location VARCHAR(255),
        anonymous BOOLEAN DEFAULT FALSE,
        status VARCHAR(50) DEFAULT 'pending',
        priority VARCHAR(20) DEFAULT 'medium',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `;

    // Create suspicious_entities table
    await sql`
      CREATE TABLE IF NOT EXISTS suspicious_entities (
        id VARCHAR(255) PRIMARY KEY,
        user_id VARCHAR(255) REFERENCES users(id),
        entity_type VARCHAR(50) NOT NULL,
        entity_value VARCHAR(255) NOT NULL,
        description TEXT NOT NULL,
        status VARCHAR(50) DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `;

    // Create data_requests table
    await sql`
      CREATE TABLE IF NOT EXISTS data_requests (
        id VARCHAR(255) PRIMARY KEY,
        officer_id VARCHAR(255) REFERENCES users(id),
        request_type VARCHAR(100) NOT NULL,
        target_entity VARCHAR(255) NOT NULL,
        justification TEXT NOT NULL,
        urgency VARCHAR(20) DEFAULT 'medium',
        status VARCHAR(50) DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `;

    console.log('Database tables initialized successfully');
  } catch (error) {
    console.error('Database initialization error:', error);
  }
};

// Routes

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// Auth routes
app.post('/api/auth/register', async (req, res) => {
  try {
    const { full_name, aadhaar_number, phone_number, email, address, role = 'USER' } = req.body;

    // Validate required fields
    if (!full_name || !aadhaar_number || !phone_number || !email || !address) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    // Check if user already exists
    const existingUser = await sql`
      SELECT id FROM users 
      WHERE aadhaar_number = ${aadhaar_number} OR email = ${email} OR phone_number = ${phone_number}
    `;

    if (existingUser.length > 0) {
      return res.status(409).json({ error: 'User already exists with this Aadhaar, email, or phone number' });
    }

    // Generate user ID and OTP
    const userId = uuidv4();
    const otp = generateOTP();
    const otpExpiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

    // Insert user
    await sql`
      INSERT INTO users (id, full_name, aadhaar_number, phone_number, email, address, role, otp, otp_expires_at)
      VALUES (${userId}, ${full_name}, ${aadhaar_number}, ${phone_number}, ${email}, ${address}, ${role}, ${otp}, ${otpExpiresAt})
    `;

    // Send OTP
    await sendOTP(phone_number, otp);

    res.status(201).json({
      message: 'User registered successfully. OTP sent for verification.',
      user_id: userId
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Registration failed' });
  }
});

app.post('/api/auth/verify-otp', async (req, res) => {
  try {
    const { user_id, otp, password } = req.body;

    if (!user_id || !otp || !password) {
      return res.status(400).json({ error: 'User ID, OTP, and password are required' });
    }

    // Find user and verify OTP
    const user = await sql`
      SELECT * FROM users WHERE id = ${user_id} AND otp = ${otp} AND otp_expires_at > NOW()
    `;

    if (user.length === 0) {
      return res.status(400).json({ error: 'Invalid or expired OTP' });
    }

    // Hash password and update user
    const passwordHash = await bcrypt.hash(password, 10);
    await sql`
      UPDATE users 
      SET password_hash = ${passwordHash}, is_verified = TRUE, otp = NULL, otp_expires_at = NULL
      WHERE id = ${user_id}
    `;

    res.json({ message: 'Account verified successfully' });
  } catch (error) {
    console.error('OTP verification error:', error);
    res.status(500).json({ error: 'OTP verification failed' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { user_id, password } = req.body;

    if (!user_id || !password) {
      return res.status(400).json({ error: 'User ID and password are required' });
    }

    // Find user
    const user = await sql`
      SELECT * FROM users WHERE id = ${user_id} AND is_verified = TRUE
    `;

    if (user.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Verify password
    const isValidPassword = await bcrypt.compare(password, user[0].password_hash);
    if (!isValidPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Generate OTP for login verification
    const otp = generateOTP();
    const otpExpiresAt = new Date(Date.now() + 10 * 60 * 1000);

    await sql`
      UPDATE users SET otp = ${otp}, otp_expires_at = ${otpExpiresAt} WHERE id = ${user_id}
    `;

    // Send OTP
    await sendOTP(user[0].phone_number, otp);

    res.json({ message: 'OTP sent for login verification' });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

app.post('/api/auth/login-verify', async (req, res) => {
  try {
    const { user_id, otp } = req.body;

    if (!user_id || !otp) {
      return res.status(400).json({ error: 'User ID and OTP are required' });
    }

    // Verify OTP
    const user = await sql`
      SELECT * FROM users WHERE id = ${user_id} AND otp = ${otp} AND otp_expires_at > NOW()
    `;

    if (user.length === 0) {
      return res.status(400).json({ error: 'Invalid or expired OTP' });
    }

    // Clear OTP and generate JWT
    await sql`
      UPDATE users SET otp = NULL, otp_expires_at = NULL WHERE id = ${user_id}
    `;

    const token = jwt.sign(
      { userId: user[0].id, role: user[0].role },
      process.env.JWT_SECRET || 'fallback-secret',
      { expiresIn: '24h' }
    );

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user[0].id,
        full_name: user[0].full_name,
        email: user[0].email,
        phone_number: user[0].phone_number,
        role: user[0].role,
        aadhaar_number: user[0].aadhaar_number,
        address: user[0].address
      }
    });
  } catch (error) {
    console.error('Login verification error:', error);
    res.status(500).json({ error: 'Login verification failed' });
  }
});

// User routes
app.get('/api/user/:userID', async (req, res) => {
  try {
    const { userID } = req.params;
    
    const user = await sql`
      SELECT id, full_name, email, phone_number, role, aadhaar_number, address, created_at
      FROM users WHERE id = ${userID}
    `;

    if (user.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json(user[0]);
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({ error: 'Failed to fetch user' });
  }
});

app.patch('/api/user/:userID/profile', async (req, res) => {
  try {
    const { userID } = req.params;
    const { full_name, email, phone_number, address } = req.body;

    await sql`
      UPDATE users 
      SET full_name = ${full_name}, email = ${email}, phone_number = ${phone_number}, 
          address = ${address}, updated_at = CURRENT_TIMESTAMP
      WHERE id = ${userID}
    `;

    res.json({ message: 'Profile updated successfully' });
  } catch (error) {
    console.error('Update profile error:', error);
    res.status(500).json({ error: 'Failed to update profile' });
  }
});

app.post('/api/user/:userID/report_grievance', upload.array('evidence'), async (req, res) => {
  try {
    const { userID } = req.params;
    const { category, subcategory, description, location, anonymous } = req.body;

    const reportId = uuidv4();
    
    await sql`
      INSERT INTO reports (id, user_id, category, subcategory, description, location, anonymous)
      VALUES (${reportId}, ${userID}, ${category}, ${subcategory}, ${description}, ${location}, ${anonymous === 'true'})
    `;

    res.status(201).json({
      message: 'Grievance reported successfully',
      report_id: reportId
    });
  } catch (error) {
    console.error('Report grievance error:', error);
    res.status(500).json({ error: 'Failed to submit grievance' });
  }
});

app.post('/api/user/:userID/report_suspicious', upload.array('evidence'), async (req, res) => {
  try {
    const { userID } = req.params;
    const { entity_type, entity_value, description } = req.body;

    const entityId = uuidv4();
    
    await sql`
      INSERT INTO suspicious_entities (id, user_id, entity_type, entity_value, description)
      VALUES (${entityId}, ${userID}, ${entity_type}, ${entity_value}, ${description})
    `;

    res.status(201).json({
      message: 'Suspicious entity reported successfully',
      entity_id: entityId
    });
  } catch (error) {
    console.error('Report suspicious error:', error);
    res.status(500).json({ error: 'Failed to report suspicious entity' });
  }
});

// Reports routes
app.get('/api/reports', async (req, res) => {
  try {
    const { status, category, limit = 50 } = req.query;
    
    let query = sql`SELECT * FROM reports WHERE 1=1`;
    
    if (status) {
      query = sql`SELECT * FROM reports WHERE status = ${status}`;
    }
    
    const reports = await query;
    res.json(reports);
  } catch (error) {
    console.error('Get reports error:', error);
    res.status(500).json({ error: 'Failed to fetch reports' });
  }
});

// AI routes
app.post('/api/ai/analyze-complaint', async (req, res) => {
  try {
    const result = await AIService.analyzeComplaint(req.body);
    res.json(result);
  } catch (error) {
    console.error('AI analysis error:', error);
    res.status(500).json({ error: 'AI analysis failed' });
  }
});

app.post('/api/ai/check-similarity-advanced', async (req, res) => {
  try {
    const result = await AIService.checkDatabaseSimilarity(req.body);
    res.json(result);
  } catch (error) {
    console.error('Similarity check error:', error);
    res.status(500).json({ error: 'Similarity check failed' });
  }
});

app.post('/api/ai/chat-enhanced', async (req, res) => {
  try {
    const { query } = req.body;
    const result = await AIService.getChatbotResponse(query);
    res.json(result);
  } catch (error) {
    console.error('Chat error:', error);
    res.status(500).json({ error: 'Chat request failed' });
  }
});

app.post('/api/ai/analyze-audio', upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No audio file provided' });
    }
    
    const result = await AIService.analyzeAudioFile({ audio_file_path: req.file.path });
    res.json(result);
  } catch (error) {
    console.error('Audio analysis error:', error);
    res.status(500).json({ error: 'Audio analysis failed' });
  }
});

app.post('/api/ai/analyze-video', upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No video file provided' });
    }
    
    const result = await AIService.analyzeVideoFile({ video_file_path: req.file.path });
    res.json(result);
  } catch (error) {
    console.error('Video analysis error:', error);
    res.status(500).json({ error: 'Video analysis failed' });
  }
});

app.post('/api/ai/analyze-image', upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No image file provided' });
    }
    
    const result = await AIService.analyzeImageFile({ image_file_path: req.file.path });
    res.json(result);
  } catch (error) {
    console.error('Image analysis error:', error);
    res.status(500).json({ error: 'Image analysis failed' });
  }
});

app.post('/api/ai/analyze-pdf', upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No PDF file provided' });
    }
    
    const result = await AIService.analyzePdfFile({ pdf_file_path: req.file.path });
    res.json(result);
  } catch (error) {
    console.error('PDF analysis error:', error);
    res.status(500).json({ error: 'PDF analysis failed' });
  }
});

app.post('/api/ai/detect-call-scam', upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No audio file provided' });
    }
    
    const { language = 'en' } = req.body;
    const result = await AIService.detectCallScam({
      audio_file_path: req.file.path,
      language
    });
    res.json(result);
  } catch (error) {
    console.error('Call scam detection error:', error);
    res.status(500).json({ error: 'Call scam detection failed' });
  }
});

app.post('/api/ai/complete-analysis', async (req, res) => {
  try {
    const result = await AIService.completeAnalysis(req.body);
    res.json(result);
  } catch (error) {
    console.error('Complete analysis error:', error);
    res.status(500).json({ error: 'Complete analysis failed' });
  }
});

app.post('/api/ai/contradiction', async (req, res) => {
  try {
    const result = await AIService.findContradictions(req.body);
    res.json(result);
  } catch (error) {
    console.error('Contradiction analysis error:', error);
    res.status(500).json({ error: 'Contradiction analysis failed' });
  }
});

// Officer routes
app.post('/api/officer/login', async (req, res) => {
  try {
    const { user_id, password } = req.body;

    const user = await sql`
      SELECT * FROM users WHERE id = ${user_id} AND role = 'OFFICER' AND is_verified = TRUE
    `;

    if (user.length === 0) {
      return res.status(401).json({ error: 'Invalid officer credentials' });
    }

    const isValidPassword = await bcrypt.compare(password, user[0].password_hash);
    if (!isValidPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { userId: user[0].id, role: user[0].role },
      process.env.JWT_SECRET || 'fallback-secret',
      { expiresIn: '24h' }
    );

    res.json({
      message: 'Officer login successful',
      token,
      user: {
        id: user[0].id,
        full_name: user[0].full_name,
        email: user[0].email,
        role: user[0].role
      }
    });
  } catch (error) {
    console.error('Officer login error:', error);
    res.status(500).json({ error: 'Officer login failed' });
  }
});

app.post('/api/data-request', async (req, res) => {
  try {
    const { request_type, target_entity, justification, urgency = 'medium' } = req.body;
    
    const requestId = uuidv4();
    
    await sql`
      INSERT INTO data_requests (id, request_type, target_entity, justification, urgency)
      VALUES (${requestId}, ${request_type}, ${target_entity}, ${justification}, ${urgency})
    `;

    res.status(201).json({
      message: 'Data request created successfully',
      request_id: requestId
    });
  } catch (error) {
    console.error('Data request error:', error);
    res.status(500).json({ error: 'Failed to create data request' });
  }
});

app.get('/api/data-requests', async (req, res) => {
  try {
    const requests = await sql`
      SELECT * FROM data_requests ORDER BY created_at DESC
    `;
    res.json(requests);
  } catch (error) {
    console.error('Get data requests error:', error);
    res.status(500).json({ error: 'Failed to fetch data requests' });
  }
});

// Meta routes
app.get('/api/meta/complaint-categories', (req, res) => {
  res.json([
    {
      id: 'financial',
      name: 'Financial Fraud',
      subcategories: [
        { id: 'upi_fraud', name: 'UPI Fraud' },
        { id: 'credit_card', name: 'Credit Card Fraud' },
        { id: 'investment_scam', name: 'Investment Scam' },
      ],
    },
    {
      id: 'identity',
      name: 'Identity Theft',
      subcategories: [
        { id: 'aadhaar_misuse', name: 'Aadhaar Misuse' },
        { id: 'social_media', name: 'Social Media Impersonation' },
      ],
    },
    {
      id: 'cyber_bullying',
      name: 'Cyber Bullying',
      subcategories: [
        { id: 'harassment', name: 'Online Harassment' },
        { id: 'stalking', name: 'Cyber Stalking' },
      ],
    },
  ]);
});

app.get('/api/meta/suspicious-entity-types', (req, res) => {
  res.json([
    { id: 'phone', name: 'Phone Number', placeholder: 'e.g., +91 9876543210' },
    { id: 'email', name: 'Email Address', placeholder: 'e.g., scammer@example.com' },
    { id: 'website', name: 'Website/URL', placeholder: 'e.g., https://suspicious-site.com' },
    { id: 'upi', name: 'UPI ID', placeholder: 'e.g., scammer@paytm' },
    { id: 'bank_account', name: 'Bank Account', placeholder: 'e.g., 1234567890' },
    { id: 'social_media', name: 'Social Media Profile', placeholder: 'e.g., @suspicious_user' },
    { id: 'crypto_wallet', name: 'Crypto Wallet', placeholder: 'e.g., 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa' },
  ]);
});

// Admin routes
app.get('/api/admin/dashboard', async (req, res) => {
  try {
    const totalReports = await sql`SELECT COUNT(*) as count FROM reports`;
    const pendingReports = await sql`SELECT COUNT(*) as count FROM reports WHERE status = 'pending'`;
    const resolvedReports = await sql`SELECT COUNT(*) as count FROM reports WHERE status = 'resolved'`;
    
    res.json({
      total_reports: totalReports[0].count,
      pending_reports: pendingReports[0].count,
      resolved_reports: resolvedReports[0].count,
      active_investigations: pendingReports[0].count,
      threats_neutralized: resolvedReports[0].count
    });
  } catch (error) {
    console.error('Dashboard error:', error);
    res.status(500).json({ error: 'Failed to fetch dashboard data' });
  }
});

// Analytics route
app.get('/api/collect', (req, res) => {
  // Mock analytics collection
  res.json({ status: 'collected' });
});

// Error handling middleware
app.use((error, req, res, next) => {
  console.error('Server error:', error);
  res.status(500).json({ error: 'Internal server error' });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

// Start server
const startServer = async () => {
  try {
    await initializeDatabase();
    
    app.listen(PORT, () => {
      console.log(`🚀 Server running on http://localhost:${PORT}`);
      console.log(`📊 Health check: http://localhost:${PORT}/health`);
      console.log(`🤖 AI docs: http://localhost:${PORT}/api/ai/docs`);
    });
  } catch (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
};

startServer();