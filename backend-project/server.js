const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const nodemailer = require('nodemailer');  // Add Nodemailer for sending emails
const User = require('./models/User');  // Ensure the User model is imported
const authenticateToken = require('./middlewares/auth'); // Import the middleware

const app = express();
const port = 8080;

app.use(express.json());
app.use(cors());

// MongoDB connection
const mongoURI = process.env.MONGO_URI || 'mongodb://localhost:27017/mydatabase';  // Ensure this is defined

mongoose.connect(mongoURI)
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB connection error:', err));

// Configure Nodemailer
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'xujianqiao86@gmail.com', // Your email
    pass: 'opco kaqp peqj enf' // Your app-specific password
  }
});
// Debugging the transporter setup
transporter.verify((error, success) => {
  if (error) {
    console.log('Error with email transporter:', error);
  } else {
    console.log('Email transporter is ready to send emails');
  }
});
// Registration route with email verification
app.post('/register', async (req, res) => {
  const { username, email, password } = req.body;

  if (!username || !email || !password) {
    return res.status(400).json({ message: 'Please enter all fields' });
  }

  const existingUser = await User.findOne({ email });
  if (existingUser) {
    return res.status(400).json({ message: 'User already exists' });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const newUser = new User({ username, email, password: hashedPassword });

  // Generate email verification token
  const verificationToken = crypto.randomBytes(32).toString('hex');
  newUser.verificationToken = verificationToken;
  newUser.isVerified = false; // User is not verified yet

  await newUser.save();

  // Send verification email
  const verificationLink = `http://localhost:8080/verify-email/${verificationToken}`;
  const mailOptions = {
    from: 'your-email@gmail.com',
    to: email,
    subject: 'Email Verification',
    text: `Please verify your email by clicking on the following link: ${verificationLink}`
  };

  transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      console.error('Error sending email:', error);
      return res.status(500).json({ message: 'Error sending verification email' });
    } else {
      console.log('Verification email sent:', info.response);
      res.status(201).json({ message: 'User registered successfully. Please verify your email.' });
    }
  });
});

// Email verification route
app.get('/verify-email/:token', async (req, res) => {
  const { token } = req.params;

  try {
    const user = await User.findOne({ verificationToken: token });
    if (!user) {
      return res.status(400).json({ message: 'Invalid or expired token' });
    }

    user.isVerified = true;
    user.verificationToken = null;  // Clear the token after verification
    await user.save();

    res.status(200).json({ message: 'Email verified successfully' });
  } catch (error) {
    console.error('Error verifying email:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Login route (only verified users can log in)
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: 'Please enter all fields' });
  }

  const user = await User.findOne({ email });
  if (!user) {
    return res.status(400).json({ message: 'Invalid credentials' });
  }

  if (!user.isVerified) {
    return res.status(400).json({ message: 'Please verify your email first' });
  }

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) {
    return res.status(400).json({ message: 'Invalid credentials' });
  }

  const token = jwt.sign({ id: user._id, username: user.username }, 'yourSecretKey', { expiresIn: '1h' });
  res.status(200).json({ token });
});

// Profile route (protected)
app.get('/profile', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.json(user);
  } catch (err) {
    console.error('Error fetching profile:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Route to request password reset
app.post('/request-reset-password', async (req, res) => {
  const { email } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const resetToken = crypto.randomBytes(32).toString('hex');
    user.resetPasswordToken = resetToken;
    user.resetPasswordExpires = Date.now() + 3600000; // Token expires in 1 hour

    await user.save();

    const resetLink = `http://localhost:8080/reset-password/${resetToken}`;
    console.log(`Password reset link: ${resetLink}`);
    res.status(200).json({ message: 'Password reset link has been sent to your email' });
  } catch (error) {
    console.error('Error requesting password reset:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Route to reset password
app.post('/reset-password/:token', async (req, res) => {
  const { token } = req.params;
  const { password } = req.body;

  try {
    const user = await User.findOne({
      resetPasswordToken: token,
      resetPasswordExpires: { $gt: Date.now() },
    });

    if (!user) {
      return res.status(400).json({ message: 'Invalid or expired token' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    user.password = hashedPassword;
    user.resetPasswordToken = null;
    user.resetPasswordExpires = null;

    await user.save();
    res.status(200).json({ message: 'Password has been reset successfully' });
  } catch (error) {
    console.error('Error resetting password:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Start the server
app.listen(port, '0.0.0.0', () => {
  console.log(`Server is running on port ${port}`);
});
