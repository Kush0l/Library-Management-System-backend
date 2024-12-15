// Import necessary modules
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
require('dotenv').config();

// Initialize Express app
const app = express();
app.use(bodyParser.json());

// MongoDB connection
mongoose.connect(process.env.MONGO_URL, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const db = mongoose.connection;
db.on('error', console.error.bind(console, 'connection error:'));
db.once('open', () => {
  console.log('Connected to MongoDB');
});

// Define Schemas and Models
const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
  role: { type: String, enum: ['Reader', 'Author'], required: true },
  borrowedBooks: [String], // For Readers
  booksWritten: [String], // For Authors
});

const bookSchema = new mongoose.Schema({
  title: String,
  author: String,
  genre: String,
  stock: Number,
});

const User = mongoose.model('User', userSchema);
const Book = mongoose.model('Book', bookSchema);

// Utility functions
const generateToken = (userId) => {
  return jwt.sign({ userId }, process.env.JWT_SECRET, { expiresIn: '15d' });
};

// Middleware for authentication
const authenticate = (req, res, next) => {
  const token = req.headers['authorization'];
  if (!token) return res.status(401).send('Access Denied');

  try {
    const verified = jwt.verify(token, process.env.JWT_SECRET);
    req.user = verified;
    next();
  } catch (error) {
    res.status(400).send('Invalid Token');
  }
};

// API Endpoints

// User Signup
app.post('/users/signup', async (req, res) => {
  const { name, email, password, role } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);

  const user = new User({
    name,
    email,
    password: hashedPassword,
    role,
    borrowedBooks: [],
    booksWritten: [],
  });

  try {
    const savedUser = await user.save();
    res.status(201).send(savedUser);
  } catch (error) {
    res.status(400).send(error);
  }
});

// User Login
app.post('/users/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(404).send('User not found');

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.status(400).send('Invalid credentials');

    const token = generateToken(user._id);
    res.status(200).send({ token });
  } catch (error) {
    res.status(400).send(error);
  }
});

// Add a Book (Authors only)
app.post('/books/create', authenticate, async (req, res) => {
  const { title, genre, stock } = req.body;

  try {
    const user = await User.findById(req.user.userId);
    if (user.role !== 'Author') return res.status(403).send('Access denied');

    const book = new Book({ title, author: user.name, genre, stock });
    const savedBook = await book.save();

    user.booksWritten.push(savedBook._id);
    await user.save();

    res.status(201).send(savedBook);
  } catch (error) {
    res.status(400).send(error);
  }
});

// Get All Books or Search
app.get('/books', async (req, res) => {
  const { title, author, genre } = req.query;

  try {
    const query = {};
    if (title) query.title = title;
    if (author) query.author = author;
    if (genre) query.genre = genre;

    const books = await Book.find(query);
    res.status(200).send(books);
  } catch (error) {
    res.status(400).send(error);
  }
});

// Borrow a Book (Readers only)
app.post('/reader/books/borrow', authenticate, async (req, res) => {
  const { bookId } = req.body;

  try {
    const user = await User.findById(req.user.userId);
    if (user.role !== 'Reader') return res.status(403).send('Access denied');
    if (user.borrowedBooks.length >= 5) return res.status(400).send('Borrowing limit reached');

    const book = await Book.findById(bookId);
    if (!book || book.stock <= 0) return res.status(404).send('Book not available');

    book.stock -= 1;
    user.borrowedBooks.push(bookId);

    await book.save();
    await user.save();

    res.status(200).send('Book borrowed successfully');
  } catch (error) {
    res.status(400).send(error);
  }
});

// Return a Book
app.post('/reader/books/return', authenticate, async (req, res) => {
  const { bookId } = req.body;

  try {
    const user = await User.findById(req.user.userId);
    const bookIndex = user.borrowedBooks.indexOf(bookId);
    if (bookIndex === -1) return res.status(404).send('Book not found in borrowed list');

    const book = await Book.findById(bookId);
    book.stock += 1;
    user.borrowedBooks.splice(bookIndex, 1);

    await book.save();
    await user.save();

    res.status(200).send('Book returned successfully');
  } catch (error) {
    res.status(400).send(error);
  }
});

// Start the Server
const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
