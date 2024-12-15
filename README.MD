# Library Management Backend

## Description

A comprehensive backend application for a library management system built with Node.js, Express, and MongoDB. The application supports two types of users (Readers and Authors) with features like user authentication, book creation, borrowing, and returning books.

## Features

- User Authentication (Signup and Login)
- Role-based Access Control (Reader and Author roles)
- Book Creation for Authors
- Book Borrowing for Readers
- Book Search and Filtering
- JWT-based Authentication
- Password Hashing with bcrypt

## Technologies Used

- Node.js
- Express.js
- MongoDB
- Mongoose
- JSON Web Token (JWT)
- Bcrypt
- Dotenv (Environment Configuration)

## Prerequisites

- Node.js (v14 or later)
- MongoDB
- npm (Node Package Manager)

## Installation

1. Clone the repository
```bash
git clone <your-repo-url>
cd library-backend
```

2. Install dependencies
```bash
npm install
```

3. Set up environment variables
```bash
# Install dotenv
npm install dotenv
```

## Configuration

### Environment Variables

Create a `.env` file in the project root with the following variables:
```
MONGO_URL= <your_mongo_url>
JWT_SECRET= <your_very_secret_key>
```

### Applying Environment Variables

In your main application file:
```javascript
require('dotenv').config(); // Load environment variables

// Use environment variables
mongoose.connect(process.env.MONGO_URL, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

// JWT secret from environment
const generateToken = (userId) => {
  return jwt.sign({ userId }, process.env.JWT_SECRET, { expiresIn: '15d' });
};
```

### .gitignore

Ensure to add `.env` to your `.gitignore` file:
```
node_modules/
.env
```

## API Endpoints

### User Endpoints
- `POST /users/signup`: Register a new user
- `POST /users/login`: Authenticate user and get JWT token

### Book Endpoints
- `POST /books/create`: Create a new book (Authors only)
- `GET /books`: Search and list books
- `POST /reader/books/borrow`: Borrow a book (Readers only)
- `POST /reader/books/return`: Return a borrowed book

## Authentication

- Use the JWT token received during login in the `Authorization` header for protected routes
- Token expires in 15 days

## User Roles

### Reader
- Can borrow up to 5 books
- Can return books
- Cannot create books

### Author
- Can create books
- Cannot borrow books

## Running the Application

```bash
npm start
```

The server will run on `http://localhost:3000`

## Environment Variable Security

- Never commit `.env` files to version control
- Use `.env.example` with placeholder values for other developers
- Keep sensitive information like database credentials and secret keys confidential

## Security Features

- Environment-based configuration
- Password hashing with bcrypt
- JWT-based authentication
- Role-based access control
- Input validation

## Error Handling

The API returns appropriate HTTP status codes and error messages for various scenarios:
- 401: Unauthorized access
- 403: Forbidden (role-based access denied)
- 404: Resource not found
- 400: Bad request or validation error

## Future Improvements

- Add more comprehensive input validation
- Implement refresh tokens
- Add rate limiting
- Create more detailed error responses
- Implement proper environment-specific configurations
- Add logging mechanisms

