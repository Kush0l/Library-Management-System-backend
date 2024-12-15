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
   - Create a `.env` file in the root directory
   - Add your MongoDB connection string
   - Add your JWT secret key

## Configuration

### MongoDB Connection
Update the MongoDB connection string in the code:
```javascript
mongoose.connect('mongodb+srv://kushalrdev:kushalr.dev@cluster0.hko96.mongodb.net/library-backend', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});
```

### JWT Secret
Replace `'secretKey'` with a strong, unique secret key in the `generateToken` function.

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

## Security Features

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
- Add logging


