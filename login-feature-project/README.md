# Login Feature Project

## Overview
This project implements a login feature using a MongoDB database. It provides user registration and authentication functionalities through a RESTful API built with Express.js.

## Project Structure
```
login-feature-project
├── src
│   ├── app.js
│   ├── config
│   │   └── db.js
│   ├── controllers
│   │   └── authController.js
│   ├── models
│   │   └── userModel.js
│   ├── routes
│   │   └── authRoutes.js
│   └── utils
│       └── hashPassword.js
├── package.json
├── .env
├── .gitignore
└── README.md
```

## Installation
1. Clone the repository:
   ```
   git clone <repository-url>
   ```
2. Navigate to the project directory:
   ```
   cd login-feature-project
   ```
3. Install the dependencies:
   ```
   npm install
   ```

## Configuration
1. Create a `.env` file in the root directory and add your MongoDB connection string:
   ```
   MONGODB_URI=<your_mongodb_connection_string>
   ```

## Usage
1. Start the application:
   ```
   npm start
   ```
2. The server will run on `http://localhost:3000`.

## API Endpoints
- **POST /register**: Register a new user.
- **POST /login**: Authenticate an existing user.

## Dependencies
- Express: Web framework for Node.js
- Mongoose: MongoDB object modeling tool
- Bcrypt: Password hashing library
- Dotenv: Module to load environment variables from a `.env` file

## License
This project is licensed under the MIT License.