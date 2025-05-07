const express = require('express');
const { register, login } = require('../controllers/authController');

const router = express.Router();

// Ruta para registrar un usuario
router.post('/register', register);

// Ruta para iniciar sesión
router.post('/login', login);

module.exports = router;