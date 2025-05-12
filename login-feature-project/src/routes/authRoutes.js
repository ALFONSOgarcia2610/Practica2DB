const express = require('express');
const { register, login, changePassword } = require('../controllers/authController');
const verifyToken = require('../middleware/verifyToken');

const router = express.Router();

// Ruta para registrar un usuario
router.post('/register', register);

// Ruta para iniciar sesión
router.post('/login', login);

router.post('/changePassword', verifyToken, changePassword);


module.exports = router;