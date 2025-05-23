const express = require('express'); 
const userController = require('../Controller/userController'); 
const router = express.Router(); 

router.post("/login", userController.login);
router.post("/register", userController.register);
router.post('/forgot-password', userController.forgotPassword);
router.post('/reset-password', userController.resetPassword);

module.exports = router; 
