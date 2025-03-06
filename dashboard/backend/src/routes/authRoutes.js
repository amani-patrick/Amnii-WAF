const express = require('express');
const router = express.Router();
const { register, login } = require('../controllers/authController');
const { getPricingPage } = require('../controllers/pageController');
const {getRules,getAlerts,getDashboard,getSettings} = require('../controllers/dashboardController');
router.post('/register', register);
router.post('/login', login);
router.get('/pricing', getPricingPage);
router.get('/rules', getRulesPage);

