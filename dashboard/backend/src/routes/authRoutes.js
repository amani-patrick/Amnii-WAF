const express = require('express');
const router = express.Router();
const { register, login } = require('../controllers/authController');
const { getPricingPage } = require('../controllers/pageController');
const {getRules,getAlerts,getDashboard,getSettings} = require('../controllers/dashboardController');
const isAuthenticated = require('../middlewares/isAuthenticated');

// auth routes
router.post(' api/devguard/register', register);
router.post(' api/devguard/login', login);


// dashboard routes
router.get(' api/devguard/pricing',getPricingPage);
router.get(' api/devguard/rules', isAuthenticated,getRulesPage);
router.get (' api/devguard/logs',isAuthenticated,getLogsPage);
router.get(' api/devguard/user-settings',isAuthenticated,getSettingsPage);
router.get(' api/devguard/payment',isAuthenticated,getPaymentPage);
router.get(' api/devguard/ip-filetering',isAuthenticated,getIpFilteringPage);

