const express = require('express');
const router = express.Router();
const { landing } = require('../controllers/landing');

router.get('/', landing);

module.exports = router;
