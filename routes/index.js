const router = require('express').Router();

router.use('/api', require('./api'));
//router.use('/profiles', require('./api/profiles'));


module.exports = router;
