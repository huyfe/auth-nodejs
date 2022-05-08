const router = require('express').Router();
const User = require('../model/User');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { registerValidation, loginValidation } = require('../validation');

// REGISTER
router.post('/register', async (req, res) => {
    // Validation
    const { error } = registerValidation(req.body);
    if (error) {
        return res.status(400).send(error.details[0].message);
    }

    // Checking if the user is already in the database
    const emailExist = await User.findOne({ email: req.body.email });
    if (emailExist) {
        return res.status(400).send('Email already exists');
    }

    // Hash password
    const saltRound = 10;
    const salt = await bcrypt.genSalt(saltRound);
    const hashedPassword = await bcrypt.hash(req.body.password, salt);

    // Create a user belong User model
    const user = new User({
        name: req.body.name,
        email: req.body.email,
        password: hashedPassword
    });
    try {
        const savedUser = await user.save(); // Save register user into collection users
        res.send({ message: 'Registered successfully', user: user._id }); // Send to client message successfully
    }
    catch (err) {
        res.status(400).send(err); // Send to client error status and message
    }
});

// LOGIN
router.post('/login', async (req, res) => {
    // Validation
    const { error } = loginValidation(req.body);
    if (error) {
        return res.status(400).send(error.details[0].message);
    }

    // Checking if the email exists
    const user = await User.findOne({ email: req.body.email });
    if (!user) {
        return res.status(400).send('Email is not found');
    }

    // PASSWORD IS CORRECT
    const validPass = await bcrypt.compare(req.body.password, user.password);
    if (!validPass) {
        return res.status(400).send('Invalid password');
    }

    // Create and assign a token
    const payload = { _id: user._id };
    const secretKey = process.env.TOKEN_SECRET;
    const token = jwt.sign(payload, secretKey);
    res.header('auth-token', token);

    const userData = {
        id: user._id,
        name: user.name,
        avatar: user.avatar,
        isOnline: user.isOnline,
        token: user.token,
    }

    res.status(200).send({ message: 'Log in has been successfully', user: userData });
})


module.exports = router; // Export in order that index.js can use