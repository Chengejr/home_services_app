const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { check, validationResult } = require('express-validator');

const app = express();  // Initialize 'app' before using it

// Middleware
app.use(express.json());

// Dummy user storage (replace with a database in a real app)
const users = [];

// Register Route
app.post('/api/register', [
    check('email', 'Please include a valid email').isEmail(),
    check('password', 'Password must be 6 or more characters').isLength({ min: 6 })
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { email, password } = req.body;

    let user = users.find(user => user.email === email);
    if (user) {
        return res.status(400).json({ msg: 'User already exists' });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    user = { id: users.length + 1, email, password: hashedPassword };
    users.push(user);

    const payload = { user: { id: user.id } };
    jwt.sign(payload, 'secretToken', { expiresIn: '1h' }, (err, token) => {
        if (err) throw err;
        res.json({ token });
    });
});

// Login Route
app.post('/api/login', [
    check('email', 'Please include a valid email').isEmail(),
    check('password', 'Password is required').exists()
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { email, password } = req.body;

    const user = users.find(user => user.email === email);
    if (!user) {
        return res.status(400).json({ msg: 'Invalid Credentials' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
        return res.status(400).json({ msg: 'Invalid Credentials' });
    }

    const payload = { user: { id: user.id } };
    jwt.sign(payload, 'secretToken', { expiresIn: '1h' }, (err, token) => {
        if (err) throw err;
        res.json({ token });
    });
});

// Start the Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
