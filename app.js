const express = require('express');
const app = express();
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
dotenv.config();
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser')
const User = require('./models/userSChema');

app.use(express.json());

const URI = 'mongodb://localhost:27017/user';

mongoose.connect(URI)
.then((conn) => {
    console.log(`Database Connected: ${conn.connection.host}`);
    app.listen(3000, () => {
        console.log('Server listening on port 3000');
    })
})
.catch((err) => {
    console.log(err);
})

app.post('/register', async (req, res) => {
    const {email, username, password} = req.body;
    try {
        const existingUser = await User.findOne({email})
        if(existingUser) {
            return res.sendStatus(400)
        }
        const hashedPassword = await bcrypt.hash(password, 13);

        const user = new User({
            username,
            email,
            password: hashedPassword
        })

        await user.save();
        res.status(201).json(user);


    } catch (err) {
        console.log(err);
        res.sendStatus(404);
    }
})


app.post('/login',async (req, res) => {
    try {
        const {username, password} = req.body;
        const existingUser = await User.findOne({username});
        if (!existingUser) {
            return res.status(401).json({error: "Invalid username"})
        }

        const same = await bcrypt.compare(password, existingUser.password);
        if (!same) {
            return res.status(401).json({error: "Invalid Password"})
        }

        const accessToken = jwt.sign({username: existingUser.username}, process.env.ACCESS_TOKEN_SECRET, {expiresIn: '45s'});
        const refreshToken = jwt.sign({username: existingUser.username}, process.env.REFRESH_TOKEN_SECRET);

        existingUser.refreshToken = refreshToken;

        await existingUser.save();

        res.status(201).json({accessToken, refreshToken});

    } catch (err) {
        console.log(err);
        res.sendStatus(404);
    }
    
})



app.post('/token', async (req, res) => {
    try {
        const {token} = req.body;
        if (!token) {
            return res.sendStatus(401);
        }

        const user = await User.findOne({refreshToken: token});
        if (!user) {
            return res.sendStatus(403);
        }

        jwt.verify(token, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
            if(err) {
                return res.sendStatus(403);
            }
            const accessToken = jwt.sign({ username: user.username }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '45s' });
            res.json({ accessToken });
        })

    } catch (err) {
        console.log(err);
        res.sendStatus(404);
    }
})

app.get('/users', authenticateToken, async (req, res) => {
    const users = await User.find();
    res.json(users);
})



function authenticateToken (req, res, next)  {
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(' ')[1]
    if (token == null){
        return res.sendStatus(401)
    } 
    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
        if(err) {
            return res.sendStatus(403)
        }
        req.user = user
        next()
    })
}










