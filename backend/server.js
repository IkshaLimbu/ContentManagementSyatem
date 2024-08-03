const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const db = require('./models');
const { VIRTUAL } = require('sequelize');
const Post = db.Post;
const Users = db.Users;

require('dotenv').config();
const secret = process.env.JWSTOKEN; // Use your actual secret key
console.log('JWT Secret Key:', secret);

const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(cors({
    origin: ['http://localhost:3000'],
    methods: ['POST', 'GET', 'DELETE', 'PUT'],
    credentials: true
}));

const createAdmin = async () => {
    try {
        const adminExists = await Users.findOne({ where: { email: 'admin@example.com' } });
        if (!adminExists) {
            const saltRounds = 10;
            const hashedPassword = await bcrypt.hash('admin_password', saltRounds);
            await Users.create({
                name: 'admin',
                email: 'admin@example.com',
                password: hashedPassword,
                type: 'admin'
            });
            console.log('Admin user created.');
        }
    } catch (error) {
        console.error('Error creating admin user:', error);
    }
};


const vreifyUser = (req, res, next) => {

    const token = req.cookies.token || req.headers.authorization?.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'No token provided' });
    }

    jwt.verify(token, secret, async (err, decoded) => {
        if (err) {
            return res.status(401).json({ error: 'Invalid token' });
        }

        // Fetch user from database
        try {
            console.log("decoded id in verify user middleware", decoded.id)
            const user = await Users.findByPk(decoded.id);
            if (!user) {
                return res.status(404).json({ error: 'User not found' });
            }

            // Attach user information to request
            req.user = {
                id: user.id,
                type: user.type
            };
            console.log(req.user)
            next();
        } catch (err) {
            console.error('Error fetching user:', err);
            return res.status(500).json({ error: 'Internal server error' });
        }
    });
};



const testToken = jwt.sign({ id: 1, name: 'testUser', type: 'user' }, secret, { expiresIn: '1d' });

jwt.verify(testToken, secret, (err, decoded) => {
    if (err) {
        console.error('Test token verification error:', err);
    } else {
        console.log('Test token decoded:', decoded); // Should print { id: 1, name: 'testUser', type: 'user', iat: <timestamp>, exp: <timestamp> }
    }
});



app.get('/', async (req, res) => {
    //const token = req.cookies.token;
    const token = req.cookies.token || req.headers.authorization?.split(' ')[1];
    console.log("Token from cookies:", token); // Debugging line to check token in cookies
    if (!token) {
        return res.status(401).json({ Error: "Unauthorized" });
    }

    jwt.verify(token, secret, async (err, decoded) => {
        if (err) {
            return res.status(401).json({ Error: "Unauthorized" });
        }
        console.log("Decoded payload:", decoded); // Debugging line

        const user = await Users.findOne({ where: { name: decoded.name } });
        if (user) {
            try {
                let posts;
                if (user.type === 'admin') {
                    console.log(`Fetching all posts for admin user ID: ${user.id}`);
                    posts = await Post.findAll();
                } else {
                    console.log(`Fetching posts for user ID: ${user.id}`);
                    posts = await Post.findAll({ where: { userId: user.id } });
                }
                console.log(`Posts fetched: ${JSON.stringify(posts)}`);
                return res.json({
                    Status: "Success",
                    userType: user.type,
                    name: user.name,
                    posts: posts
                });
            } catch (err) {
                console.error("Error fetching posts:", err);
                return res.status(500).json({ Error: "Error fetching posts" });
            }
        } else {
            return res.status(404).json({ Error: "User not found" });
        }
    });
});



app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    const users = await Users.findOne({ where: { email: email } });

    if (users === null) {
        return res.status(500).json({ error: "Cannot find the email" });
    }

    const isMatch = await bcrypt.compare(password, users.password);
    if (!isMatch) {
        return res.status(401).json({ Error: "Password not matched" });
    }

    const name = users.name;
    // const token = jwt.sign({ name }, secret, { expiresIn: '1d' });
    const token = jwt.sign({ id: users.id, name: users.name, type: users.type }, secret, { expiresIn: '1d' });
    console.log('Generated Token:', token);

    res.cookie('token', token, { httpOnly: true, maxAge: 24 * 60 * 60 * 1000, secure: false });
    console.log('Cookie Set:', res.getHeader('Set-Cookie')); // Debugging line
    const posts = await Post.findAll({ where: { userId: users.id } });  // Ensure posts are fetched correctly here

    return res.json({ Status: "Success", userType: users.type, name: users.name, posts: posts, token: token });
});

// Add more routes and middleware as needed

app.post('/register', (req, res) => {
    //console.log('Request body:', req.body);
    const saltRounds = 10;
    const { name, email, password } = req.body;

    bcrypt.hash(password.toString(), saltRounds, (err, hash) => {
        if (err) {
            console.error('Error hashing password:', err);
            return res.status(500).json({ error: "Error hashing password" });
        }

        Users.create({
            name,
            email,
            password: hash
        })
            .then(result => {
                //console.log('User created:', result);
                res.status(201).json({ Status: "Success", data: result });;
            })
            .catch(error => {
                console.error('Error creating user:', error);
                res.status(500).json({ error: "Error creating user", details: error.message });
            });
    });
});

// Define the endpoint to get a post by ID
app.get('/get/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const post = await Post.findByPk(id); // Adjust if you're using a different method to find the post
        if (!post) {
            return res.status(404).json({ Error: 'Post not found' });
        }
        res.json(post);
    } catch (err) {
        console.error("Error fetching post:", err);
        res.status(500).json({ Error: 'Internal server error' });
    }
});

app.post('/addPost', vreifyUser, async (req, res, next) => {
    try {
        const { description } = req.body;
        const userId = req.user.id;

        if (!description) {
            return res.status(400).json({ message: 'Description is required' });
        }

        await Post.create({ description, userId });
        return res.json({ status: "Success", message: "Post created successfully" });
    } catch (error) {
        next(error);
    }
});



app.put('/updatePost/:id', vreifyUser, async (req, res) => {
    const { id } = req.params;
    const { description } = req.body;

    try {
        // Get user info from req.user
        const userId = req.user.id;
        console.log("UserId received in updatedPost", userId)
        const userType = req.user.type;
        console.log("UsetType received in updatedPost", userType)

        // Find the post
        const post = await Post.findByPk(id);
        if (!post) {
            return res.status(404).json({ error: "Post not found" });
        }

        // Check permissions
        if (userType === 'admin' || post.userId === userId) {
            await post.update({ description });
            return res.json({ status: "Success", message: "Post updated successfully" });
        } else {
            return res.status(403).json({ error: "Permission denied" });
        }

    } catch (err) {
        console.error("Error updating post:", err);
        return res.status(500).json({ error: "Failed to update post", details: err.message });
    }
});


app.delete('/delete/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const post = await Post.findByPk(id);
        if (!post) {
            return res.status(404).json({ Error: "Post not found" });
        }
        await post.destroy();
        return res.json({ Status: "Success", Message: "Post deleted successfully" });
    } catch (err) {
        console.error("Error deleting post:", err);
        return res.status(500).json({ Error: "Error deleting post" });
    }
});


app.get('/logout', (req, res) => {
    res.clearCookie('token');
    return res.json({ Status: "Success" });
})

db.sequelize.sync()
    .then(async () => {
        await createAdmin()
        app.listen(4000, () => {
            console.log("Server is running on port", 4000);
        });
    })
    .catch((error) => {
        console.error("Unable to connect to the database:", error);
    });
