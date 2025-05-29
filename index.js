const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
require('dotenv').config();

const UserModel = require('./models/UserModel');
const PostModel = require('./models/PostModel');

const app = express();

app.use(express.json());
app.use(express.static('public'));

app.use(cors({
  origin: ["http://localhost:3000", "https://simple-jet.vercel.app"],
  methods: ["GET", "POST", "PUT", "DELETE"],
  credentials: true
}));

app.use(cookieParser());

mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
});

// REGISTER
app.post('/', (req, res) => {
  const { name, email, password } = req.body;
  bcrypt.hash(password, 10)
    .then(hash => {
      UserModel.create({ name, email, password: hash })
        .then(result => res.json(result))
        .catch(err => res.json(err));
    })
    .catch(err => res.json(err));
});

// LOGIN
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await UserModel.findOne({ email: email });
    if (!user) return res.json({ msg: "Invalid user" });

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) return res.json({ msg: "Invalid password" });

    const token = jwt.sign(
      { email: user.email, role: user.role },
      "secret-key",
      { expiresIn: "1d" }
    );

    res.cookie("token", token, {
      httpOnly: true,
      secure: true,         // ✅ Required for HTTPS
      sameSite: "None",     // ✅ Required for cross-origin cookies
      maxAge: 24 * 60 * 60 * 1000,
    });

    return res.json({ Status: "login success", role: user.role });

  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: "Internal server error" });
  }
});

// VERIFY TOKEN MIDDLEWARE
const verifyuser = (req, res, next) => {
  const token = req.cookies.token;
  if (!token) return res.json("token is not available");

  jwt.verify(token, "secret-key", (err, decoded) => {
    if (err) return res.json("wrong token");
    req.email = decoded.email;
    req.name = decoded.name;
    next();
  });
};

// PROTECTED ROUTE
app.get('/home', verifyuser, (req, res) => {
  res.json({ email: req.email, name: req.name });
});

// MULTER CONFIG
const storage = multer.diskStorage({
  destination: (req, file, callb) => {
    callb(null, 'Public/Images');
  },
  filename: (req, file, callb) => {
    callb(null, file.fieldname + "_" + Date.now() + path.extname(file.originalname));
  }
});
const upload = multer({ storage: storage });

// ADD POST
app.post('/addpost', verifyuser, upload.single('file'), (req, res) => {
  PostModel.create({ title: req.body.title, description: req.body.description, file: req.file.filename })
    .then(result => res.json("post added success"))
    .catch(err => res.json(err));
});

// GET POSTS
app.get('/getposts', (req, res) => {
  PostModel.find()
    .then(posts => res.json(posts))
    .catch(err => res.json(err));
});

// VIEW POST
app.get('/viewpost/:id', (req, res) => {
  PostModel.findById({ _id: req.params.id })
    .then(result => res.json(result))
    .catch(err => console.log(err));
});

// EDIT POST
app.put('/editpost/:id', (req, res) => {
  PostModel.findByIdAndUpdate({ _id: req.params.id }, {
    title: req.body.title,
    description: req.body.description
  })
    .then(result => res.json("post updated"))
    .catch(err => console.log(err));
});

// DELETE POST
app.delete('/deletepost/:id', (req, res) => {
  PostModel.findByIdAndDelete({ _id: req.params.id })
    .then(result => res.json("post deleted"))
    .catch(err => console.log(err));
});

// GET USERS
app.get('/getalluserdata', (req, res) => {
  UserModel.find()
    .then(result => res.json(result))
    .catch(err => res.json(err));
});

// LOGOUT
app.get('/logout', (req, res) => {
  res.clearCookie('token', {
    httpOnly: true,
    secure: true,
    sameSite: "None"
  });
  return res.json("cookie cleared");
});

// START SERVER
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
