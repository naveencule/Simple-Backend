const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');

const UserModel = require('./models/UserModel');
const PostModel = require('./models/PostModel');

const app = express();

app.use(express.json());
app.use(express.static('public'));
app.use(cors({
    origin : ["http://localhost:3000","https://simple-jet.vercel.app"],
    methods : ["GET","POST","PUT","DELETE"],
    credentials:true
}));
app.use(cookieParser());

mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
});

// Register user
app.post('/',(req,res)=>{
    const {name,email,password} = req.body;
    bcrypt.hash(password,10)
    .then(hash=>{
        UserModel.create({name,email,password:hash})
            .then(result=>res.json(result))
            .catch(err=>res.json(err))
    })
    .catch(err=>res.json(err))
});

// Login user
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await UserModel.findOne({ email: email });
    if (!user) {
      return res.json({ msg: "Invalid user" });
    }
    
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.json({ msg: "Invalid password" });
    }
    
    const token = jwt.sign(
      { email: user.email, role: user.role },
      "secret-key",
      { expiresIn: "1d" }
    );

    res.cookie("token", token, {
      httpOnly: true,
      sameSite: "lax",
      maxAge: 24 * 60 * 60 * 1000,
    });

    return res.json({ Status: "login success", role: user.role });
    
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: "Internal server error" });
  }
});

const verifyuser = (req,res,next)=>{
    const token = req.cookies.token;
    if(!token){
        return res.json("token is not available");
    }
    else{
        jwt.verify(token,"secret-key",(err,decoded)=>{
            if(err){
                return res.json("wrong token");
            }
            else{
                req.email = decoded.email;
                req.name = decoded.name;
                next();
            }
        });
    }
};

app.get('/home',verifyuser,(req,res)=>{
    res.json({email:req.email ,name:req.name});
});

const storage = multer.diskStorage({
    destination : (req,file,callb)=>{
        callb(null,'Public/Images');  // Keeping as you requested, capital P
    },
    filename: (req,file,callb)=>{
        callb(null,file.fieldname + "_"+ Date.now() + path.extname(file.originalname));
    }
});

const upload = multer({
    storage: storage
});

app.post('/addpost',verifyuser,upload.single('file'),(req,res)=>{
    PostModel.create({title:req.body.title,description:req.body.description,file:req.file.filename})
        .then(result => res.json("post added success"))
        .catch(err => res.json(err));
});

app.get('/getposts',(req,res)=>{
    PostModel.find()
        .then(posts => res.json(posts))
        .catch(err => res.json(err));
});

app.get('/viewpost/:id',(req,res)=>{
    const id = req.params.id;
    PostModel.findById({_id: id})
        .then(result=> res.json(result))
        .catch(err => console.log(err));
});

app.put('/editpost/:id',(req,res)=>{
    const id = req.params.id;
    PostModel.findByIdAndUpdate({_id: id}, {title: req.body.title, description: req.body.description})
        .then(result=> res.json("post updated"))
        .catch(err => console.log(err));
});

app.delete('/deletepost/:id',(req,res)=>{
    PostModel.findByIdAndDelete({_id: req.params.id})
        .then(result=> res.json("post deleted"))
        .catch(err => console.log(err));
});

app.get('/getalluserdata',(req,res)=>{
    UserModel.find()
        .then(result=> res.json(result))
        .catch(err => res.json(err));
});

app.get('/logout',(req,res)=>{
    res.clearCookie('token');
    return res.json("cookie cleared");
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
