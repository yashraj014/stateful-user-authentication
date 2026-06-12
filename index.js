import express from 'express'
// import session from 'express-session';
// import connectMongoDBSession from 'connect-mongodb-session'
import mongoose from 'mongoose'
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';
import {User} from './models/user.js';
const mongoURI = "mongodb://localhost:27017/sessions";
const SECRET_KEY = 'f948d1406a8a44264a2ea842b54708cfac49f24443fe6d34688e5eb777f09e31d9410e33';
const app = express()

mongoose.connect(mongoURI)
.then(()=>console.log("MongoDB connected"))

// const MongoDBStore = connectMongoDBSession(session);

// const store = new MongoDBStore({
//     uri: mongoURI,
//     collection: 'mySessions'
// });
// app.use(session({
//     secret: "a secret key that will sign the session",
//     resave: false,
//     saveUninitialized: false,
//     store: store
// }))

app.set("view engine","ejs")
app.use(express.urlencoded({extended:false}));
app.use(cookieParser());
// const isAuth =(req,res,next)=>{
//    if(req.session.userId){
//     next();
//    }
//    else{
//     res.redirect('/login')
//    }
// }
const isAuthorized = (req,res,next)=>{
    const token = req.cookies.token;
    try{
        const decoded = jwt.verify(token,SECRET_KEY);
        console.log(decoded);
        req.userId = decoded.userId;
        next();
    }
    catch(err){
        return res.status(401).send("Unauthorized");
    }
}

app.get("/",(req,res)=>{
    res.render("home");
})

app.get("/signup",(req,res)=>{
    res.render("signup")
})

app.post("/signup",async(req,res)=>{
    const {username,email,password} = req.body;

    let existing_user = await User.findOne({
        email
    })
    if(existing_user){
        return res.redirect("/signup")
    }
    const hashedPw = await bcrypt.hash(password,12);
    const user = await User.create({
        username,email,password:hashedPw
    })

    
    res.redirect('/login')
    // res.status(201).json({token:token})
})

app.get("/login",(req,res)=>{
    res.render("login")
})

app.post("/login",async(req,res)=>{
   const {email,password} = req.body;

   const user = await User.findOne({
    email
   })
   if(!user) return res.redirect('/login')

    const isMatch = await bcrypt.compare(password,user.password);
    if(!isMatch)
        return res.redirect('/login')
    // req.session.userId = user._id;
    const token = jwt.sign(
        {userId : user._id},
        SECRET_KEY,
        {expiresIn:"1h"}
    );
    console.log(token);
    res.cookie("token", token, {
    httpOnly: true
});
    res.redirect('/dashboard')
})

app.get("/dashboard",isAuthorized,async(req,res)=>{
    const user = await User.findOne({
        _id:req.userId
    })
    console.log(req.userId)
    console.log(user)
    
    res.render("dashboard",{user:user})
})

app.post('/logout',(req,res)=>{
    // req.session.destroy((err)=>{
    //     if(err) throw err;
    //     res.redirect('/')
    // })
    res.clearCookie("token", {
    httpOnly: true,
});
res.redirect('/')
})
app.listen(8000,()=> console.log("App running on PORT:8000"))