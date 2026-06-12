import express from 'express'
import session from 'express-session';
import connectMongoDBSession from 'connect-mongodb-session'
import mongoose from 'mongoose'
import bcrypt from 'bcryptjs';

import {User} from './models/user.js';
const mongoURI = "mongodb://localhost:27017/sessions";

const app = express()

mongoose.connect(mongoURI)
.then(()=>console.log("MongoDB connected"))

const MongoDBStore = connectMongoDBSession(session);

const store = new MongoDBStore({
    uri: mongoURI,
    collection: 'mySessions'
});
app.use(session({
    secret: "a secret key that will sign the session",
    resave: false,
    saveUninitialized: false,
    store: store
}))

app.set("view engine","ejs")
app.use(express.urlencoded({extended:false}))

const isAuth =(req,res,next)=>{
   if(req.session.userId){
    next();
   }
   else{
    res.redirect('/login')
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
    req.session.userId = user._id;
    res.redirect('/dashboard')
})

app.get("/dashboard",isAuth,(req,res)=>{
    res.render("dashboard")
})

app.post('/logout',(req,res)=>{
    req.session.destroy((err)=>{
        if(err) throw err;
        res.redirect('/')
    })
})
app.listen(8000,()=> console.log("App running on PORT:8000"))