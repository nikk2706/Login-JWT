const bcrypt = require('bcrypt');
const User = require('../models/user-model');
const {register_service, checkuserexist , getAllUser} = require('../Services/services');
// JWT Token
const jwt = require('jsonwebtoken');
const secretKey = 'secretkey';
const generateToken = (user)=>{
    return jwt.sign({useId: user.id},secretKey,{expiresIn :'1h'});  
}

const registerUser = async (req, res) => {
    const { username, password, role } = req.body;
    try {
        const userexist = await checkuserexist(username)
        if(userexist){
            return res.status(400).json({message:"User already exist"});
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({ username, password: hashedPassword , role: role || 'user' }); // save to db default role is user
        
        await register_service(user);

        res.json({ message:'Register Successfully..'});

    } catch (error) {
        res.status(500).json({ message: 'Registration failed', error: error.message });
    }
};

const loginUser = async (req, res) => {
    const { username, password } = req.body;
    try {
        const user = await checkuserexist(username);
        if (!user) {
            return res.status(401).json({ message: 'Invalid Credentials' })
        }

        const passwd = await bcrypt.compare(password, user.password)
        if (!passwd) {
            return res.status(401).json({ message: "Invalid Credentials" })
        }

        const token = generateToken(user);
        res.json({ message :'Login Successful....',token});

    } catch (error) {
        res.status(500).json({ message: 'Login Failed', error: error.message });
    }
};


const getUsersData =async(req, res)=>{
    try{
        const data = await getAllUser();
        res.status(200).send(data);
    }catch(error){
        res.status(500).send(error);
    }
}
module.exports = { registerUser, loginUser, getUsersData}