const User = require('../models/user-model');

const checkuserexist = async (username) => {
    const userexist = await User.findOne({ username });
    return userexist;
}

const register_service = async (userdata) => {
    const user = new User(userdata)
    await user.save();
}

const getAllUser = async()=>{
    return await User.find();
}

module.exports = { checkuserexist, register_service, getAllUser }