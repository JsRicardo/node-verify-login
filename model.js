const mongoose = require('mongoose')

mongoose.connect(process.env.db, {
    useCreateIndex: true,
    useNewUrlParser: true
})

const UserSchema = new mongoose.Schema({
    name: {
        type: String,
        unique: true, // 不可重复
    },
    pwd: {
        type: String
    }
})

const User = mongoose.model('User', UserSchema)

module.exports = {
    User
}