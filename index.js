require('dotenv').config();
const express = require('express')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')

const { User: UserModel } = require('./model')

const app = express()

app.use(express.json())
app.use(require('cors')())

// 注册
app.post('/api/register', async (req, res) => {
    const { name, pwd } = req.body
    if (!name || !pwd) return res.send('缺少参数') 

    // 散列用户密码
    const bcryptPwd = bcrypt.hashSync(pwd, 10)

    const user = await UserModel.create({
        pwd: bcryptPwd,
        name,
    })

    if (!user) return
    res.send(user)
})

// 登陆
app.post('/api/login', async (req, res) => {
    const { name, pwd } = req.body
    const user = await UserModel.findOne({ name })
    if (!user)
        return res.status(422).send({ errmsg: '用户不存在' })

    // 验证密码 compareSync
    const isPass = await bcrypt.compareSync(pwd, user.pwd)
    if (!isPass)
        return res.status(422).send({ errmsg: '密码错误' })
    
    // 验证通过 给客户端返回token 以备后面验证登陆

    // 生成token
    const token = jwt.sign({
        id: String(user._id),
        unUse: '随便加的字段，不用在意'
    }, process.env.SECRET)

    res.send({ 
        success: '登陆成功',
        token
    })
})

// 权限验证中间件
const authMiddleWare = async (req, res, next) => {
    const { authorization } = req.headers
    const token = String(authorization).split(' ')[1]

    if (!token) return  res.send({ errmsg: 'token已过期' })
    // 解析token
    const { id } = jwt.verify(token, process.env.SECRET)

    const user = await UserModel.findById(id)

    if (user) {
        req.user = user
        next()
    } else {
        res.send({
            errmsg: 'token已过期'
        })
    }
}

// 获取个人信息
app.get('/api/getUserInfo', authMiddleWare, async (req, res) => {
    res.send(req.user)
})

app.listen(5000, () => {
    console.log(`app is start at localhost:5000`)
})