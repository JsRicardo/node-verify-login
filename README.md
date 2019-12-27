# node js实现密码散列加密以及jwt登陆验证

# 为什么使用token

## session
当用户第一次通过浏览器使用用户名和密码访问服务器时，服务器会验证用户数据，验证成功后在**服务器端写入session数据**，向客户端浏览器返回sessionid，浏览器将sessionid保存在cookie中。

当用户再次访问服务器时，会携带sessionid，服务器会进行用户信息查询，查询到，会将查询到的用户信息返回，从而实现状态保持。

## token
token与session的不同主要在认证成功后，会对当前用户数据进行加密，生成一个加密字符串token，返还给客户端，由**客户端保存**。

再次访问时服务器端对token值的处理：服务器对浏览器传来的token值进行解密，解密完成后进行用户数据的查询，如果查询成功，则通过认证，实现状态保持。

相比较而言，token很大程度上减少了服务端的压力，服务器不用保存那么多sessionid,只需要对token解密就可以了，也不用保存用户在哪个服务器登录的，只需要jwt加密规则相同就行。

# node js实现token
使用到的包：
- `express@next`：开启服务器
- `cors`： 开启跨域请求
- `dotenv`： 应用env文件
- `mongoose`： 连接MongoDB
- `bcrypt`： bcrypt散列加密，或者使用bcryptjs，兼容性好，不过性能差一点
- `jsonwebtoken`： 无属性token生成


思路：

1. 为了保证用户密码的安全性，用户的密码存入到数据库之前应该被加密
2. 用户登录时，输入的是密码，需要解析一下和数据库里面存的散列数据对比
3. 用户登录成功后，需要向客户端发送token，客户端保存下来
4. 客户端发起的每一个需要登录验证的接口，都需要在请求里面带上token，后端解析验证通过再做后面的业务逻辑

- 先创建一个express的服务

```js
require('dotenv').config(); // 使用env文件
const express = require('express')
const bcrypt = require('bcryptjs') // 散列加密
const jwt = require('jsonwebtoken') // jwt加密token
const app = express()

const { User: UserModel } = require('./model')

app.use(express.json()) // 处理请求
app.use(require('cors')()) // 处理跨域

app.listen(5000, () => {
    console.log(`app is start at localhost:5000`)
})
```

用一个简单的model User来实现这个样例

创建model.js文件 导出一个User Model

```js
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

module.exports = { User }
```

## 注册逻辑

注册需要处理的事情就是将用户密码散列加密，存入数据库中

brypt加密，即使是同一个字符串，每次加密生成的密文都是不一样的

bcrypt散列有两种方式，一种同步的`hashSync(需要加密的字符串, 密码强度)`，一种异步的`hash(需要加密的字符串, 密码强度, 回调函数)`

密码强度不宜太高，太高了性能低。太低了，加密力度又不够，一般8-12差不多。

```js
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
```

## 登陆逻辑

登陆时需要用到brypt的`compareSync(解密字符串, 已经加密的对应字符串)`或者`compare(解密字符串, 已经加密的对应字符串).then(res)`来解密pwd，也只有这玩意儿能解密了。

如果解密通过了，需要调用jwt.sign生成token传给前端，由前端存储登陆凭据

sign接收一个目标对象和一个加密的secret：
    目标对象就是需要传给客户端的用于登陆验证的信息
    secret则保存在服务器，加密解密都需要这个字段，不应该被外界知晓

```js
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
```

## 验证登陆

首先，我们肯定有很多接口都需要登陆验证，那我们肯定不可能在每一个接口里面都去处理token，更好的方法就是封装一个函数用于处理这个token。

那么express提供了一个很好的解决方案：中间件

创建好中间件之后，之后每一个需要验证权限的接口，都使用这个中间件即可

增加一个权限验证中间件：
    jwt一般来说都放在header里面的`Authorization`,在后端只需要在headers字段中拿到token
    拿到token之后使用`verify(token, seceret)`解密
    查找用户
    找到了就进行下一步，没找到就返回错误

```js
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
```

使用这个中间件
```js
// 获取个人信息
app.get('/api/getUserInfo', authMiddleWare, async (req, res) => {
    res.send(req.user)
})
```

思路清晰，步骤简单。当然这里只是记录jwt，bcrypt的使用，很多容错处理就没有省略了，在实际的业务中肯定还是得加上的。