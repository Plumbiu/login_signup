import { PrismaClient } from '@prisma/client'
import express from 'express'
import bodyParser from 'body-parser'
import crypto from 'crypto'
import jwt from 'jsonwebtoken'
const AES_SECRET_KEY = '0123456789abcdefghijklmnopqrstuv'
const AES_SECRET_IV = '0123456789abcdef'
const prisma = new PrismaClient()
const app = express()
const JWT_SECRET_KEY = 'plumbiu' // 准备 JWT 的密钥

// 加密算法
function encrypt(password: string) {
  let decipher = crypto.createCipheriv('aes-256-cbc', AES_SECRET_KEY, AES_SECRET_IV)
  return decipher.update(password, 'binary', 'hex') + decipher.final('hex')
}
// 解密算法
function decrypt(crypted: string ) {
  crypted = Buffer.from(crypted, 'hex').toString('binary')
  let decipher = crypto.createDecipheriv('aes-256-cbc', AES_SECRET_KEY, AES_SECRET_IV)
  return decipher.update(crypted, 'binary', 'utf-8') + decipher.final('utf-8')
}
app.use(express.json())
app.use(bodyParser.urlencoded({ extended: false }))

app.post('/signup', async (req, res) => {
	const { username, email, password } = req.body
  /* 这里不对 usernmae, emial, password 是否为空做判断，是因为这是前端的工作 */
  // 1.生成 token
  const token = jwt.sign({
    email,
    // username
  }, JWT_SECRET_KEY, {
    expiresIn: 60 * 24 * 30 // token 的有效期为 30 天
  })
  // 2.加密密码
  const crypetedPassword = encrypt(password)
	// 3.存储用户信息
  try {
    await prisma.user.create({
      data: {
        username, email, token,
        password: crypetedPassword
      }
    })
    res.send({
      code: 2000,
      message: '注册成功'
    })
  } catch(err) {
    res.send({
      code: 2001,
      message: '注册失败'
    })
  }
})

app.post('/login', async (req, res) => {
  const { email, password } = req.body
  console.log(email, password);
  
  let user // 声明 user 变量
  // 1.获取用户信息
  try {
    user = await prisma.user.findUnique({
      where: { email }
    })
    // 如果用户不存在或者密码错误，则抛出一个错误
    if(!user || decrypt(user.password) !== password) {
      throw new Error('邮箱不存在或者密码错误')
    }
  } catch(err: any) {
    return res.send({
      code: 2002,
      message: err.message
    })
  }
  // 2.验证 token 是否有效
  const token = user?.token ?? ''
  jwt.verify(token, JWT_SECRET_KEY, (err, data) => {
    if(err) {
      return res.send({
        code: 2003,
        message: 'token 无效'
      })
    }
    res.send({
      code: 2000,
      message: '登陆成功',
      data
    })
  })
})

const server = app.listen(3000, () =>
  console.log(`
🚀 Server ready at: http://localhost:3000
⭐️ See sample requests: http://pris.ly/e/ts/rest-express#3-using-the-rest-api`),
)
