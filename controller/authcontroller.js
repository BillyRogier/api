const User = require("../models/user")
const config = require("../config/key")
const axios = require("axios")
var bcrypt = require("bcryptjs")
var jwt = require("jsonwebtoken")

const CLIENT_ID = "xxx"
const CLIENT_SECRET = "xxx"
const GITHUB_URL = "https://github.com/login/oauth/access_token"

exports.signup = async (req, res) => {
  const user = new User({
    username: req.body.username,
    name: req.body.name,
    password: bcrypt.hashSync(req.body.password, 8),
    role: req.body.role || "user",
  })
  try {
    await user.save()
    res.send({ message: "User was registered successfully!" })
  } catch (err) {
    console.log(err)
    res.status(500).send("Erreur lors de la création de compte")
  }
}

exports.signin = async (req, res) => {
  const user = await User.findOne({ username: req.body.username })
  var passwordIsValid = bcrypt.compareSync(req.body.password, user.password)

  if (!passwordIsValid) {
    return res.status(401).send({
      accessToken: null,
      message: "Invalid Password!",
    })
  }
  const token = jwt.sign(
    { id: user.id, username: user.username },
    config.secret,
    {
      algorithm: "HS256",
      allowInsecureKeySizes: true,
      expiresIn: 86400, // 24 hours
    }
  )
  res.status(200).send({
    id: user._id,
    username: user.username,
    name: user.name,
    accessToken: token,
  })
}

exports.oauth2Redirect = async (req, res) => {
  try {
    const response = await axios({
      method: "POST",
      url: `${GITHUB_URL}?client_id=${CLIENT_ID}&client_secret=${CLIENT_SECRET}&code=${req.query.code}`,
      headers: {
        Accept: "application/json",
      },
    })
    const userData = await axios({
      method: "GET",
      url: "https://api.github.com/user",
      headers: {
        Authorization: "token " + response.data.access_token,
      },
    })
    console.log(userData)
    const { login, name } = userData.data
    let user = await User.findOne({ login }).select("-password")
    if (!user) {
      user = new User({
        username: login,
        name: name,
      })
      try {
        await user.save()
      } catch (err) {
        console.log(err)
        res.status(500).send("Erreur lors de la création de compte")
      }
    }
    const token = jwt.sign(
      { id: user.id, username: user.username },
      config.secret,
      {
        algorithm: "HS256",
        allowInsecureKeySizes: true,
        expiresIn: 86400, // 24 hours
      }
    )

    res.redirect(`http://localhost:8080/todo.html?access_token=${token}`)
  } catch (error) {
    console.error("Erreur lors de l'authentification GitHub :", error)
    res.status(500).send("Erreur lors de l'authentification GitHub")
  }
}
