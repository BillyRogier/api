const User = require("../models/user");
var bcrypt = require("bcryptjs");
const config = require("../config/key");
var jwt = require("jsonwebtoken");

exports.signup = async (req, res) => {
    const user = new User({
      username: req.body.username,
      name: req.body.name,
      password: bcrypt.hashSync(req.body.password, 8),
      role: req.body.role || 'user',
    });
    try {
      await user.save();
      res.send({ message: "User was registered successfully!" });
    } catch (err) {
      console.log(err);
      res.status(500).send("Erreur lors de la création de compte");
    }
};

exports.signin = async (req, res) => {
    const user = await User.findOne({ username: req.body.username });
    var passwordIsValid = bcrypt.compareSync(req.body.password, user.password);
  
    if (!passwordIsValid) {
      return res.status(401).send({
        accessToken: null,
        message: "Invalid Password!",
      });
    }
    const token = jwt.sign({ id: user.id,username:user.username },
      config.secret,
      {
        algorithm: 'HS256',
        allowInsecureKeySizes: true,
        expiresIn: 86400, // 24 hours
      });
    res.status(200).send({
      id: user._id,
      username: user.username,
      name: user.name,
      accessToken: token,
    });
  };
  