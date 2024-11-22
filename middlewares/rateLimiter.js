const setRateLimit = require("express-rate-limit");
const User = require("../models/user");

const userRateLimiter = setRateLimit({
  windowMs: 60 * 1000, 
  max: 5,
  message: "You have exceeded your 5 requests per minute limit.",
  standardHeaders: true,
  legacyHeaders: false,
});

const adminRateLimiter = setRateLimit({
  windowMs: 60 * 1000, 
  max: 10,
  message: "You have exceeded your 10 requests per minute limit.",
  standardHeaders: true,
  legacyHeaders: false,
});

const dynamicRateLimiter = async (req, res, next) => {
  try {
    const user = await User.findById(req.userId);
    if (!user) {
      return res.status(403).send({ message: "User not found" });
    }

    if (user.role === "admin") {
      return adminRateLimiter(req, res, next);
    } else {
      return userRateLimiter(req, res, next);
    }
  } catch (err) {
    res.status(500).send({ message: "Error applying rate limiter" });
  }
};

module.exports = dynamicRateLimiter;
