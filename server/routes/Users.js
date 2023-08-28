const express = require("express");
const router = express.Router();
const { Users } = require("../models");
const bcrypt = require("bcrypt");
const {validateToken} = require("../middlewares/AuthMiddleWare")
const { sign } = require('jsonwebtoken')

router.post("/", async (req, res) => {
  const { username, password } = req.body;
  bcrypt.hash(password, 10).then((hash) => {
    Users.create({
      username: username,
      password: hash,
    });
    res.json("SUCCESS");
  });
});

router.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    const user = await Users.findOne({ where: { username: username } });

    if (!user) {
      return res.json({ error: "User Doesn't Exist" });
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.json({ error: "Wrong Username And Password Combination" });
    }

    const accessToken = sign({ username: user.username, id: user.id }, "importantsecret");

    return res.json({ token: accessToken, username: username, id: user.id });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: "An internal server error occurred." });
  }
});

router.get("/auth", validateToken, (req, res) => {
  res.json(req.user);
})

router.get("/basicinfo/:id", async (req, res) => {
  const id = req.params.id
  const basicInfo = await Users.findByPk(id, {attributes: {exclude: 'password'}})

  res.json(basicInfo)
})

router.put("/changepassword", validateToken, async (req, res) => {
  try {
    const { oldPassword, newPassword } = req.body;
    const user = await Users.findOne({ where: { username: req.user.username } });

    const match = await bcrypt.compare(oldPassword, user.password);
    if (!match) {
      return res.json({ error: "Wrong Password Entered" });
    }

    const hash = await bcrypt.hash(newPassword, 10);
    await Users.update({ password: hash }, { where: { username: req.user.username } });

    return res.json("SUCCESS");
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: "An internal server error occurred." });
  }
});


module.exports = router;