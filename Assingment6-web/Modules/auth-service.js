const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
require("dotenv").config();

const Schema = mongoose.Schema;
const userSchema = new Schema({
  userName: {
    type: String,
    unique: true,
    required: true,
  },
  password: {
    type: String,
    required: true,
  },
  email: {
    type: String,
    required: true,
  },
  loginHistory: {
    type: [
      {
        dateTime: Date,
        userAgent: String,
      },
    ],
    default: [],
  },
});

let User;

const initialize = () => {
  return new Promise((resolve, reject) => {
    console.log("Initilizing mongoDB");
    let db = mongoose.createConnection(process.env.MONGODB_URI);
    db.on("error", (err) => {
      reject(err);
    });
    db.once("open", () => {
      User = db.model("users", userSchema);
      console.log("USER Initilized:", User);
      resolve();
    });
  });
};

const registerUser = (userData) => {
  return new Promise((resolve, reject) => {
    if (userData.password !== userData.password2) {
      reject("Passwords do not match");
    } else {
      let user = new User(userData);
      bcrypt
        .hash(user.password, 10)
        .then((hash) => {
          user.password = hash;
          user
            .save()
            .then(() => resolve())
            .catch((err) => {
              if (err.code === 11000) {
                reject("User Name already taken");
              } else {
                reject("There was an error creating the user: " + err);
              }
            });
        })
        .catch((err) => console.log(err));
    }
  });
};

const checkUser = (userData) => {
  return new Promise((resolve, reject) => {
    User.find({ userName: userData.userName })
      .exec()
      .then((users) => {
        if (users.length > 0) {
          let user = users[0];
          bcrypt.compare(userData.password, user.password).then((result) => {
            if (result) {
              if (user.loginHistory.length == 8) {
                user.loginHistory.pop();
              }
              user.loginHistory.unshift({
                dateTime: new Date().toISOString(),
                userAgent: userData.userAgent,
              });
              User.updateOne(
                { userName: userData.userName },
                { $set: { loginHistory: user.loginHistory } }
              )
                .exec()
                .then(() => {
                  resolve(user);
                })
                .catch((err) =>
                  reject("There was an error verifying the user: " + err)
                );
            } else {
              reject("Incorrect Password for user: " + userData.userName);
            }
          });
        } else {
          reject("Unable to find user: " + userData.userName);
        }
      })
      .catch((err) => reject("Error finding user: " + err));
  });
};

module.exports = { initialize, registerUser, checkUser };
