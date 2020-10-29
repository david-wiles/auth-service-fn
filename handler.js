'use strict'

const redis = require("redis");
const {sha256} = require("js-sha256");
const jwt = require("jsonwebtoken");
const {promisify} = require("util");

const redisClient = redis.createClient({
  port: process.env.REDIS_PORT,
  host: process.env.REDIS_HOST,
  password: process.env.REDIS_PASS
});

const redisGet = promisify(redisClient.get).bind(redisClient);
const redisSet = promisify(redisClient.set).bind(redisClient);

/**
 * Authenticates a user and returns an object containing their information
 * @param event
 */
const authenticate = (event) => {
  return new Promise((resolve, reject) => {
    if (!event.headers.authorization) {
      reject(new Error("No authorization header"));
    } else {
      const [type, auth] = (event.headers.authorization || '').split(' ');
      if (type.toLowerCase() === "basic") {
        const [login, password] = Buffer.from(auth, 'base64').toString().split(':');
        if (login && password) {
          redisGet(login)
            .then((user) => {
              let userJson = JSON.parse(user);
              if (userJson && userJson.password === sha256(password)) {
                resolve(userJson);
              } else {
                reject(new Error("Invalid password"));
              }
            })
            .catch(err => reject(err));
        }
      } else if (type.toLowerCase() === "bearer") {
        jwt.verify(auth, process.env.JWT_SECRET, {algorithm: ["HS512"]}, (err, payload) => {
          if (err) reject(err);
          else {
            if (payload && payload.user) resolve(payload.user);
            else reject(new Error("No user found in jwt payload"))
          }
        });
      } else {
        reject(new Error("Bad authorization request"));
      }
    }
  });
};

/**
 * Creates a new user
 * @param event
 * @returns {Promise}
 */
const create = (event) => {
  return new Promise(async (resolve, reject) => {
    try {
      if (!event.body.login || !event.body.password) reject(new Error("Missing required information"));
      else {
        let user = await redisGet(event.body.login);
        if (!user) {
          let user = {
            login: event.body.login,
            password: sha256(event.body.password)
          };
          await redisSet(event.body.login, JSON.stringify(user));
          resolve(user);
        } else {
          reject(new Error("User already exists"));
        }
      }
    } catch (err) {
      reject(err);
    }
  });
};

/**
 * Updates an existing user if they have been authenticated
 * @param event
 * @returns {Promise<*>}
 */
const update = async (event) => {
  let user = await authenticate(event);

  Object.keys(event.body).forEach((key) => {
    if (key === "password") {
      user.password = sha256(event.body.password);
    } else if (key !== "login") {
      user[key] = event.body[key];
    }
  });

  await redisSet(user.login, JSON.stringify(user));
  return user;
};

module.exports = async (event, context) => {
  let result = {};

  try {
    switch (event.method) {
      case "PUT":
        result.user = await create(event);
        break;
      case "POST":
        result.user = await update(event);
        break;
      case "GET":
      default:
        result.user = await authenticate(event);
    }

    if (result.user && result.user.password) {
      delete result.user.password;
    }

    result.jwt = jwt.sign(result, process.env.JWT_SECRET, {algorithm: "HS512", expiresIn: "2h"});

  } catch (err) {
    result.error = err.toString();
    if (result.user && result.user.password) {
      delete result.user.password;
    }

    return context
      .status(500)
      .succeed(result);
  }

  return context
    .status(200)
    .succeed(result)
}

