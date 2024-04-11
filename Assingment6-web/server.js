/********************************************************************************
 *  WEB322 – Assignment 06
 *
 *  I declare that this assignment is my own work in accordance with Seneca's
 *  Academic Integrity Policy:
 *
 *  https://www.senecacollege.ca/about/policies/academic-integrity-policy.html
 *
 *  Name:Ali Naraghi  Student ID:123747222  Date:Apr.11.2024
 *  Published URL:https://misty-pink-dugong.cyclic.app
 *
 ********************************************************************************/

const express = require("express");
const bodyParser = require("body-parser");
const unCountryData = require("./Modules/unCountries");
const authData = require("./Modules/auth-service");
const clientSessions = require("client-sessions");

const app = express();
const HTTP_PORT = process.env.PORT || 8080;

app.use(express.static("public"));
app.set("view engine", "ejs");
app.set("views", "views");

// The code "express.urlencoded({extended:true})" did not work properly, so after doing a little search I found that the "body-parser" package does the exact same thing.
app.use(bodyParser.urlencoded({ extended: true }));
app.use(
  clientSessions({
    cookieName: "session",
    secret: "znFg5ASdPBZY6xC",
    duration: 2 * 60 * 1000,
    activeDuration: 1000 * 60,
  })
);
app.use((req, res, next) => {
  res.locals.session = req.session;
  next();
});

function onHttpStart() {
  console.log("Express http server listening on: " + HTTP_PORT);
}

function ensureLogin(req, res, next) {
  if (!req.session.user) {
    res.redirect("/login");
  } else {
    next();
  }
}

app.get("/", (req, res) => {
  res.render("home");
});

app.get("/about", (req, res) => {
  res.render("about");
});

app.get("/un/countries", async (req, res) => {
  try {
    const { region } = req.query;
    if (region) {
      const countriesByRegion = await unCountryData.getCountriesByRegion(
        region
      );
      res.render("countries", { countries: countriesByRegion });
    } else {
      const allCountries = await unCountryData.getAllCountries();
      res.render("countries", { countries: allCountries });
    }
  } catch (err) {
    console.log(err);
    res.status(404).render("404", {
      message: "The region you are looking for is not available.",
    });
  }
});

app.get("/un/countries/:a2code", async (req, res) => {
  try {
    const country = await unCountryData.getCountryByCode(req.params.a2code);
    if (country) {
      res.render("country", { country });
    } else {
      throw new Error("Country not found");
    }
  } catch (err) {
    res.status(404).render("404", {
      message: "The country you are looking for is not available.",
    })();
  }
});

app.get("/un/addCountry", ensureLogin, async (req, res, next) => {
  unCountryData
    .getAllRegions()
    .then((regions) => {
      res.render("addCountry", { regions });
    })
    .catch((err) =>
      res.render("500", { message: "Failed to load regions : " + err })
    );
});

app.post("/un/addCountry", async (req, res, next) => {
  ensureLogin(req, res, next);
  unCountryData
    .addCountry(req.body)
    .then(() => {
      res.redirect("/un/countries");
    })
    .catch((err) =>
      res.render("500", {
        message: `I'm sorry, but we have encountered the following error: ${err}`,
      })
    );
});

app.get("/un/editCountry/:code", async (req, res, next) => {
  ensureLogin(req, res, next);
  unCountryData
    .getAllRegions()
    .then((regions) => {
      unCountryData
        .getCountryByCode(req.params.code.toLocaleLowerCase().toUpperCase())
        .then((country) => {
          res.render("editCountry", { regions, country });
        })
        .catch((err) =>
          res
            .status(404)
            .render("404", { message: "Failed to load country data : " + err })
        );
    })
    .catch((err) =>
      res
        .status(500)
        .render("500", { message: "Failed to load regions : " + err })
    );
});

app.post("/un/editCountry", async (req, res, next) => {
  ensureLogin(req, res, next);
  if (req.body.a2code) {
    unCountryData
      .editCountry(req.body.a2code, req.body)
      .then(() => res.redirect("/un/countries"))
      .catch((err) =>
        res.render("500", {
          message: `I'm sorry, but we have encountered the following error: ${err}`,
        })
      );
  } else {
    res.render("500", {
      message: "There has been an error while updating country data. :(",
    });
  }
});

app.get("/un/deleteCountry/:code", async (req, res, next) => {
  ensureLogin(req, res, next);
  unCountryData
    .deleteCountry(req.params.code)
    .then(() => res.redirect("/un/countries"))
    .catch((err) => {
      res.render("500", {
        message: `I'm sorry, but we have encountered the following error: ${err}`,
      });
    });
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.post("/login", (req, res) => {
  req.body.userAgent = req.get("User-Agent");
  authData
    .checkUser(req.body)
    .then((user) => {
      req.session.user = {
        userName: user.userName,
        loginHistory: user.loginHistory,
        email: user.email,
      };
      res.redirect("/un/countries");
    })
    .catch((err) => {
      res.render("login", { errorMessage: err, userName: req.body.userName });
    });
});

app.get("/register", (req, res) => {
  res.render("register");
});

app.post("/register", (req, res) => {
  authData
    .registerUser(req.body)
    .then(() => res.render("register", { successMessage: "User created" }))
    .catch((err) => {
      res.render("register", {
        errorMessage: err,
        userName: req.body.userName,
      });
    });
});

app.get("/logout", (req, res) => {
  req.session.reset();
  res.redirect("/");
});

app.get("/userHistory", ensureLogin, (req, res) => {
  res.render("userHistory");
});

app.use((req, res) => {
  res.status(404).render("404", {
    message: "I'm sorry, we're unable to find what you're looking for",
  });
});

unCountryData
  .initialize()
  .then(authData.initialize)
  .then(() => {
    app.listen(HTTP_PORT, onHttpStart);
  })
  .catch((err) => {
    console.error("Error initializing data service: ", err);
  });
