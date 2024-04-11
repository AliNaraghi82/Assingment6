const { Sequelize } = require("sequelize");
const { sequelize, Country, Region } = require("./models");

function initialize() {
  return new Promise((resolve, reject) => {
    try {
      sequelize
        .sync()
        .then((res) => {
          console.log("Synced Sequelize");
          resolve(res)
        })
        .catch((err) => reject(err));
    } catch (error) {
      reject(error);
    }
  });
}

function getAllCountries() {
  return new Promise((resolve, reject) => {
    Country.findAll({ include: "Region" })
      .then((countries) => resolve(countries))
      .catch((err) => reject("Unable to find countries: " + err));
  });
}

function getCountryByCode(countryCode) {
  return new Promise((resolve, reject) => {
    Country.findAll({ where: { a2code: countryCode }, include: "Region" })
      .then((countries) => {
        if (countries.length !== 0) resolve(countries[0]);
        else reject("No Country was found!");
      })
      .catch((err) => reject("Unable to find requested country :" + err));
  });
}

function getCountriesByRegion(region) {
  return new Promise((resolve, reject) => {
    Country.findAll({
      include: [Region],
      where: {
        "$Region.name$": {
          [Sequelize.Op.iLike]: `%${region}%`,
        },
      },
    })
      .then((countries) => {
        if (countries.length !== 0) resolve(countries);
        else reject("No Country was found!");
      })
      .catch((err) => reject("Unable to find this region's countries :" + err));
  });
}

function addCountry(countryData) {
  return new Promise((resolve, reject) => {
    Country.create({
      ...countryData,
      permanentUNSC: countryData.permanentUNSC?.checked || false,
    })
      .then(() => resolve())
      .catch((err) =>
        reject(
          "An Error occured while creating a country: " + err.errors[0].message
        )
      );
  });
}

function editCountry(countryCode, countryData) {
  return new Promise((resolve, reject) => {
    Country.update(
      {
        ...countryData,
        permanentUNSC: countryData.permanentUNSC?.checked || false,
      },
      { where: { a2code: countryCode } }
    )
      .then(resolve)
      .catch((err) => reject(err.errors[0].message));
  });
}

function deleteCountry(countryCode) {
  return new Promise((resolve, reject) => {
    Country.destroy({ where: { a2code: countryCode } })
      .then(resolve)
      .catch((err) => reject(err.errors[0].message));
  });
}

function getAllRegions() {
  return new Promise((resolve, reject) => {
    Region.findAll()
      .then((regions) => resolve(regions))
      .catch((err) => reject("Unable to find Regions: " + err));
  });
}

module.exports = {
  initialize,
  getAllCountries,
  getCountryByCode,
  getCountriesByRegion,
  addCountry,
  getAllRegions,
  editCountry,
  deleteCountry,
};
