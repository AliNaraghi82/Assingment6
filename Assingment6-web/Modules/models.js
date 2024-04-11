const countryData = require("../data/countryData");
const regionData = require("../data/regionData");

require("dotenv").config();
const { Sequelize } = require("sequelize");
let { PGHOST, PGDATABASE, PGUSER, PGPASSWORD } = process.env;

const sequelize = new Sequelize(PGDATABASE, PGUSER, PGPASSWORD, {
  host: PGHOST,
  dialect: "postgres",
  port: 5432,
  dialectOptions: {
    ssl: { rejectUnauthorized: false },
  },
});

const Region = sequelize.define("Region", {
  id: {
    type: Sequelize.INTEGER,
    autoIncrement: true,
    allowNull: false,
    primaryKey: true,
  },
  name: Sequelize.STRING,
  subs: Sequelize.STRING,
});

const Country = sequelize.define("Country", {
  a2code: { type: Sequelize.STRING, primaryKey: true },
  name: Sequelize.STRING,
  official: Sequelize.STRING,
  nativeName: Sequelize.STRING,
  permanentUNSC: Sequelize.BOOLEAN,
  wikipediaURL: Sequelize.STRING,
  capital: Sequelize.STRING,
  regionId: Sequelize.INTEGER,
  languages: Sequelize.STRING,
  population: Sequelize.INTEGER,
  flag: Sequelize.STRING,
});

Country.belongsTo(Region, { foreignKey: "regionId" });

module.exports = { sequelize, Country, Region };

// Code Snippet to insert existing data from Countries / Regions

// sequelize
//   .sync({force: true})
//   .then( async () => {
//     try{
//       await Region.bulkCreate(regionData);
//       await Country.bulkCreate(countryData); 
//       console.log("-----");
//       console.log("data inserted successfully");
//     }catch(err){
//       console.log("-----");
//       console.log(err.message);

//       // NOTE: If you receive the error:

//       // insert or update on table "Countries" violates foreign key constraint "Countries_region_id_fkey"

//       // it is because you have a "country" in your collection that has a "regionId" that does not exist in the "regionData".   

//       // To fix this, use PgAdmin to delete the newly created "Regions" and "Countries" tables, fix the error in your .json files and re-run this code
//     }

//     process.exit();
//   })
//   .catch((err) => {
//     console.log('Unable to connect to the database:', err);
//   });