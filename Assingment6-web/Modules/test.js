
const { initialize, getAllCountries, getCountryByCode, getCountriesByRegion } = require('./unCountries');


initialize()
    .then(() => {
        console.log("Countries initialized successfully!");
        return getAllCountries();
    })
    .then(countries => {
        console.log("All countries:", countries);
        return getCountryByCode('AF');
    })
    .then(country => {
        console.log("Country by code:", country);
        return getCountriesByRegion('Asia');
    })
    .then(countriesInRegion => {
        console.log("Countries in Asia:", countriesInRegion);
    })
    .catch(error => {
        console.error("Error:", error);
    });
