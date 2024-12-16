require("dotenv").config();

if (!process.env) process.exit(1, "[!] No .env file found."); 

module.exports = process.env;