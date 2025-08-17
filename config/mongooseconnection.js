const mongoose = require("mongoose");
const debuglog = require("debug")("development:mongooseconfig");

mongoose.connect(process.env.MongoURI);

const db = mongoose.connection;

db.on("error", function(err) {
    debuglog(err);
});

db.on("open", function() {
    debuglog("connected"); 
    console.log("connected database");
});

module.exports = db;
