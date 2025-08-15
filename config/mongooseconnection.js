const mongoose = require("mongoose");
const debuglog = require("debug")("development:mongooseconfig");

mongoose.connect("mongodb://127.0.0.1:27017/DiaryApp");

const db = mongoose.connection;

db.on("error", function(err) {
    debuglog(err);
});

db.on("open", function() {
    debuglog("connected"); 
    console.log("connected database");
});

module.exports = db;
