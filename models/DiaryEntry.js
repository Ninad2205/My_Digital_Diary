const mongoose = require("mongoose");

const diaryEntrySchema = new mongoose.Schema({
    title: { type: String, required: true, trim: true, maxlength: 100 },
    content: { type: String, required: true, maxlength: 5000 },
    user: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model("DiaryEntry", diaryEntrySchema);
