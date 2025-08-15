const mongoose = require("mongoose");

const diaryEntrySchema = new mongoose.Schema({
    title: { type: String, required: true },
    content: { type: String, required: true },
    user: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    isPublic: { type: Boolean, default: false },
    shareId: { type: String, unique: true, sparse: true },
    createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model("DiaryEntry", diaryEntrySchema);
