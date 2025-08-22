const mongoose = require('mongoose');
const { Schema } = mongoose;

const adminSchema = new Schema({
  employmentNumber: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  name: { type: String, required: true },
  role: { type: String, default: 'admin' }
});

module.exports = mongoose.model('Admin', adminSchema); 