const path = require('path');
require('dotenv').config({ path: path.resolve(__dirname, '../.env') });
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const Admin = require('./models/Admin');

const MONGODB_URI = process.env.MONGODB_URI;

async function seedAdmin() {
  try {
    await mongoose.connect(MONGODB_URI);
    console.log('Successfully connected to MongoDB for seeding.');

    const existingAdmin = await Admin.findOne({ employmentNumber: 'admin' });
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash('admin@aticas', salt);
    if (existingAdmin) {
      existingAdmin.employmentNumber = 'AC001';
      existingAdmin.password = hashedPassword;
      existingAdmin.role = 'superadmin';
      await existingAdmin.save();
      console.log('Admin user updated to super admin.');
      return;
    }
    const newAdmin = new Admin({
      employmentNumber: 'AC001',
      name: 'Default Admin',
      password: hashedPassword,
      role: 'superadmin'
    });

    await newAdmin.save();
    console.log('Default admin user has been created successfully!');
    console.log('You can now log in with:');
    console.log('Employment Number: AC001');
    console.log('Password: admin@aticas');

  } catch (error) {
    console.error('Error seeding admin user:', error);
  } finally {
    mongoose.connection.close();
  }
}

seedAdmin(); 