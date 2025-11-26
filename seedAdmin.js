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

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash('admin@aticas', salt);

    // Seed Cafeteria Admin
    let cafeteriaAdmin = await Admin.findOne({ employmentNumber: 'AC001' });
    if (!cafeteriaAdmin) {
      cafeteriaAdmin = new Admin({
        employmentNumber: 'AC001',
        name: 'Cafeteria Admin',
        password: hashedPassword,
        role: 'admin',
        adminType: 'cafeteria'
      });
      await cafeteriaAdmin.save();
      console.log('Cafeteria admin created: AC001');
    }

    // Seed Butchery Admin
    let butcheryAdmin = await Admin.findOne({ employmentNumber: 'AB001' });
    if (!butcheryAdmin) {
      butcheryAdmin = new Admin({
        employmentNumber: 'AB001',
        name: 'Butchery Admin',
        password: hashedPassword,
        role: 'admin',
        adminType: 'butchery'
      });
      await butcheryAdmin.save();
      console.log('Butchery admin created: AB001');
    }

    // Update any existing admin with old employmentNumber
    const existingAdmin = await Admin.findOne({ employmentNumber: 'admin' });
    if (existingAdmin) {
      existingAdmin.employmentNumber = 'AC001';
      existingAdmin.password = hashedPassword;
      existingAdmin.role = 'superadmin';
      existingAdmin.adminType = 'cafeteria';
      await existingAdmin.save();
      console.log('Existing admin updated to super admin: AC001');
    }

    console.log('\nAdmin users have been seeded successfully!');
    console.log('Login credentials for all admins:');
    console.log('Password: admin@aticas');
    console.log('Cafeteria Admin: AC001');
    console.log('Butchery Admin: AB001');

  } catch (error) {
    console.error('Error seeding admin users:', error);
  } finally {
    mongoose.connection.close();
  }
}

seedAdmin(); 