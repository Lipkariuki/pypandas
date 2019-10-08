const crypto = require('crypto');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

const userLoginSchema = new mongoose.Schema({
  username: {
    type: String,
    required: [true, 'A user must have a username'],
    unique: true
  },
  email: {
    required: [true, 'A user must fill email'],
    type: String,
    unique: true
  },
  password: {
    type: String,
    required: [true, 'User must fill the password'],
    minlength: 8,
    maxlength: 10,
    unique: false,
    select: false
  },
  passwordChangedAt: Date,
  passwordResetToken: String,
  passwordResetTokenExpires: Date,
  dob: {
    type: Date,
    required: [true, 'User must have date of birth'],
    default: new Date() // just for getting ISO date
  },
  role: {
    type: String,
    enum: ['user', 'seller', 'admin'],
    default: 'user'
  },
  image: {
    type: String,
    required: [true, 'Every user must have an image'],
    unique: false
  }
});

userLoginSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 12);
  this.confirmPassword = undefined;
});

userLoginSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();

  this.passwordChangedAt = Date.now() - 1000;
  next();
});

userLoginSchema.methods.correctPassword = async function(
  candidatePassword,
  userPassword
) {
  return await bcrypt.compare(candidatePassword, userPassword);
};

//static instance method
userLoginSchema.methods.changedPasswordAfter = function(JWTTimestamp) {
  if (this.passwordChangedAt) {
    const changedTimestamp = parseInt(
      this.passwordChangedAt.getTime() / 1000,
      10
    );
    return JWTTimestamp < changedTimestamp;
  }
  // False means password was NOT changed
  return false;
};

userLoginSchema.methods.createPasswordResetToken = function() {
  const resetToken = crypto.randomBytes(32).toString('hex');
  this.passwordResetToken = crypto
    .createHash('sha256')
    .update(resetToken)
    .digest('hex');
  this.passwordResetTokenExpires = Date.now() + 10 * 60 * 1000;
  console.log(this.passwordResetTokenExpires);
  return resetToken;
};

const UserDataLogin = mongoose.model('userLogin', userLoginSchema);

module.exports = UserDataLogin;
