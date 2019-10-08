const { promisify } = require('util');
const crypto = require('crypto');
const UserdataLogin = require('../models/user');
const catchAsync = require('../utils/catchAsync');
const jwt = require('jsonwebtoken');
const AppError = require('../utils/appError');
const sendEmail = require('../utils/mailer');
const bcrypt = require('bcrypt');

const signToken = id => {
  return jwt.sign({ id }, 'secret', {
    expiresIn: process.env.JWT_EXPIRES_IN
  });
};
const createToken = (user, statusCode, res) => {
  const token = signToken(user._id);
  const options = {
    path: '/',
    expires: new Date (
      Date.now() + process.env.JWT_COOKIE_EXPIRES_IN * 24 * 60 * 60 * 1000
    ),
    httpOnly: true
  };
  res.cookie('jwt', token, options);
  user.password = undefined;
  user.passwordChangedAt = undefined;
  res.status(statusCode).json({
    statusCode: statusCode,
    message: 'success',
    token: token,
    data: user
  });
};
exports.users = catchAsync(async (req, res) => {
  const checkUserName = await UserdataLogin.find();
  if (checkUserName.length === 0) {
    return res.status(400).json({
      statusCode: 400,
      message: `user doesn't exist`
    });
  }
  let users = await UserdataLogin.aggregate([
    { $project: { _id: 1, username: 1, role: 1, image: 1 } }
  ]);
  res.status(200).json({
    statusCode: 200,
    message: 'success',
    data: users
  });
});

exports.deleteSellerOrUser = catchAsync(async (req, res) => {
  let data = await UserdataLogin.findByIdAndDelete(req.params.id);
  res.status(204).json({
    statusCode: '204', // successfully deleted
    message: 'success'
  });
});

exports.signup = catchAsync(async (req, res) => {
  let newUser = await UserdataLogin.create(req.body);
  createToken(newUser, 201, res);
});

exports.login = catchAsync(async (req, res, next) => {
  const { username, password } = req.body;
  // check if username and password is existing
  if (!username || !password) {
    return next(new AppError('please provide username and password!', 400));
  }
  // console.log(username);
  //to check whether the given username provided exists or not
  const checkUserName = await UserdataLogin.find({
    username: req.body.username
  });
  // console.log('hi',checkUserName.length);
  if (checkUserName.length === 0) {
    return res.status(400).json({
      statusCode: 400,
      message: `user doesn't exist`
    });
  }
  const user = await UserdataLogin.findOne({ username }).select('+password');
  const correct = await user.correctPassword(password, user.password);
  if (!user || !correct) {
    return next(new AppError('Incorrect username or password', 401));
  }
  createToken(user, 200, res);
});

exports.protect = catchAsync(async (req, res, next) => {
  // 1) Getting token and check of it's there
  let token;
  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith('Bearer')
  )
    token = req.headers.authorization.split(' ')[1];
  if (!token) {
    return next(
      new AppError('You are not logged in! Please log in to get access.', 401)
    );
  }
  // 2) Verification token
  const decoded = await promisify(jwt.verify)(token, 'secret');
  // 3) Check if user still exists
  const currentUser = await UserdataLogin.findById(decoded.id);
  if (!currentUser) {
    return next(
      new AppError(
        'The user belonging to this token does no longer exist.',
        401
      )
    );
  }
  if (currentUser.changedPasswordAfter(decoded.iat)) {
    return next(
      new AppError('User recently changed password! Please log in again.', 401)
    );
  }
  req.user = currentUser;
  exports.currentUser;
  next();
});

exports.restrictTo = (...roles) => {
  return (req, res, next) => {
    // roles ['admin', 'seller']. role='user'
    if (!roles.includes(req.user.role)) {
      return next(
        new AppError('You do not have permission to perform this action', 403)
      );
    }
    next();
  };
};

exports.forgotPassword = catchAsync(async (req, res, next) => {
  const user = await UserdataLogin.findOne({ email: req.body.email });
  if (!user) {
    return next(
      new Error(
        'There is no such email address found!!\n please check the email again'
      ),
      404
    );
  }
  const resetToken = user.createPasswordResetToken();
  await user.save({ validateBeforeSave: false });
  const resetURL = `${req.protocol}://${req.get(
    'host'
  )}/api/v1/ecommerce/resetPassword/${resetToken}`;
  const message = `Forgot your password ? Confirm your password to: ${resetURL}.\n`;
  try {
    await sendEmail({
      email: user.email,
      subject: `your password reset token[valid only for next 10 minutes]`,
      message
    });
    res.status(200).json({
      statusCode: 200,
      status: 'success',
      message: 'If email provided exists then check your mail for reset token'
    });
  } catch (error) {
    user.passwordResetToken = undefined;
    user.passwordResetTokenExpires = undefined;
    await user.save({ validateBeforeSave: false });
    return next(new Error(`Some error occured please try again later`), 500);
  }
});

exports.resetPassword = catchAsync(async (req, res, next) => {
  const hashedToken = crypto
    .createHash('sha256')
    .update(req.params.token)
    .digest('hex');

  const user = await UserdataLogin.findOne({
    passwordResetToken: hashedToken,
    passwordResetTokenExpires: { $gt: Date.now() }
  }).select('+password');
  if (!user) {
    return next(new AppError('Token is invalid or has expired', 400));
  }
  if (await bcrypt.compare(req.body.password, user.password)) {
    return res.status(400).json({
      statusCode: 400,
      status: 'fail',
      message: 'new password should not be old password'
    });
  }
  user.password = req.body.password;
  user.passwordResetToken = undefined;
  user.passwordResetTokenExpires = undefined;
  await user.save();
  createToken(user, 200, res);
});

exports.updatePassword = catchAsync(async (req, res, next) => {
  let user = await UserdataLogin.findById(req.user.id).select('+password');

  if (!(await user.correctPassword(req.body.currentPassword, user.password))) {
    return next(
      new AppError(`current password is wrong please try again`, 400)
    );
  }
  if (await bcrypt.compare(req.body.currentPassword, user.password)) {
    return res.status(400).json({
      statusCode: 400,
      status: 'fail',
      message: 'new password should not be old password'
    });
  }
  user.password = req.body.password;
  user.currentPassword = req.body.currentPassword;
  await user.save();
  createToken(user, 200, res);
});
