const express = require('express');
const {
  signup,
  login,
  users,
  protect,
  restrictTo,
  deleteSellerOrUser,
  forgotPassword,
  resetPassword,
  updatePassword
} = require('./../controllers/authController');
const {
  productValidatorResponse,
  addProduct,
  getProduct,
  getProducts,
  updateProduct,
  deleteProduct
} = require('./../controllers/product');
/**
 * routes only without params or query string
 */
const router = express.Router();

router.post('/signup', signup);
router.post('/login', login);
router.post('/forgotPassword', forgotPassword);
router.patch('/resetPassword/:token', resetPassword);
router.patch('/updatePassword/', protect, updatePassword);

router.get('/users', protect, restrictTo('admin'), users); //list all users
router.delete('/users/:id', protect, restrictTo('admin'), deleteSellerOrUser);

router.post(
  '/product',
  protect,
  restrictTo('admin', 'seller'),
  productValidatorResponse,
  addProduct
);
router.put(
  '/product/:id',
  protect,
  restrictTo('seller'),
  productValidatorResponse,
  updateProduct
);
router.delete(
  '/product/:id',
  protect,
  restrictTo('seller', 'admin'),
  deleteProduct
);
router.get(
  '/products',
  protect,
  restrictTo('amin', 'user', 'seller'),
  getProducts
);
router.get(
  '/product/?',
  protect,
  restrictTo('admin', 'user', 'seller'),
  getProduct
);

module.exports = router;
