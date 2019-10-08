const mongoose = require('mongoose');

const productSchema = new mongoose.Schema({
    name: {
        type: String,
        required: [true, 'A product must have a productName'],
        unique: true,
    },
    category: {
        type: String,
        required: [true, 'A category is needed'],
        unique: true
    },
    description: {
        type: String,
        required: [true, 'A description is needed'],
        min: (8),
        max: (255)
    },
    shortDescription: {
        type: String,
        required: [true, 'A description is needed to show'],
        min: (8),
        max: (255)
    },
    image: {
        type: String,
        required: [true, 'Every user must have an image']
    },
    soldBy: {
        sellerId:{
            type: String,
            required:[true,'A product seller must have an id']
        },
        sellerName:{
            type: String,
            required:[true,'A product seller must have a name']
        }
    }
});

const ProductData = mongoose.model('product', productSchema);

module.exports = ProductData;
