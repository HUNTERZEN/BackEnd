const mongoose = require('mongoose');

const partnerSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    unique: true
  },
  shopName: { type: String, required: true },
  ownerName: { type: String, required: true },
  email: { type: String, required: true },
  countryCode: { type: String, default: '+91' },
  phone: { type: String, required: true },
  address: { type: String, required: true },
  city: { type: String, required: true },
  state: { type: String, required: true },
  zipCode: { type: String },
  profession: { type: String, required: true },
  specializations: [{ type: String }],
  experience: { type: String, required: true },
  description: { type: String, required: true },
  servicesOffered: [{ type: String }],
  availableForCalls: { type: Boolean, default: true },
  availableForLiveService: { type: Boolean, default: true },
  workingHours: { type: String, required: true },
  certifications: { type: String },
  website: { type: String }
}, {
  timestamps: true
});

const Partner = mongoose.model('Partner', partnerSchema);
module.exports = Partner;
