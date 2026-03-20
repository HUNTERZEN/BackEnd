const express = require('express');
const router = express.Router();
const Partner = require('../models/Partner');
const authMiddleware = require('../authMiddleware');

// POST /api/partner/register
router.post('/register', authMiddleware, async (req, res) => {
  try {
    const userId = req.user.userId; // Extract from token via authMiddleware

    // Check if user is already a partner
    const existingPartner = await Partner.findOne({ userId });
    if (existingPartner) {
      return res.status(400).json({ message: 'User is already registered as a partner' });
    }

    const partnerData = {
      userId,
      ...req.body
    };

    const newPartner = new Partner(partnerData);
    await newPartner.save();

    res.status(201).json({ message: 'Partner registered successfully', partner: newPartner });
  } catch (error) {
    console.error('Error in partner registration:', error);
    res.status(500).json({ message: 'Failed to register partner', error: error.message });
  }
});

// GET /api/partner/profile
router.get('/profile', authMiddleware, async (req, res) => {
  try {
    const userId = req.user.userId;
    const partner = await Partner.findOne({ userId });

    if (!partner) {
      return res.status(404).json({ message: 'Partner profile not found' });
    }

    res.status(200).json({ partner });
  } catch (error) {
    console.error('Error fetching partner profile:', error);
    res.status(500).json({ message: 'Failed to fetch partner profile' });
  }
});

module.exports = router;
