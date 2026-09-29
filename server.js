require('dotenv').config();
const crypto = require('crypto');
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const mongoose = require('mongoose');

/* ---------------- Config ---------------- */
const PORT = process.env.PORT || 4000;
const MONGODB_URI = process.env.MONGODB_URI;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '')
  .split(',')
  .map(s => s.trim().replace(/\/$/, ''))
  .filter(Boolean);

if (!MONGODB_URI) {
  console.error('CRITICAL: Missing MONGODB_URI environment variable. Server cannot start.');
  process.exit(1);
}
if (!ADMIN_PASSWORD || ADMIN_PASSWORD.length < 8) {
  console.error('CRITICAL: ADMIN_PASSWORD is missing or too short (min 8 characters). Set a strong password in .env or your host environment variables.');
  process.exit(1);
}

const DELIVERY_FEES = { inside: 110, outside: 150 };
const DELIVERY_LABELS = { inside: 'Inside Sylhet', outside: 'Outside Sylhet' };
const CATEGORIES = ['Samba', 'Nike Air', 'Air Force', 'Other'];
const PAY_METHODS = ['bKash', 'Nagad', 'Cash on Delivery'];
const ORDER_STATUSES = ['Pending confirmation', 'Confirmed', 'Shipped', 'Delivered', 'Cancelled'];

/* ---------------- App + Security Middleware ---------------- */
const app = express();
app.set('trust proxy', 1); // Needed behind reverse proxies (Render, Cloudflare, etc.)

app.use(helmet({
  crossOriginResourcePolicy: { policy: 'cross-origin' }
}));

app.use(cors({
  origin(origin, cb) {
    if (!origin) return cb(null, true); // Mobile apps, curl, server-to-server, health checks
    if (!ALLOWED_ORIGINS.length) return cb(null, true); // Dev default if empty
    if (ALLOWED_ORIGINS.includes(origin) || ALLOWED_ORIGINS.includes('*')) return cb(null, true);
    // Allow localhost/127.0.0.1 for local development
    if (/^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin)) return cb(null, true);
    cb(new Error(`CORS blocked origin: ${origin}`));
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'x-admin-password'],
  credentials: true
}));

const limiterBase = { standardHeaders: 'draft-7', legacyHeaders: false };

// General API rate limiter (300 requests per 15 minutes)
const apiLimiter = rateLimit({
  ...limiterBase,
  windowMs: 15 * 60 * 1000,
  limit: 300,
  message: { error: 'Too many requests. Please try again later.' }
});

// Stricter limiter for public order placements (15 orders per hour per IP)
const orderLimiter = rateLimit({
  ...limiterBase,
  windowMs: 60 * 60 * 1000,
  limit: 15,
  message: { error: 'Too many orders placed from this network. Please try again in an hour.' }
});

// Admin login / auth brute-force limiter (counts only failed attempts)
const adminFailLimiter = rateLimit({
  ...limiterBase,
  windowMs: 15 * 60 * 1000,
  limit: 10,
  skipSuccessfulRequests: true,
  message: { error: 'Too many failed login attempts. Try again in 15 minutes.' }
});

app.use('/api', apiLimiter);

/* ---------------- Database ---------------- */
mongoose.connect(MONGODB_URI)
  .then(() => console.log('✓ Successfully connected to MongoDB Atlas'))
  .catch(err => {
    console.error('MongoDB connection error:', err.message);
    process.exit(1);
  });

const productSchema = new mongoose.Schema({
  name: { type: String, required: true, maxlength: 120, trim: true },
  price: { type: Number, required: true, min: 1 },
  sizes: { type: [String], default: [] },
  stock: { type: Number, default: 0, min: 0 },
  desc: { type: String, default: '', maxlength: 2000, trim: true },
  images: { type: [String], default: [] },
  video: { type: String, default: null },
  category: { type: String, enum: CATEGORIES, default: 'Other' },
  bestSeller: { type: Boolean, default: false }
}, { timestamps: true });

// Transform _id to id in JSON outputs for frontend consistency
productSchema.set('toJSON', {
  virtuals: true,
  transform: (doc, ret) => {
    ret.id = ret._id.toString();
    return ret;
  }
});

const orderSchema = new mongoose.Schema({
  orderId: { type: String, required: true, unique: true, index: true },
  name: { type: String, required: true, trim: true },
  phone: { type: String, required: true, trim: true },
  address: { type: String, required: true, trim: true },
  payMethod: { type: String, enum: PAY_METHODS, required: true },
  trx: { type: String, required: true, index: true },
  deliveryZone: { type: String, required: true },
  deliveryFee: { type: Number, required: true },
  items: [{
    productId: { type: mongoose.Schema.Types.ObjectId, ref: 'Product' },
    name: String,
    size: String,
    qty: Number,
    price: Number
  }],
  subtotal: { type: Number, required: true },
  total: { type: Number, required: true },
  status: { type: String, enum: ORDER_STATUSES, default: 'Pending confirmation' }
}, { timestamps: true });

orderSchema.set('toJSON', {
  virtuals: true,
  transform: (doc, ret) => {
    ret.id = ret.orderId || ret._id.toString();
    return ret;
  }
});

const Product = mongoose.model('Product', productSchema);
const Order = mongoose.model('Order', orderSchema);

/* ---------------- Helpers ---------------- */
const isObjectId = id => /^[a-f\d]{24}$/i.test(String(id));
const serverError = (res, e) => {
  console.error('Server error:', e);
  res.status(500).json({ error: 'Internal server error' });
};

function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const ha = crypto.createHash('sha256').update(a).digest();
  const hb = crypto.createHash('sha256').update(b).digest();
  return crypto.timingSafeEqual(ha, hb);
}

function requireAdmin(req, res, next) {
  const incoming = req.header('x-admin-password') || '';
  if (!safeEqual(incoming, ADMIN_PASSWORD)) {
    return res.status(401).json({ error: 'Unauthorized: Invalid admin credentials' });
  }
  next();
}

const adminGate = [adminFailLimiter, requireAdmin];

// Clean and whitelist product fields to prevent mass assignment
function cleanProduct(b, partial = false) {
  const out = {};
  if (!partial || b.name !== undefined) {
    if (typeof b.name !== 'string' || !b.name.trim()) return { error: 'Product name is required.' };
    out.name = b.name.trim().slice(0, 120);
  }
  if (!partial || b.price !== undefined) {
    const n = Number(b.price);
    if (!Number.isFinite(n) || n <= 0 || n > 1000000) return { error: 'Price must be a valid positive number.' };
    out.price = Math.round(n);
  }
  if (!partial || b.sizes !== undefined) {
    if (!Array.isArray(b.sizes)) return { error: 'Sizes must be a list of size strings.' };
    out.sizes = b.sizes.map(s => String(s).trim().slice(0, 10)).filter(Boolean).slice(0, 30);
    if (!out.sizes.length) return { error: 'At least one size is required.' };
  }
  if (b.stock !== undefined) {
    const n = parseInt(b.stock, 10);
    if (!Number.isInteger(n) || n < 0 || n > 100000) return { error: 'Stock must be a non-negative integer.' };
    out.stock = n;
  }
  if (b.desc !== undefined) {
    out.desc = String(b.desc || '').trim().slice(0, 2000);
  }
  if (b.images !== undefined) {
    if (!Array.isArray(b.images) || b.images.length > 4) return { error: 'A maximum of 4 images is allowed.' };
    for (const img of b.images) {
      if (typeof img !== 'string' || img.length > 3500000 ||
          !/^(https?:\/\/|data:image\/(jpeg|png|webp|gif);base64,)/i.test(img)) {
        return { error: 'One or more images are invalid or too large.' };
      }
    }
    out.images = b.images;
  }
  if (b.video !== undefined) {
    if (b.video === null || b.video === '') {
      out.video = null;
    } else if (typeof b.video === 'string' && /^https?:\/\//i.test(b.video)) {
      out.video = b.video.slice(0, 500);
    } else {
      return { error: 'Invalid video URL.' };
    }
  }
  if (b.category !== undefined) {
    if (!CATEGORIES.includes(b.category)) return { error: `Category must be one of: ${CATEGORIES.join(', ')}` };
    out.category = b.category;
  }
  if (b.bestSeller !== undefined) {
    out.bestSeller = b.bestSeller === true;
  }
  return { data: out };
}

async function restoreStock(reserved) {
  for (const r of reserved) {
    try {
      await Product.updateOne({ _id: r.pid }, { $inc: { stock: r.qty } });
    } catch (e) {
      console.error('Stock restore error:', r, e.message);
    }
  }
}

/* ---------------- Health Check ---------------- */
app.get('/', (req, res) => res.json({
  ok: true,
  service: 'ruso-backend',
  version: '1.0.0',
  uptime: Math.floor(process.uptime())
}));

/* ---------------- Admin Authentication ---------------- */
app.post('/api/admin/login', adminGate, (req, res) => {
  res.json({ ok: true, message: 'Authentication successful' });
});

/* ---------------- Product Routes ---------------- */
// Public: list all products
app.get('/api/products', async (req, res) => {
  try {
    const products = await Product.find().sort({ createdAt: -1 });
    res.json(products);
  } catch (e) {
    serverError(res, e);
  }
});

// Admin: add product
app.post('/api/products', adminGate, express.json({ limit: '15mb' }), async (req, res) => {
  try {
    const { data, error } = cleanProduct(req.body || {}, false);
    if (error) return res.status(400).json({ error });
    const p = await Product.create(data);
    res.status(201).json(p);
  } catch (e) {
    serverError(res, e);
  }
});

// Admin: update product
app.put('/api/products/:id', adminGate, express.json({ limit: '15mb' }), async (req, res) => {
  try {
    if (!isObjectId(req.params.id)) return res.status(400).json({ error: 'Invalid product ID' });
    const { data, error } = cleanProduct(req.body || {}, true);
    if (error) return res.status(400).json({ error });
    if (!Object.keys(data).length) return res.status(400).json({ error: 'No valid fields provided for update.' });

    const p = await Product.findByIdAndUpdate(req.params.id, { $set: data }, { new: true, runValidators: true });
    if (!p) return res.status(404).json({ error: 'Product not found' });
    res.json(p);
  } catch (e) {
    serverError(res, e);
  }
});

// Admin: delete product
app.delete('/api/products/:id', adminGate, async (req, res) => {
  try {
    if (!isObjectId(req.params.id)) return res.status(400).json({ error: 'Invalid product ID' });
    const p = await Product.findByIdAndDelete(req.params.id);
    if (!p) return res.status(404).json({ error: 'Product not found' });
    res.json({ ok: true, message: 'Product deleted' });
  } catch (e) {
    serverError(res, e);
  }
});

/* ---------------- Order Routes ---------------- */
// Public: place an order.
// Server strictly recomputes prices, validates stock, reserves stock atomically, and ignores any client total/status.
app.post('/api/orders', orderLimiter, express.json({ limit: '20kb' }), async (req, res) => {
  const bad = (msg, code = 400) => res.status(code).json({ error: msg });
  const reserved = [];

  try {
    const b = req.body || {};
    const name = typeof b.name === 'string' ? b.name.trim() : '';
    const phone = typeof b.phone === 'string' ? b.phone.replace(/[\s-]/g, '') : '';
    const address = typeof b.address === 'string' ? b.address.trim() : '';
    const payMethod = typeof b.payMethod === 'string' ? b.payMethod.trim() : '';
    let trx = typeof b.trx === 'string' ? b.trx.trim().toUpperCase() : '';
    const zone = b.deliveryZone;

    if (name.length < 2 || name.length > 100) return bad('Please enter your full name.');
    if (!/^01[0-9]{9}$/.test(phone)) return bad('Please enter a valid WhatsApp number (01XXXXXXXXX).');
    if (address.length < 6 || address.length > 300) return bad('Please enter your full delivery address.');
    if (!PAY_METHODS.includes(payMethod)) return bad('Invalid payment method.');
    if (zone !== 'inside' && zone !== 'outside') return bad('Invalid delivery location.');
    if (!Array.isArray(b.items) || b.items.length < 1 || b.items.length > 20) return bad('Cart is empty or contains too many items.');

    // Transaction ID handling: required for bKash/Nagad, generated/optional for Cash on Delivery
    if (payMethod === 'Cash on Delivery') {
      if (!trx) {
        trx = 'COD-' + crypto.randomBytes(4).toString('hex').toUpperCase();
      }
    } else {
      if (!/^[A-Z0-9]{4,30}$/.test(trx)) {
        return bad('Please enter a valid bKash/Nagad Transaction ID.');
      }
      // Reject duplicate TrxID for digital payment methods
      const existingTrx = await Order.findOne({ trx });
      if (existingTrx) {
        return bad('This Transaction ID has already been used for another order. Please check your payment details.', 409);
      }
    }

    const wanted = [];
    for (const it of b.items) {
      const qty = Number(it && it.qty);
      const size = it && typeof it.size === 'string' ? it.size.trim() : '';
      if (!it || !isObjectId(it.productId) || !Number.isInteger(qty) || qty < 1 || qty > 10 || !size) {
        return bad('Invalid cart item specifications.');
      }
      wanted.push({ productId: String(it.productId), size, qty });
    }

    // Look up real prices and stock from the Database
    const ids = [...new Set(wanted.map(w => w.productId))];
    const found = await Product.find({ _id: { $in: ids } });
    const byId = new Map(found.map(p => [String(p._id), p]));

    const qtyByProduct = {};
    const lineItems = [];
    let subtotal = 0;

    for (const w of wanted) {
      const p = byId.get(w.productId);
      if (!p) return bad('A product in your cart is no longer available.');
      if (!p.sizes.includes(w.size)) return bad(`Size ${w.size} is not available for ${p.name}.`);

      qtyByProduct[w.productId] = (qtyByProduct[w.productId] || 0) + w.qty;
      if (qtyByProduct[w.productId] > p.stock) {
        return bad(p.stock <= 0 ? `${p.name} is currently out of stock.` : `Only ${p.stock} pair(s) left of ${p.name}.`);
      }

      lineItems.push({
        productId: p._id,
        name: p.name,
        size: w.size,
        qty: w.qty,
        price: p.price
      });
      subtotal += p.price * w.qty;
    }

    // Atomically decrement stock
    for (const [pid, qty] of Object.entries(qtyByProduct)) {
      const r = await Product.updateOne({ _id: pid, stock: { $gte: qty } }, { $inc: { stock: -qty } });
      if (r.modifiedCount !== 1) {
        await restoreStock(reserved);
        return res.status(409).json({ error: 'Sorry, another customer just bought the last pair. Please review your cart.' });
      }
      reserved.push({ pid, qty });
    }

    const deliveryFee = DELIVERY_FEES[zone];
    const total = subtotal + deliveryFee;

    // Retry loop for generating guaranteed collision-free order ID
    for (let attempt = 0; attempt < 5; attempt++) {
      try {
        const randomCode = crypto.randomInt(100000, 999999);
        const orderId = `RUSO-${randomCode}`;

        const order = await Order.create({
          orderId,
          name,
          phone,
          address,
          payMethod,
          trx,
          deliveryZone: DELIVERY_LABELS[zone],
          deliveryFee,
          items: lineItems,
          subtotal,
          total,
          status: 'Pending confirmation'
        });

        return res.status(201).json({
          ok: true,
          orderId: order.orderId,
          subtotal,
          deliveryFee,
          total: order.total,
          status: order.status
        });
      } catch (e) {
        if (e.code === 11000 && e.keyPattern && e.keyPattern.trx) {
          await restoreStock(reserved);
          return res.status(409).json({ error: 'This Transaction ID has already been recorded.' });
        }
        if (e.code === 11000 && e.keyPattern && e.keyPattern.orderId) {
          continue; // Collision on orderId, generate new code and retry
        }
        throw e;
      }
    }

    throw new Error('Failed to create order ID after multiple attempts.');
  } catch (e) {
    await restoreStock(reserved);
    serverError(res, e);
  }
});

// Admin: list all orders
app.get('/api/orders', adminGate, async (req, res) => {
  try {
    const orders = await Order.find().sort({ createdAt: -1 });
    res.json(orders);
  } catch (e) {
    serverError(res, e);
  }
});

// Admin: update order status
app.put('/api/orders/:id', adminGate, express.json({ limit: '5kb' }), async (req, res) => {
  try {
    const orderIdentifier = req.params.id;
    const status = req.body && req.body.status;
    if (!ORDER_STATUSES.includes(status)) {
      return res.status(400).json({ error: `Invalid status. Must be one of: ${ORDER_STATUSES.join(', ')}` });
    }

    let o;
    if (isObjectId(orderIdentifier)) {
      o = await Order.findByIdAndUpdate(orderIdentifier, { $set: { status } }, { new: true });
    } else {
      o = await Order.findOneAndUpdate({ orderId: orderIdentifier }, { $set: { status } }, { new: true });
    }

    if (!o) return res.status(404).json({ error: 'Order not found' });
    res.json(o);
  } catch (e) {
    serverError(res, e);
  }
});

/* ---------------- Global Error Handler ---------------- */
app.use((err, req, res, next) => {
  if (err.type === 'entity.too.large') {
    return res.status(413).json({ error: 'Upload payload is too large.' });
  }
  if (err.type === 'entity.parse.failed') {
    return res.status(400).json({ error: 'Malformed JSON in request body.' });
  }
  if (err.message && err.message.includes('CORS')) {
    return res.status(403).json({ error: err.message });
  }
  console.error('Unhandled express error:', err);
  res.status(500).json({ error: 'Server error' });
});

app.listen(PORT, () => console.log(`✓ RUSO Backend running smoothly on port ${PORT}`));