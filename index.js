const express = require('express');
const cors = require('cors');
const dns = require('dns');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const compression = require('compression');
require('dotenv').config();

const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const { initializeApp, cert } = require('firebase-admin/app');
const { getAuth } = require('firebase-admin/auth');

// DNS resolver for reliable SRV lookups in some environments
dns.setServers(['8.8.8.8', '1.1.1.1']);

const app = express();
const port = process.env.PORT || 3000;

// 1. Security Headers & Compression
app.disable('x-powered-by');
app.use(helmet());
app.use(compression());

// 2. Rate Limiting (DoS / Brute-force protection)
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 150, // Max 150 requests per IP per 15 minutes
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, message: 'Too many requests, please try again later.' },
});
app.use('/models', apiLimiter);

// 3. CORS Configuration (Allowed frontend origins only)
const allowedOrigins = [
  'http://localhost:5173',
  'http://localhost:3000',
  'https://modelhub-96e69.web.app',
  process.env.CLIENT_URL,
].filter(Boolean);

app.use(
  cors({
    origin(origin, callback) {
      // Allow requests with no origin (e.g., curl, Postman, server-to-server) or from allowed origins
      if (!origin || allowedOrigins.includes(origin)) {
        return callback(null, true);
      }
      return callback(new Error('Not allowed by CORS'));
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
  })
);

// Limit JSON payload size to prevent DoS with large bodies
app.use(express.json({ limit: '100kb' }));

// 4. Firebase Admin Initialization
let serviceAccount;
try {
  if (process.env.FIREBASE_SERVICE_ACCOUNT_BASE64) {
    const decoded = Buffer.from(process.env.FIREBASE_SERVICE_ACCOUNT_BASE64, 'base64').toString('utf8');
    serviceAccount = JSON.parse(decoded);
  } else {
    // Matches the file name in your project root: firebase-adminsdk.json
    serviceAccount = require('./firebase-adminsdk.json');
  }
} catch (err) {
  console.error('Failed to load Firebase service account:', err.message);
  process.exit(1);
}

initializeApp({
  credential: cert(serviceAccount),
});

const auth = getAuth();

// 5. MongoDB Client (Initialized once and reused across requests)
const uri = process.env.MONGODB_URI;
if (!uri) {
  console.error('Missing MONGODB_URI in environment variables');
  process.exit(1);
}

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
  maxPoolSize: 20,
  minPoolSize: 2,
});

let dbPromise = null;

async function getCollections() {
  if (!dbPromise) {
    dbPromise = client
      .connect()
      .then(async () => {
        const db = client.db('modelDB');
        const modelsCollection = db.collection('models');
        const downloadsCollection = db.collection('downloads');
        const cartCollection = db.collection('carts');

        // Create index for faster sorting without crashing if it fails
        await modelsCollection.createIndex({ createdAt: -1 }).catch(() => {});
        return { modelsCollection, downloadsCollection, cartCollection };
      })
      .catch((err) => {
        dbPromise = null;
        throw err;
      });
  }
  return dbPromise;
}

// Helper: Sanitize string inputs to reduce XSS and injection risks
function sanitizeString(value, maxLen = 500) {
  if (typeof value !== 'string') return '';
  return value
    .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
    .replace(/[<>]/g, '')
    .trim()
    .slice(0, maxLen);
}

function buildModelPayload(body = {}) {
  const payload = {};

  if (body.name !== undefined) payload.name = sanitizeString(body.name, 120);
  if (body.title !== undefined) payload.title = sanitizeString(body.title, 150);
  if (body.category !== undefined) payload.category = sanitizeString(body.category, 80);
  if (body.description !== undefined) payload.description = sanitizeString(body.description, 2000);
  if (body.image !== undefined) {
    const cleanUrl = sanitizeString(body.image, 500);
    if (cleanUrl && /^https?:\/\//i.test(cleanUrl)) {
      payload.image = cleanUrl;
    }
  }
  if (
    body.price !== undefined &&
    typeof body.price === 'number' &&
    Number.isFinite(body.price) &&
    body.price >= 0
  ) {
    payload.price = body.price;
  }

  return payload;
}

function resolveIdQuery(id) {
  if (ObjectId.isValid(id) && String(new ObjectId(id)) === id) {
    return { _id: new ObjectId(id) };
  }
  return { _id: id };
}

// 6. Verify Token Middleware
const verifyToken = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).send({ message: 'unauthorized access' });
    }

    const token = authHeader.split(' ')[1];
    if (!token) {
      return res.status(401).send({ message: 'unauthorized access' });
    }

    const decodedToken = await auth.verifyIdToken(token);
    req.decodedToken = decodedToken;
    next();
  } catch (error) {
    console.error('Token verification error:', error.message);
    return res.status(401).send({ message: 'unauthorized access' });
  }
};

// 7. Root Route
app.get('/', (req, res) => {
  res.status(200).send('new server is running');
});

// 8. Models Routes
// GET all models (supports pagination and excludes heavy description field)
app.get('/models', async (req, res) => {
  try {
    const { modelsCollection } = await getCollections();
    const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 50, 1), 100);
    const skip = Math.max(parseInt(req.query.skip, 10) || 0, 0);

    const models = await modelsCollection
      .find({}, { projection: { description: 0 } })
      .skip(skip)
      .limit(limit)
      .toArray();

    res.status(200).send(models);
  } catch (error) {
    console.error('Error fetching models:', error);
    res.status(500).send({ success: false, message: 'Failed to fetch models' });
  }
});

// POST new model (protected + sanitized)
app.post('/models', verifyToken, async (req, res) => {
  try {
    const { modelsCollection } = await getCollections();
    const cleanData = buildModelPayload(req.body);

    if (!cleanData.name && !cleanData.title) {
      return res.status(400).send({ success: false, message: 'Model name or title is required' });
    }

    const docToInsert = {
      ...cleanData,
      createdBy: req.decodedToken.email || req.decodedToken.uid,
      createdAt: new Date(),
    };

    const result = await modelsCollection.insertOne(docToInsert);
    res.status(201).send({ success: true, insertedId: result.insertedId });
  } catch (error) {
    console.error('Error posting model:', error);
    res.status(500).send({ success: false, message: 'Failed to post model' });
  }
});

// GET single model by ID
app.get('/models/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { modelsCollection } = await getCollections();
    const query = resolveIdQuery(id);

    const model = await modelsCollection.findOne(query);
    if (!model) {
      return res.status(404).send({ success: false, message: 'Model not found' });
    }

    res.status(200).send(model);
  } catch (error) {
    console.error('Error fetching model by id:', error);
    res.status(500).send({ success: false, message: 'Failed to fetch model' });
  }
});

// UPDATE model by ID (protected + sanitized)
app.put('/models/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { modelsCollection } = await getCollections();
    const query = resolveIdQuery(id);
    const updates = buildModelPayload(req.body);

    if (Object.keys(updates).length === 0) {
      return res.status(400).send({ success: false, message: 'No valid fields to update' });
    }

    updates.updatedAt = new Date();

    const result = await modelsCollection.updateOne(query, { $set: updates });
    if (result.matchedCount === 0) {
      return res.status(404).send({ success: false, message: 'Model not found' });
    }

    res.status(200).send({ success: true, modifiedCount: result.modifiedCount });
  } catch (error) {
    console.error('Error updating model:', error);
    res.status(500).send({ success: false, message: 'Failed to update model' });
  }
});

// DELETE model by ID (protected)
app.delete('/models/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { modelsCollection } = await getCollections();
    const query = resolveIdQuery(id);

    const result = await modelsCollection.deleteOne(query);
    if (result.deletedCount === 0) {
      return res.status(404).send({ success: false, message: 'Model not found' });
    }

    res.status(200).send({ success: true, deletedCount: result.deletedCount });
  } catch (error) {
    console.error('Error deleting model:', error);
    res.status(500).send({ success: false, message: 'Failed to delete model' });
  }
});

// Global error handler
app.use((err, req, res, next) => {
  if (err && err.message === 'Not allowed by CORS') {
    return res.status(403).send({ success: false, message: 'CORS policy blocked this request' });
  }
  console.error('Unhandled error:', err);
  res.status(500).send({ success: false, message: 'Internal server error' });
});

if (!process.env.VERCEL) {
  app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
  });
}

module.exports = app;