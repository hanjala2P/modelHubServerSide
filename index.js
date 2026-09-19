const express = require('express');
const cors = require('cors');
const dns = require("dns");
const dotenv = require("dotenv");

// DNS 
dns.setServers(["8.8.8.8", "1.1.1.1"]);
dotenv.config();

const app = express();
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const { initializeApp, cert } = require("firebase-admin/app");
const { getAuth } = require("firebase-admin/auth");

const serviceAccount = require("./serviceAccountKey.json");

initializeApp({
  credential: cert(serviceAccount)
});

app.use(cors());
app.use(express.json());

const port = process.env.PORT || 3000;

const uri = process.env.MONGODB_URI;

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});

async function run() {
  try {
    // Connect the client to the server
    await client.connect();

    const db = client.db('modelDB');
    const modelCollection = db.collection('models');
    const downloadsCollection = db.collection('downloads');
    const cartCollection = db.collection('carts');

    // Root route
    app.get('/', (req, res) => {
        res.send('new server is running');
    });

    // Verify Token Middleware
    const verifyToken = async (req, res, next) => {
      try {
        const authorization = req.headers.authorization;

        if (!authorization) {
          return res.status(401).send({
            message: "unauthorized access"
          });
        }

        const token = authorization.split(" ")[1];
        const decodedToken = await getAuth().verifyIdToken(token);
        req.decodedToken = decodedToken;
        next();
      } catch (error) {
        console.error("Token verification error:", error);
        return res.status(401).send({
          message: "unauthorized access"
        });
      }
    };

    // Get all models
    app.get('/models', async (req, res) => {
        try {
            const result = await modelCollection.find().toArray();
            res.send(result);
        } catch (error) {
            console.error("Error fetching models:", error);
            res.status(500).send({ success: false, message: "Failed to fetch models" });
        }
    });

    // Send data (Post model)
    app.post('/models', async (req, res) => {
      try {
        const data = req.body;
        const result = await modelCollection.insertOne(data);
        res.send({ success: true, result });
      } catch (error) {
        console.error("Error posting model:", error);
        res.status(500).send({ success: false, error: error.message });
      }
    });

    // Get data by id
    app.get('/models/:id', async (req, res) => {
      try {
        const { id } = req.params;
        let query;

        if (ObjectId.isValid(id)) {
          query = { _id: new ObjectId(id) };
        } else {
          query = { _id: id };
        }

        const result = await modelCollection.findOne(query);
        
        if (!result) {
          return res.status(404).send({ success: false, message: "Model not found" });
        }

        res.send({ success: true, result });
      } catch (error) {
        console.error("Error fetching model by id:", error);
        res.status(500).send({ success: false, error: error.message });
      }
    });

    // UPDATE DATA
    app.put('/models/:id', verifyToken, async (req, res) => {
      try {
        const { id } = req.params;
        if (!ObjectId.isValid(id)) {
          return res.status(400).send({ success: false, message: "Invalid ID format" });
        }

        const model = await modelCollection.findOne({ _id: new ObjectId(id) });
        if (!model) {
          return res.status(404).send({ success: false, message: "Model not found" });
        }

        const data = req.body;
        const filter = { _id: new ObjectId(id) };
        const update = {
          $set: data
        };
        const result = await modelCollection.updateOne(filter, update);
        
        res.send({
          success: true,
          result
        });
      } catch (error) {
        console.error("Error updating model:", error);
        res.status(500).send({ success: false, error: error.message });
      }
    });

    // DELETE DATA
    app.delete('/models/:id', verifyToken, async (req, res) => {
      try {
        const { id } = req.params;
        if (!ObjectId.isValid(id)) {
          return res.status(400).send({ success: false, message: "Invalid ID format" });
        }

        const model = await modelCollection.findOne({ _id: new ObjectId(id) });
        if (!model) {
          return res.status(404).send({ success: false, message: "Model not found" });
        }

        const filter = { _id: new ObjectId(id) };
        const result = await modelCollection.deleteOne(filter);
        
        res.send({
          success: true,
          result
        });
      } catch (error) {
        console.error("Error deleting model:", error);
        res.status(500).send({ success: false, error: error.message });
      }
    });

    // Recent data
    app.get('/latest-models', async (req, res) => {
      try {
        const result = await modelCollection.find().sort({ createdAt: -1 }).limit(6).toArray();
        res.send(result);
      } catch (error) {
        console.error("Error fetching latest models:", error);
        res.status(500).send({ message: "Failed to fetch latest models" });
      }
    });

    app.get('/my-models', verifyToken, async (req, res) => {
      try {
        const email = req.query.email;
        const query = { created_by: email };
        const result = await modelCollection.find(query).toArray();
        res.send(result);
      } catch (error) {
        console.error("Error fetching user models:", error);
        res.status(500).send({ message: "Failed to fetch user models" });
      }
    });

    // Download API
    app.post('/downloads/:id', async (req, res) => {
        try {
            const modelId = req.params.id; 
            if (!ObjectId.isValid(modelId)) {
              return res.status(400).send({ message: "Invalid Model ID format" });
            }
            const data = req.body;
            
            const result = await downloadsCollection.insertOne({
                ...data,
                model_id: modelId
            });

            const filter = { _id: new ObjectId(modelId) };
            const update = {
                $inc: {
                    downloads: 1
                }
            };
            
            const downloadCounted = await modelCollection.updateOne(filter, update);

            res.send({ result, downloadCounted });
            
        } catch (error) {
            console.error("Error updating download count:", error);
            res.status(500).send({ message: "Failed to update download count" });
        }
    });

    // My downloads API
    app.get('/my-downloads', async (req, res) => {
        try {
            const email = req.query.email;
            const query = { downloaded_by: email };
            const result = await downloadsCollection.find(query).toArray();
            res.send(result);
        } catch (error) {
            console.error("Error fetching downloads:", error);
            res.status(500).send({ message: "Failed to fetch downloads" });
        }
    });

    // Get cart items by user email
    app.get('/cart', verifyToken, async (req, res) => {
        try {
            const email = req.query.email;
            const query = { user_email: email };
            const result = await cartCollection.find(query).toArray();
            res.send(result);
        } catch (error) {
            console.error("Error fetching cart items:", error);
            res.status(500).send({ message: "Failed to fetch cart items" });
        }
    });

    // Add to Cart API
    app.post('/cart', verifyToken, async (req, res) => {
        try {
            const cartItem = req.body;
            
            const query = { 
                model_id: cartItem.model_id, 
                user_email: cartItem.user_email 
            };
            const existingItem = await cartCollection.findOne(query);

            if (existingItem) {
                return res.status(400).send({ message: "Product already in cart!" });
            }

            const result = await cartCollection.insertOne(cartItem);
            res.send(result);
        } catch (error) {
            console.error("Error adding to cart:", error);
            res.status(500).send({ message: "Failed to add to cart" });
        }
    });

    // Delete cart item by id
    app.delete('/cart/:id', async (req, res) => {
        try {
            const id = req.params.id;
            if (!ObjectId.isValid(id)) {
              return res.status(400).send({ message: "Invalid ID format" });
            }
            const query = { _id: new ObjectId(id) };
            const result = await cartCollection.deleteOne(query);
            res.send(result);
        } catch (error) {
            console.error("Error deleting cart item:", error);
            res.status(500).send({ message: "Failed to delete item" });
        }
    });

    // Search API
    app.get('/search', async (req, res) => {
      try {
        const search_text = req.query.search;
        const result = await modelCollection.find({ modelName: { $regex: search_text,$options: "i" } }).toArray();
        res.send(result);
      } catch (error) {
        console.error("Error searching models:", error);
        res.status(500).send({ message: "Failed to search models" });
      }
    });

    app.get('/hello', (req, res) => {
        res.send('got a get request');
    });

    // Send a ping to confirm a successful connection
    await client.db("admin").command({ ping: 1 });
    console.log("Pinged your deployment. You successfully connected to MongoDB!");

  } catch (err) {
    console.error("Database connection error:", err);
  }
}
run().catch(console.dir);

app.listen(port, () => {
    console.log(`new server running on port no ${port}`);
});