const express = require("express");
const { MongoClient, ServerApiVersion } = require("mongodb");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const app = express();
require("dotenv").config();
const port = process.env.PORT || 5000;

//middleware
app.use(cors());
app.use(express.json());
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.v2tnkbl.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

//middleWare start ===============================================================
// const verifyToken = async (req, res, next) => {
//     if (!req.headers.authorization) {
//       return res.status(401).send({ message: "unauthorized access" });
//     }
//     const token = req.headers.authorization.split(" ")[1];
//     jwt.verify(token, process.env.ACCESS_TOKEN, (err, decoded) => {
//       if (err) {
//         return res.status(401).send({ message: "unauthorized access" });
//       }
//       req.decoded = decoded;
//       next();
//     });
//   };

//middleWare end ==========================================================

async function run() {
  try {
    // await client.connect();
    const database = client.db("mfsDB");
    const usersCollection = database.collection("users");

    // Connect the client to the server	(optional starting in v4.7)

    app.post("/jwt", async (req, res) => {
      const user = req.body;
      console.log(user);
      const token = jwt.sign(user, process.env.ACCESS_TOKEN, {
        expiresIn: "1h",
      });
      res.send({ token });
    });
    // login and register related api ===========================================================
    app.get("/login", async (req, res) => {
      const { email, pin } = req.query;
      try {
        const user = await usersCollection.findOne({ userId: email });
        // console.log(data);
       
        if (!user) {
          return res.send({ error: "User not found" });
        }

        const isMatch = await bcrypt.compare(pin, user?.hashedPin);
        if (!isMatch) {
          return res.send({ error: "Invalid pin" });
        }
        res.send(user);
      } catch (error) {
        res.status(500).send({ error: "Login failed" });
      }
    });

    app.post("/register", async (req, res) => {
      const { userId, pin, role, status } = req.body;
      const query = { userId: userId };
      const isExistUser = await usersCollection.findOne(query);

      if (isExistUser) {
        return res.send("User Already Exist!");
      }

      const hashedPin = await bcrypt.hash(pin, 10);
      const userInfo = {
        userId,
        hashedPin,
        role,
        status,
      };
      const result = await usersCollection.insertOne(userInfo);
      res.send(result);
    });
    // login and register related api end ===========================================================

    // Send a ping to confirm a successful connection
    await client.db("admin").command({ ping: 1 });
    console.log(
      "Pinged your deployment. You successfully connected to MongoDB!"
    );
  } finally {
    // Ensures that the client will close when you finish/error
    // await client.close();
  }
}
run().catch(console.dir);

app.get("/", (req, res) => {
  res.send("mfs running");
});

app.listen(port, () => {
  console.log(`MFS server is running on port ${port}`);
});
