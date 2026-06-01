const { MongoClient, ObjectId } = require("mongodb");

// Environment variables set in Netlify
const MONGO_URI = process.env.MONGODB_URI || process.env.MONGO_URI;
const DB_NAME = process.env.DB_NAME || "auth_db";
const COLLECTION_NAME = "users";

// Hardcoded admin credentials (or you can keep them in env)
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || "admin";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "admin123";

let cachedClient = null;

async function getDb() {
  if (!MONGO_URI) {
    throw new Error("Missing MONGODB_URI environment variable");
  }

  if (cachedClient) return cachedClient.db(DB_NAME);
  const client = new MongoClient(MONGO_URI);
  await client.connect();
  cachedClient = client;
  return client.db(DB_NAME);
}

function json(statusCode, body) {
  return {
    statusCode,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  };
}

exports.handler = async (event) => {
  if (event.httpMethod !== "POST") {
    return { statusCode: 405, body: "Method Not Allowed" };
  }

  try {
    const { action, username, password, token, newUsername, newPassword, newRole, userId } = JSON.parse(event.body || "{}");

    // ---------- LOGIN ----------
    if (action === "login") {
      // Check the admin account before opening MongoDB, so a DB config issue
      // does not block dashboard access.
      if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
        const token = Buffer.from(`${username}:${Date.now()}`).toString("base64");
        return json(200, { token, role: "admin" });
      }

      const db = await getDb();
      const usersCollection = db.collection(COLLECTION_NAME);
      const user = await usersCollection.findOne({ username, password });
      if (user) {
        const token = Buffer.from(`${username}:${Date.now()}`).toString("base64");
        return json(200, { token, role: user.role });
      }

      return json(401, { error: "Invalid username or password" });
    }

    // Helper: verify admin token (simple check)
    function isAdmin(token) {
      if (!token) return false;
      try {
        const decoded = Buffer.from(token, "base64").toString();
        const [user] = decoded.split(":");
        return user === ADMIN_USERNAME;
      } catch {
        return false;
      }
    }

    // All other actions require admin privileges
    if (!isAdmin(token)) {
      return json(403, { error: "Forbidden: admin access required" });
    }

    const db = await getDb();
    const usersCollection = db.collection(COLLECTION_NAME);

    // Ensure unique index on username
    await usersCollection.createIndex({ username: 1 }, { unique: true });

    // ---------- CREATE USER ----------
    if (action === "createUser") {
      if (!newUsername || !newPassword) {
        return json(400, { error: "Username and password required" });
      }
      const role = newRole === "admin" ? "admin" : "user";
      try {
        const result = await usersCollection.insertOne({
          username: newUsername,
          password: newPassword, // In production, hash the password!
          role: role,
          createdAt: new Date(),
        });
        return json(200, { user: newUsername, id: result.insertedId });
      } catch (err) {
        if (err.code === 11000) {
          return json(400, { error: "Username already exists" });
        }
        return json(500, { error: "Database error" });
      }
    }

    // ---------- LIST USERS ----------
    if (action === "listUsers") {
      const users = await usersCollection.find({}, { projection: { password: 0 } }).toArray();
      return json(200, { users });
    }

    // ---------- DELETE USER ----------
    if (action === "deleteUser") {
      if (!userId) {
        return json(400, { error: "User ID required" });
      }
      // Prevent deleting the main admin (optional safety)
      const objectId = new ObjectId(userId);
      const toDelete = await usersCollection.findOne({ _id: objectId });
      if (toDelete && toDelete.username === ADMIN_USERNAME) {
        return json(403, { error: "Cannot delete the main admin account" });
      }
      const result = await usersCollection.deleteOne({ _id: objectId });
      if (result.deletedCount === 0) {
        return json(404, { error: "User not found" });
      }
      return json(200, { message: "User deleted successfully" });
    }

    return json(400, { error: "Unknown action" });
  } catch (err) {
    console.error(err);
    return json(500, { error: err.message || "Internal server error" });
  }
};
