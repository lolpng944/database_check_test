const express = require("express");
const morgan = require("morgan");
const path = require("path");
const cron = require("node-cron");
const bodyParser = require("body-parser");
const sqlite3 = require("sqlite3").verbose();
const cors = require("cors");
const helmet = require("helmet");
const axios = require("axios");
const validator = require("validator");
const bcrypt = require("bcrypt");
const rateLimit = require("express-rate-limit");
const jwt = require("jsonwebtoken"); // Added JWT
const fs = require("fs");
const readline = require("readline");
require("dotenv").config();
const Discord = require("discord.js");
const { sanitize } = require("dompurify");
const webhookURL = process.env.DISCORD_KEY;

const app = express();
exports.app = app;
const port = 3000;

const accessLogStream = fs.createWriteStream(
  path.join(__dirname, "access.log"),
  { flags: "a" },
);
app.use(morgan("combined", { stream: accessLogStream }));

const limiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 Minute
  max: 60, // Maximale Anfragen pro IP-Adresse in diesem Zeitraum
  message:
    "Zu viele Anfragen vom gleichen Ort, bitte versuche es später erneut.",
});

app.use(cors());
app.use(bodyParser.json());
app.set("trust proxy", ["loopback", "linklocal", "uniquelocal"]);
app.use(limiter);
app.use(express.static("public"));

// Mittelware, um Anfragen von nicht autorisierten Ursprüngen abzulehnen
app.use((req, res, next) => {
  const allowedOrigins = [
    "https://turbowarp.org",
    "https://serve.gamejolt.net",
    "tw-editor://.",
  ];
  const origin = req.headers.origin;

  if (allowedOrigins.includes(origin)) {
    // Set CORS headers to allow requests from the authorized origin
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Access-Control-Allow-Methods", "GET, POST");
    res.setHeader(
      "Access-Control-Allow-Headers",
      "Content-Type, Authorization",
    );
    next();
  } else {
    // This is an unauthorized origin, reject the request
    console.log("Rejected request from unauthorized origin:", origin);
    return res.status(403).json({ error: "no contents" });
  }
});

const MAX_REQUEST_SIZE = 1500;
const MAX_PARAM_BODY_LENGTH = 40;

const checkRequestSize = (req, res, next) => {
  // Calculate the size of the request body
  const requestBodySize =
    JSON.stringify(req.body).length +
    JSON.stringify(req.params).length +
    // Add the estimated size of headers (adjust as needed)
    JSON.stringify(req.headers).length;

  // Check if the total size exceeds the limit
  if (requestBodySize > MAX_REQUEST_SIZE) {
    return res.status(400).json({
      message: "Request exceeds the character limit.",
    });
  }

  // Check if the length of req.params exceeds the limit
  if (JSON.stringify(req.params).length > MAX_PARAM_BODY_LENGTH) {
    return res.status(400).json({
      message: "Length of req.params exceeds the character limit.",
    });
  }

  // Check if the length of req.body exceeds the limit
  if (JSON.stringify(req.body).length > MAX_PARAM_BODY_LENGTH) {
    return res.status(400).json({
      message: "Length of req.body exceeds the character limit.",
    });
  }

  // If all checks pass, proceed to the next middleware
  next();
};

app.use(checkRequestSize);

const sanitizeInputs = (inputs) => {
  if (typeof inputs === "object" && inputs !== null) {
    if (Array.isArray(inputs)) {
      // Sanitize arrays
      return inputs.map((item) => sanitizeInputs(item));
    } else {
      // Sanitize objects
      const sanitizedInputs = {};
      for (const key in inputs) {
        if (Object.hasOwnProperty.call(inputs, key)) {
          sanitizedInputs[key] = sanitizeInputs(inputs[key]);
        }
      }
      return sanitizedInputs;
    }
  } else if (typeof inputs === "string") {
    // Sanitize strings using validator
    return validator.escape(inputs);
  } else if (typeof inputs === "number") {
    // Numbers don't need sanitization
    return inputs;
  } else if (typeof inputs === "boolean") {
    // Booleans don't typically require sanitization
    return inputs;
  } else if (inputs instanceof Date) {
    // Sanitize Date objects (e.g., convert to string)
    return inputs;
  } else {
    // Don't sanitize other types
    return inputs;
  }
};

app.use((req, res, next) => {
  req.body = sanitizeInputs(req.body);
  req.query = sanitizeInputs(req.query);
  req.params = sanitizeInputs(req.params);

  next();
});

const registerLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 15 Minuten
  max: 20, // Maximale Anfragen pro IP-Adresse in diesem Zeitraum
  message:
    "Zu viele Registrierungsanfragen von dieser IP-Adresse, bitte versuche es später erneut.",
});

const accountCreationLimit = rateLimit({
  windowMs: 24 * 60 * 60 * 1000, // 24 Stunden (pro Tag)
  max: 1, // Maximal 2 Anfragen pro IP-Adresse pro Tag
  message:
    "Sie haben bereits die maximale Anzahl von Benutzerkonten für heute erstellt.",
});

app.use(helmet({ poweredBy: false }));

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'none'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'"],
        fontSrc: ["'self'"],
        imgSrc: ["'none'"],
        connectSrc: ["'none'"],
        frameSrc: ["'none'"],
        mediaSrc: ["'none'"],
        objectSrc: ["'none'"],
        baseUri: ["'none'"],
        formAction: ["'none'"],
        frameAncestors: ["'none'"],
      },
    },
  }),
);

app.use(
  helmet({
    hsts: {
      maxAge: 31536000, // 1 year in seconds
      includeSubDomains: true,
      preload: true,
    },
  }),
);

app.use(
  helmet({
    contentSecurityPolicy: false, // Disable Helmet's default CSP
    hidePoweredBy: true, // Enable hiding the "X-Powered-By" header
    xssFilter: true, // Enable XSS filtering
    frameguard: { action: "deny" }, // Enable clickjacking protection
    expectCt: true, // Enable Certificate Transparency header
    dnsPrefetchControl: { allow: false }, // Disable DNS prefetching
    referrerPolicy: { policy: "same-origin" }, // Set referrer policy
    featurePolicy: {
      features: {
        geolocation: ["'none'"],
      },
    }, // Enable Feature Policy header
    permittedCrossDomainPolicies: { permittedPolicies: "none" }, // Disable Adobe Flash and Acrobat PDF plugins
    hsts: {
      maxAge: 31536000, // 1 year in seconds
      includeSubDomains: true,
      preload: true,
    }, // Enable HSTS header
    noSniff: true, // Enable X-Content-Type-Options header
    permissionsPolicy: {
      features: {
        accelerometer: ["'none'"],
        camera: ["'none'"],
        microphone: ["'none'"],
        geolocation: ["'none'"],
      },
    }, // Enable Permissions-Policy header
  }),
);

// Verwende ein zufälliges und sicheres Verschlüsselungsschlüssel
// const encryptionKey = crypto.randomBytes(32).toString('hex');
const encryptionKey = process.env.ENCRYPTION_KEY;

const db = new sqlite3.Database("database.db");

function getitemdata() {
  const itemsData = fs.readFileSync("items.txt", "utf8");
  const lines = itemsData.split("\n");

  db.serialize(() => {
    db.run("BEGIN TRANSACTION");

    // Delete existing items
    db.run("DELETE FROM item_data");

    // Insert new items
    const insertItem = db.prepare(
      "INSERT INTO item_data (id, name, price) VALUES (?, ?, ?)",
    );

    lines.forEach((line) => {
      const [itemId, itemName, itemPrice] = line.split(":");
      // Ensure itemPrice is a valid integer
      const parsedItemPrice = parseInt(itemPrice);
      if (!isNaN(parsedItemPrice)) {
        insertItem.run(itemId, itemName, parsedItemPrice);
      } else {
        console.error(`Invalid item price for item ${itemId}: ${itemPrice}`);
      }
    });

    insertItem.finalize();

    db.run("COMMIT", (err) => {
      if (err) {
        console.error("Error committing transaction:", err);
      } else {
        console.log("Items initialized successfully.");
      }
    });
  });
}

// Aktiviere den WAL-Modus
db.run("PRAGMA journal_mode = WAL", (err) => {
  if (err) {
    console.error("Fehler beim Aktivieren des WAL-Modus:", err);
  } else {
    console.log("WAL-Modus aktiviert.");
  }
});

db.run("PRAGMA wal_autocheckpoint = 20");

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY,
      username TEXT NOT NULL,
      password TEXT NOT NULL,
      salt TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      coins INTEGER DEFAULT 0,
      all_coins_earned INTEGER DEFAULT 0,
      last_collected INTEGER DEFAULT 0,
      equipped_item INTEGER DEFAULT 0,
      equipped_item2 INTEGER DEFAULT 0,
      equipped_banner INTEGER DEFAULT 0,
      equipped_pose INTEGER DEFAULT 0,
      equipped_color INTEGER DEFAULT 0,
      country_code TEXT DEFAULT 'Unknown'
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS coins (
      id INTEGER PRIMARY KEY,
      username TEXT NOT NULL,
      date TEXT NOT NULL
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS user_items (
      id INTEGER PRIMARY KEY,
      username TEXT NOT NULL,
      item_id TEXT NOT NULL
    )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS tokens (
      username TEXT NOT NULL,
      token TEXT NOT NULL
    )
  `);
  db.run(`
  CREATE TABLE IF NOT EXISTS item_data (
    id TEXT PRIMARY KEY,
    name TEXT,
    price INTEGER
    )
  `);
});

getitemdata();

let maintenanceMode = false;
// Middleware, um Wartungsarbeiten zu überprüfen
function checkMaintenanceMode(req, res, next) {
  if (maintenanceMode) {
    return res.status(503).send("Wartung");
  }
  next();
}

app.use(checkMaintenanceMode);

function canCollectCoins(lastCollected) {
  const now = Date.now();
  const twentyFourHoursInMs = 6 * 60 * 60 * 1000;
  // const twentyFourHoursInMs = 6 * 60 * 60 * 1000; // 24 Stunden in Millisekunden
  return now - lastCollected >= twentyFourHoursInMs;
}

function validateUserInput(username, password) {
  const usernameRegex = /^[\p{L}\p{N}_\-!@#$%^&*()+=,.;?{}[\]~|<>/\\]{4,16}$/u;
  //const usernameRegex = /^[a-zA-Z0-9_\-]{4,16}$/;
  const passwordRegex = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])[\S]{8,20}$/;

  if (!usernameRegex.test(username)) {
    return "Ungültiger Benutzername.";
  }

  if (!passwordRegex.test(password)) {
    return "Ungültiges Passwort.";
  }

  return null;
}

function validateChangeCredentials(newPassword) {
  const passwordRegex = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])[\S]{8,20}$/;

  if (!passwordRegex.test(newPassword)) {
    return "not valid password";
  }

  return null;
}

const activeSessions = new Map();

function checkActiveSessions(req, res, next) {
  const username = req.body.username || req.params.username;
  const clientIp = req.ip;

  if (activeSessions.has(username)) {
    const userSessions = activeSessions.get(username);

    for (const [ip, lastActiveTimestamp] of userSessions.entries()) {
      const currentTime = Date.now();
      if (currentTime - lastActiveTimestamp > INACTIVE_TIMEOUT) {
        userSessions.delete(ip);
      }
    }

    if (userSessions.size >= 2) {
      return res
        .status(401)
        .json({ message: "You already have two active sessions." });
    }
  }

  if (!activeSessions.has(username)) {
    activeSessions.set(username, new Map());
  }
  activeSessions.get(username).set(clientIp, Date.now());

  next();
}

function getCountryCode(userIp) {
  return axios
    .get(`https://ipinfo.io/${userIp}/json`)
    .then((response) => {
      const ipInfo = response.data;
      if (ipInfo && ipInfo.country) {
        return ipInfo.country;
      }
      return "Unknown";
    })
    .catch((error) => {
      console.error("Error while detecting the country:", error);
      return "Unknown";
    });
}

const INACTIVE_TIMEOUT = 1 * 60 * 1000;

const jwtSecret = process.env.TOKEN_KEY;

function generateToken(username) {
  // Step 1: Sign and encrypt the token
  const token = jwt.sign({ username }, jwtSecret, { expiresIn: "31d" });
  const encryptedToken = jwt.sign({ token }, encryptionKey, {
    algorithm: "HS256",
  });

  // Check if a token already exists for the given username
  const existingToken = db.get("SELECT token FROM tokens WHERE username = ?", [
    username,
  ]);

  if (existingToken) {
    // If a token already exists, update the existing token in the database
    db.run(
      "UPDATE tokens SET token = ? WHERE username = ?",
      [encryptedToken, username],
      (err) => {
        if (err) {
          console.error("Error updating token in the database:", err);
        }
      },
    );
  } else {
    // If no token exists, insert the generated token in the database
    db.run(
      "INSERT INTO tokens (username, token) VALUES (?, ?)",
      [username, encryptedToken],
      (err) => {
        if (err) {
          console.error("Error storing token in the database:", err);
        }
      },
    );
  }

  return encryptedToken;
}

function verifyToken(req, res, next) {
  const token = req.params.token;

  if (!token) {
    return res.status(401).json({ message: "Token is missing." });
  }

  // Step 1: Verify and decrypt the token
  jwt.verify(token, encryptionKey, (err, decoded) => {
    if (err) {
      return res.status(403).json({ message: "Invalid token." });
    }

    const { token: signedToken } = decoded;

    // Step 2: Verify the signed token using the JWT secret key
    jwt.verify(signedToken, jwtSecret, (err, decoded) => {
      if (err) {
        return res.status(403).json({ message: "Invalid token." });
      }

      // The token is valid, and decoded contains the user information
      const username = decoded.username;

      db.get(
        "SELECT coins FROM users WHERE username = ?",
        [username],
        async (err, userRow) => {
          if (err) {
            return res.status(500).json({ message: "Internal Server Error." });
          }

          if (!userRow) {
            return res.status(401).json({ message: "Invalid token." });
          }

          // Set the user information in the request
          req.user = { username: decoded.username };
          next();
        },
      );
    });
  });
}

const itemsFilePath = "shopitems.txt";
// Pfad zur Datei, in der die vorherige tägliche Rotation gespeichert wird
const previousRotationFilePath = "previous-rotation.txt";

const lastUpdateTimestampFilePath = "last-update-timestamp.txt";
let lastUpdateTimestamp = null; // Zeitstempel der letzten Aktualisierung

function loadLastUpdateTimestamp() {
  try {
    const timestampData = fs.readFileSync(lastUpdateTimestampFilePath, "utf8");
    lastUpdateTimestamp = parseInt(timestampData);
  } catch (err) {
    console.error(
      "Fehler beim Lesen des letzten Aktualisierungszeitstempels:",
      err,
    );
  }
}

function saveLastUpdateTimestamp() {
  try {
    fs.writeFileSync(lastUpdateTimestampFilePath, Date.now().toString()); // Aktuellen Zeitstempel speichern
  } catch (err) {
    console.error(
      "Fehler beim Speichern des Zeitstempels der letzten Aktualisierung:",
      err,
    );
  }
}

function shouldUpdateDailyRotation() {
  // Überprüfen, ob der Server nach Mitternacht gestartet wurde
  const now = new Date();
  const midnight = new Date();
  midnight.setHours(0, 0, 0, 0);

  return now > midnight && lastUpdateTimestamp < midnight.getTime();
}

let availableItems = []; // Definiere availableItems im globalen Geltungsbereich
let dailyItems = []; // Liste der täglich verfügbaren Gegenstände

// Funktion zum Lesen der Gegenstände aus der Datei und Hinzufügen zu availableItems
function loadAvailableItems() {
  try {
    const fileData = fs.readFileSync(itemsFilePath, "utf8");
    availableItems = fileData
      .split("\n")
      .map((item) => item.trim())
      .filter(Boolean);

    console.log("Verfügbare Gegenstände wurden aktualisiert.");
  } catch (err) {
    console.error("Fehler beim Lesen der Gegenstände aus der Datei:", err);
  }
}

// Funktion zum Lesen der vorherigen täglichen Rotation aus der Datei
function loadPreviousRotation() {
  try {
    const fileData = fs.readFileSync(previousRotationFilePath, "utf8");
    const lines = fileData.split("\n").filter((item) => item.trim() !== "");

    dailyItems = {};
    lines.forEach((line, index) => {
      dailyItems[(index + 1).toString()] = line.trim();
    });

    console.log("Vorherige tägliche Rotation wurde geladen.");
  } catch (err) {
    console.error(
      "Fehler beim Lesen der vorherigen täglichen Rotation aus der Datei:",
      err,
    );
  }
}

function load1PreviousRotation() {
  try {
    const data = fs.readFileSync("previous-rotation.txt", "utf8");
    return data.split("\n").map((item) => item.trim());
  } catch (error) {
    console.error("Error reading previous rotation file:", error.message);
    return [];
  }
}

function saveDailyRotation() {
  try {
    const lines = Object.values(dailyItems);
    fs.writeFileSync(previousRotationFilePath, lines.join("\n"));
  } catch (err) {
    console.error(
      "Fehler beim Speichern der täglichen Rotation in der Datei:",
      err,
    );
  }
}

// Funktion zum Zufälligen Auswählen von 4 Gegenständen für die Tagesrotation
function selectDailyItems() {
  let shuffledItems = [...availableItems]; // Use let instead of const
  dailyItems = {};

  const itemPrefixes = ["A", "B", "I", "P", "A", "B"];
  //const itemPrefixes = ["I", "I", "I", "I", "I", "I"];
  const selectedItemsSet = new Set(); // Use a set to track selected items

  // Load the previous rotation from the file
  const previousRotation = load1PreviousRotation();

  // Filter out items from previous rotation
  shuffledItems = shuffledItems.filter(
    (item) => !previousRotation.includes(item),
  );

  for (let i = 0; i < itemPrefixes.length; i++) {
    const prefix = itemPrefixes[i];

    // Filter items that start with the specified prefix and are not already selected
    const validItems = shuffledItems.filter(
      (item) => item.startsWith(prefix) && !selectedItemsSet.has(item),
    );

    if (validItems.length > 0) {
      const randomIndex = Math.floor(Math.random() * validItems.length);
      let selectedItem = validItems[randomIndex];

      // Clean up the selected item to remove carriage return characters
      selectedItem = cleanUpItem(selectedItem);

      dailyItems[(i + 1).toString()] = selectedItem;

      // Add the selected item to the set to prevent it from being selected again
      selectedItemsSet.add(selectedItem);

      // Remove the selected item from the shuffledItems array
      const indexToRemove = shuffledItems.indexOf(selectedItem);
      if (indexToRemove !== -1) {
        shuffledItems.splice(indexToRemove, 1);
      }
    } else {
      console.error(
        `Nicht genügend verfügbare Gegenstände mit dem Präfix ${prefix}.`,
      );
      return; // Exit the function if there are not enough valid items for a prefix
    }
  }

  // Save the current daily rotation to the file
  saveDailyRotation();
}

function cleanUpItem(item) {
  // Remove carriage return characters from the item
  return item.replace(/\r/g, "");
}

// Funktion zum Überprüfen, ob heute ein besonderes Datum ist (z.B. Valentinstag, Halloween oder Weihnachten)
function isSpecialDate() {
  const today = new Date();
  const month = today.getMonth() + 1; // Beachte, dass die Monate 0-basiert sind
  const day = today.getDate();

  if ((month === 12 && day >= 20 && day <= 26) || (month === 2 && day === 14)) {
    // Halloween: Am 31. Oktober
    // Weihnachten: Am 24. und 25. Dezember
    // Valentinstag: Am 14. Februar
    return true; // set to true to enable specialdays
  }

  return false; // set to true to enable specialdays
}

// Funktion zum Festlegen der täglichen Rotation für besondere Tage
function setSpecialDailyItems() {
  if (isSpecialDate()) {
    const today = new Date();
    const month = today.getMonth() + 1; // Beachte, dass die Monate 0-basiert sind
    const day = today.getDate();

    if (month === 12 && day >= 20 && day <= 26) {
      // Halloween: Am 31. Oktober
      dailyItems = createKeyedItems([
        "A024",
        "B021",
        "A013",
        "B010",
        "A017",
        "B014",
      ]);
    } else if (month === 2 && day === 14) {
      // Valentinstag: Am 14. Februar
      dailyItems = createKeyedItems([
        "A024",
        "B021",
        "A013",
        "B010",
        "A017",
        "B014",
      ]);
    }
  } else {
    selectDailyItems();
    }
  }

function createKeyedItems(items) {
  const keyedItems = {};
  items.forEach((item, index) => {
    keyedItems[index + 1] = item;
  });
  return keyedItems;
}

function initializeItems() {
  loadAvailableItems();
  loadPreviousRotation();
  loadLastUpdateTimestamp();

  if (shouldUpdateDailyRotation()) {
    setSpecialDailyItems();
    saveLastUpdateTimestamp();
  }
}

// Initialisieren der Gegenstände beim Serverstart
initializeItems();

// Täglich um Mitternacht (0:00 Uhr) die Gegenstände auswählen und aktualisieren
cron.schedule("0 23 * * *", () => {
  if (shouldUpdateDailyRotation()) {
    setSpecialDailyItems();
    saveLastUpdateTimestamp();
    console.log("Tagesrotation aktualisiert.");
  } else {
    console.log(
      "Die tägliche Rotation wird nicht aktualisiert, da nicht genügend Zeit vergangen ist.",
    );
  }
});

// Route zum Abrufen der aktuellen Tagesrotation
app.get("/daily-items/:token", verifyToken, (req, res) => {
  const token = req.params.token;

  res.json({ dailyItems });
});

app.post("/register", registerLimiter, (req, res) => {
  const { username, password } = req.body;

  const validationError = validateUserInput(username, password);

  if (validationError) {
    return res.status(400).json({ message: validationError });
  }

  const saltRounds = 10;
  const salt = bcrypt.genSaltSync(saltRounds);

  const hashedPassword = bcrypt.hashSync(password, salt);

  getCountryCode(req.ip).then((countryCode) => {
    const fallbackCountryCode = "Unknown";
    const finalCountryCode = countryCode || fallbackCountryCode;

    db.get(
      "SELECT * FROM users WHERE username COLLATE NOCASE = ?",
      [username],
      (err, row) => {
        if (err) {
          return res.status(500).json({ message: "Interner Serverfehler." });
        }

        if (row) {
          return res
            .status(400)
            .json({ message: "Benutzername bereits vergeben." });
        }

        if (username === password) {
          return res.status(400).json({
            message: "Benutzername und Passwort dürfen nicht identisch sein.",
          });
        }

        accountCreationLimit(req, res, () => {
          db.run(
            "INSERT INTO users (username, password, salt, country_code) VALUES (?, ?, ?, ?)",
            [username, hashedPassword, salt, finalCountryCode],
            (err) => {
              if (err) {
                return res
                  .status(500)
                  .json({ message: "Interner Serverfehler." });
              }

              const token = generateToken(username);
              checkActiveSessions(req, res, () => {
                res.json({
                  message: "Benutzerkonto erfolgreich erstellt.",
                  token,
                });
              });
            },
          );
        });
      },
    );
  });
});

app.post("/login", registerLimiter, (req, res) => {
  const { username, password } = req.body;

  db.get(
    "SELECT * FROM users WHERE username COLLATE NOCASE = ?",
    [username],
    (err, row) => {
      if (err) {
        return res.status(500).json({ message: "Interner Serverfehler." });
      }

      if (!row) {
        return res
          .status(401)
          .json({ message: "Ungültige Anmeldeinformationen." });
      }

      if (!bcrypt.compareSync(password, row.password)) {
        return res
          .status(401)
          .json({ message: "Ungültige Anmeldeinformationen." });
      }

      checkActiveSessions(req, res, () => {
        const token = generateToken(username);
        res.json({ message: "Anmeldung erfolgreich.", token });
      });
    },
  );
});

app.get("/get-coins/:token", verifyToken, (req, res) => {
  const token = req.params.token;
  const username = req.user.username;

  checkActiveSessions(req, res, () => {
    db.serialize(() => {
      db.run("BEGIN TRANSACTION");

      db.get(
        "SELECT * FROM users WHERE username = ?",
        [username],
        (err, row) => {
          if (err) {
            rollbackAndRespond(res, "Interner Serverfehler.");
            return;
          }

          if (!row) {
            rollbackAndRespond(res, "Ungültige Anmeldeinformationen.");
            return;
          }

          checkActiveSessions(req, res, () => {
            const lastCollected = row.last_collected || 0;

            if (!canCollectCoins(lastCollected)) {
              rollbackAndRespond(
                res,
                "Du kannst Coins erst alle 24 Stunden sammeln.",
              );
              return;
            }

            function generateRandomNumber(min, max) {
              return Math.floor(Math.random() * (max - min + 1)) + min;
            }
            const coinsToAdd = generateRandomNumber(45, 80);

            db.run(
              "UPDATE users SET coins = coins + ?, last_collected = ? WHERE username = ?",
              [coinsToAdd, Date.now(), username],
              (err) => {
                if (err) {
                  rollbackAndRespond(res, "Interner Serverfehler.");
                  return;
                }

                db.run(
                  "UPDATE users SET all_coins_earned = all_coins_earned + ? WHERE username = ?",
                  [coinsToAdd, username],
                  (err) => {
                    if (err) {
                      rollbackAndRespond(res, "Interner Serverfehler.");
                      return;
                    }

                    db.get(
                      "SELECT coins FROM users WHERE username = ?",
                      [username],
                      (err, userRow) => {
                        if (err) {
                          rollbackAndRespond(res, "Interner Serverfehler.");
                          return;
                        }

                        const coinsMessage = `${username} hat ${coinsToAdd} Coins erhalten.`;

                        const webhook = new Discord.WebhookClient({
                          url: webhookURL,
                        });
                        webhook.send(coinsMessage);

                        db.run("COMMIT", (err) => {
                          if (err) {
                            console.error(
                              "Fehler beim Beenden der Transaktion:",
                              err,
                            );
                          }

                          res.json({
                            message: `Du hast ${coinsToAdd} Coins erhalten.`,
                            coins: userRow.coins,
                          });
                        });
                      },
                    );
                  },
                );
              },
            );
          });
        },
      );
    });
  });
});

function rollbackAndRespond(res, message) {
  db.run("ROLLBACK", (err) => {
    if (err) {
      console.error("Fehler beim Rollback:", err);
    }

    res.status(500).json({ message: message });
  });
}

app.post("/buy-item/:token/:itemId", verifyToken, async (req, res) => {
  const { itemId } = req.params;
  const token = req.params.token;
  const username = req.user.username;

  db.serialize(() => {
    db.run("BEGIN TRANSACTION");

    db.get(
      "SELECT coins FROM users WHERE username = ?",
      [username],
      async (err, userRow) => {
        if (err) {
          rollbackAndRespond(res, "Interner Serverfehler.");
          return;
        }

        if (!userRow) {
          rollbackAndRespond(res, "Ungültige Anmeldeinformationen.");
          return;
        }

        checkActiveSessions(req, res, () => {
          db.get(
            "SELECT * FROM user_items WHERE username = ? AND item_id = ?",
            [username, itemId],
            (err, ownedItem) => {
              if (err) {
                rollbackAndRespond(res, "Interner Serverfehler.");
                return;
              }

              if (ownedItem) {
                rollbackAndRespond(res, "Du besitzt dieses Item bereits.");
                return;
              }

              db.get(
                "SELECT * FROM item_data WHERE id = ?",
                [itemId],
                (err, selectedItem) => {
                  if (err) {
                    rollbackAndRespond(res, "Internal Server Error.");
                    return;
                  }

                  if (!selectedItem) {
                    rollbackAndRespond(
                      res,
                      "Gegenstand nicht im Shop gefunden.",
                    );
                    return;
                  }

                  const itemExistsInDailyItems =
                    dailyItems && Object.values(dailyItems).includes(itemId);

                  if (!itemExistsInDailyItems) {
                    rollbackAndRespond(res, "Item not found in daily items.");
                    return;
                  }
                  if (userRow.coins < selectedItem.price) {
                    rollbackAndRespond(
                      res,
                      "Nicht genügend Coins, um den Gegenstand zu kaufen.",
                    );
                    return;
                  }

                  const newCoins = userRow.coins - selectedItem.price;
                  db.run(
                    "UPDATE users SET coins = ? WHERE username = ?",
                    [newCoins, username],
                    (err) => {
                      if (err) {
                        rollbackAndRespond(res, "Interner Serverfehler.");
                        return;
                      }

                      db.run(
                        "INSERT INTO user_items (username, item_id) VALUES (?, ?)",
                        [username, itemId],
                        (err) => {
                          if (err) {
                            rollbackAndRespond(res, "Interner Serverfehler.");
                            return;
                          }

                          db.run("COMMIT", (err) => {
                            if (err) {
                              console.error(
                                "Fehler beim Beenden der Transaktion:",
                                err,
                              );
                            }

                            res.json({
                              message: `Du hast ${selectedItem.name} gekauft.`,
                            });
                          });
                        },
                      );
                    },
                  );
                },
              );
            },
          );
        });
      },
    );
  });
});

app.post("/equip-item1/:token/:itemId", verifyToken, (req, res) => {
  const { itemId } = req.params;

  const token = req.params.token;
  const username = req.user.username;

  checkActiveSessions(req, res, () => {
    db.get(
      "SELECT * FROM user_items WHERE username = ? AND item_id = ?",
      [username, itemId],
      (err, ownedItem) => {
        if (err) {
          return res.status(500).json({ message: "Interner Serverfehler." });
        }

        if (!ownedItem) {
          return res
            .status(400)
            .json({ message: "Du besitzt dieses Item nicht." });
        }

        if (!itemId.startsWith("A")) {
          return res
            .status(400)
            .json({ message: 'Das zweite Item muss mit "B" beginnen.' });
        }

        db.run(
          "UPDATE users SET equipped_item = ? WHERE username = ?",
          [itemId, username],
          (err) => {
            if (err) {
              return res.status(500).json({
                message: "Interner Serverfehler beim Ausrüsten des Items.",
              });
            }

            res.json({
              message: `Du hast das Item ${itemId} erfolgreich ausgerüstet.`,
              equipped_item: itemId,
            });
          },
        );
      },
    );
  });
});

app.post("/equip-item2/:token/:itemId2", verifyToken, (req, res) => {
  const { itemId2 } = req.params;

  const token = req.params.token;
  const username = req.user.username;

  checkActiveSessions(req, res, () => {
    db.get(
      "SELECT * FROM user_items WHERE username = ? AND item_id = ?",
      [username, itemId2],
      (err, ownedItem) => {
        if (err) {
          return res.status(500).json({ message: "Interner Serverfehler." });
        }

        if (!ownedItem) {
          return res
            .status(400)
            .json({ message: "Du besitzt dieses Item nicht." });
        }

        if (!itemId2.startsWith("B")) {
          return res
            .status(400)
            .json({ message: 'Das zweite Item muss mit "B" beginnen.' });
        }

        db.run(
          "UPDATE users SET equipped_item2 = ? WHERE username = ?",
          [itemId2, username],
          (err) => {
            if (err) {
              return res.status(500).json({
                message: "Interner Serverfehler beim Ausrüsten des Items.",
              });
            }

            res.json({
              message: `Du hast das Item ${itemId2} erfolgreich ausgerüstet.`,
              equipped_item2: itemId2,
            });
          },
        );
      },
    );
  });
});

app.post("/equip-banner/:token/:banner", verifyToken, (req, res) => {
  const { banner } = req.params;

  const token = req.params.token;
  const username = req.user.username;

  checkActiveSessions(req, res, () => {
    db.get(
      "SELECT * FROM user_items WHERE username = ? AND item_id = ?",
      [username, banner],
      (err, ownedItem) => {
        if (err) {
          return res.status(500).json({ message: "Interner Serverfehler." });
        }

        if (!ownedItem) {
          return res
            .status(400)
            .json({ message: "Du besitzt dieses Item nicht." });
        }

        if (!banner.startsWith("I")) {
          return res
            .status(400)
            .json({ message: 'Das zweite Item muss mit "I" beginnen.' });
        }

        db.run(
          "UPDATE users SET equipped_banner = ? WHERE username = ?",
          [banner, username],
          (err) => {
            if (err) {
              return res.status(500).json({
                message: "Interner Serverfehler beim Ausrüsten des Items.",
              });
            }

            res.json({
              message: `Du hast das Item ${banner} erfolgreich ausgerüstet.`,
              equipped_banner: banner,
            });
          },
        );
      },
    );
  });
});

app.post("/equip-pose/:token/:pose", verifyToken, (req, res) => {
  const { pose } = req.params;

  const token = req.params.token;
  const username = req.user.username;

  checkActiveSessions(req, res, () => {
    db.get(
      "SELECT * FROM user_items WHERE username = ? AND item_id = ?",
      [username, pose],
      (err, ownedItem) => {
        if (err) {
          return res.status(500).json({ message: "Interner Serverfehler." });
        }

        if (!ownedItem) {
          return res
            .status(400)
            .json({ message: "Du besitzt dieses Item nicht." });
        }

        if (!pose.startsWith("P")) {
          return res
            .status(400)
            .json({ message: 'Das zweite Item muss mit "I" beginnen.' });
        }

        db.run(
          "UPDATE users SET equipped_pose = ? WHERE username = ?",
          [pose, username],
          (err) => {
            if (err) {
              return res.status(500).json({
                message: "Interner Serverfehler beim Ausrüsten des Items.",
              });
            }

            res.json({
              message: `Du hast das Item ${pose} erfolgreich ausgerüstet.`,
              equipped_pose: pose,
            });
          },
        );
      },
    );
  });
});

app.post("/equip-color/:token/:color", verifyToken, (req, res) => {
  const { color } = req.params;
  const token = req.params.token;
  const username = req.user.username;

  const parsedColor = parseInt(color, 10);
  if (isNaN(parsedColor) || parsedColor < -400 || parsedColor > 400) {
    return res
      .status(400)
      .json({ message: "Color must be a number between -200 and 200." });
  }

  checkActiveSessions(req, res, () => {
    db.run(
      "UPDATE users SET equipped_color = ? WHERE username = ?",
      [parsedColor, username],
      (err) => {
        if (err) {
          return res
            .status(500)
            .json({ message: "Internal Server Error while equipping color." });
        }

        res.json({
          message: `You have successfully equipped color ${parsedColor}.`,
          equipped_color: parsedColor,
        });
      },
    );
  });
});

app.get("/get-user-inventory/:token", verifyToken, (req, res) => {
  const token = req.params.token;
  const username = req.user.username;

  db.get(
    "SELECT * FROM users WHERE username = ?",
    [username],
    (err, userRow) => {
      if (err) {
        return res.status(500).json({ message: "Interner Serverfehler." });
      }

      if (!userRow) {
        return res
          .status(401)
          .json({ message: "Ungültige Anmeldeinformationen." });
      }

      checkActiveSessions(req, res, () => {
        db.get(
          "SELECT equipped_item, equipped_item2, equipped_banner, equipped_pose, equipped_color FROM users WHERE username = ?",
          [username],
          (err, equippedItems) => {
            if (err) {
              return res
                .status(500)
                .json({ message: "Interner Serverfehler." });
            }

            db.all(
              "SELECT item_id FROM user_items WHERE username = ?",
              [username],
              (err, items) => {
                if (err) {
                  return res
                    .status(500)
                    .json({ message: "Interner Serverfehler." });
                }

                const userItemsList = items.map((item) => item.item_id);

                const response = {
                  coins: userRow.coins,
                  items: userItemsList,
                  last_collected: userRow.last_collected,
                  server_timestamp: Date.now(),
                };

                if (equippedItems) {
                  response.equipped_item = equippedItems.equipped_item;
                  response.equipped_item2 = equippedItems.equipped_item2;
                  response.equipped_banner = equippedItems.equipped_banner;
                  response.equipped_pose = equippedItems.equipped_pose;
                  response.equipped_color = equippedItems.equipped_color;
                }

                res.json(response);
              },
            );
          },
        );
      });
    },
  );
});

app.post("/reset-equipped-items/:token", verifyToken, (req, res) => {
  const token = req.params.token;
  const username = req.user.username;

  checkActiveSessions(req, res, () => {
    db.run(
      "UPDATE users SET equipped_item = 0, equipped_item2 = 0, equipped_banner = 0, equipped_pose = 0, equipped_color = 0 WHERE username = ?",
      [username],
      (err) => {
        if (err) {
          return res.status(500).json({
            message: "Internal Server Error while resetting equipped items.",
          });
        }

        res.json({
          message: "Equipped items have been reset successfully.",
          equipped_item: 0,
          equipped_item2: 0,
          equipped_banner: 0,
          equipped_pose: 0,
          equipped_color: 0,
        });
      },
    );
  });
});

function readAndRedeemCodeFromFile(username, code, db, res) {
  const filePath = "codes.txt";

  fs.readFile(filePath, "utf8", (err, data) => {
    if (err) {
      return res
        .status(500)
        .json({ message: "Fehler beim Lesen der Codes aus der Datei." });
    }

    const lines = data.split("\n");
    const codeList = [];

    lines.forEach((line) => {
      const trimmedLine = line.trim();
      if (trimmedLine) {
        codeList.push(trimmedLine);
      }
    });

    let codeFound = false;
    let updatedCodeList = [];

    codeList.forEach((line) => {
      const [fileCode, reward, rewardType] = line.split(":");
      if (fileCode === code) {
        codeFound = true;

        if (rewardType === "coins") {
          const coinsToAdd = parseInt(reward, 10);

          if (isNaN(coinsToAdd)) {
            return res
              .status(500)
              .json({ message: "Ungültige Belohnung für Coins." });
          }

          db.run(
            "UPDATE users SET coins = coins + ? WHERE username = ?",
            [coinsToAdd, username],
            (err) => {
              if (err) {
                return res
                  .status(500)
                  .json({ message: "Interner Serverfehler." });
              }

              res.json({
                message: "Der Code wurde erfolgreich eingelöst.",
                reward: { coins: coinsToAdd },
              });

              updatedCodeList = codeList.filter(
                (line) => line !== `${code}:${reward}:${rewardType}`,
              );

              fs.writeFile(
                filePath,
                updatedCodeList.join("\n"),
                "utf8",
                (err) => {
                  if (err) {
                    console.error(
                      "Fehler beim Aktualisieren der Codes in der Datei.",
                    );
                  }
                },
              );
            },
          );
        } else if (rewardType === "item") {
          db.run(
            "INSERT INTO user_items (username, item_id) VALUES (?, ?)",
            [username, reward],
            (err) => {
              if (err) {
                return res.status(500).json({
                  message: "Interner Serverfehler beim Hinzufügen des Items.",
                });
              }

              res.json({
                message: "Der Code wurde erfolgreich eingelöst.",
                reward: { item: reward },
              });

              updatedCodeList = codeList.filter(
                (line) => line !== `${code}:${reward}:${rewardType}`,
              );

              fs.writeFile(
                filePath,
                updatedCodeList.join("\n"),
                "utf8",
                (err) => {
                  if (err) {
                    console.error(
                      "Fehler beim Aktualisieren der Codes in der Datei.",
                    );
                  }
                },
              );
            },
          );
        } else {
          res.status(500).json({ message: "Ungültiger Belohnungstyp." });
        }
      } else {
        updatedCodeList.push(line);
      }
    });

    if (!codeFound) {
      res.status(404).json({ message: "Der Code existiert nicht." });
    }
  });
}

app.post("/redeem-code/:token/:code", verifyToken, (req, res) => {
  const { code } = req.params;
  const token = req.params.token;
  const username = req.user.username;

  checkActiveSessions(req, res, () => {
    readAndRedeemCodeFromFile(username, code, db, res);
  });
});

app.get("/global-place/:token", verifyToken, (req, res) => {
  const token = req.params.token;
  const username = req.user.username;

  db.get(
    'SELECT COUNT(*) AS place FROM users WHERE username != "Liquem" AND all_coins_earned >= (SELECT all_coins_earned FROM users WHERE username = ?)',
    [username],
    (err, row) => {
      if (err) {
        return res.status(500).json({ message: "Interner Serverfehler." });
      }

      if (row) {
        const place = row.place + 0;
        res.json({ place });
      } else {
        res.status(404).json({ message: "Benutzer nicht gefunden." });
      }
    },
  );
});

function updateHighscores(callback) {
  db.all(
    'SELECT username, all_coins_earned FROM users WHERE username != "Liquem" ORDER BY all_coins_earned DESC LIMIT 50',
    (err, rows) => {
      if (err) {
        console.error(
          "Interner Serverfehler beim Aktualisieren der Highscores:",
          err,
        );
        return callback(err);
      }

      const highscores = rows.map((row) => ({
        username: row.username,
        all_coins_earned: row.all_coins_earned,
      }));

      // Speichern Sie die aktualisierten Highscores in einer Servervariable.
      app.set("highscores", highscores);

      console.log("Highscores wurden erfolgreich aktualisiert.");

      // Rufen Sie die Callback-Funktion auf, um anzuzeigen, dass die Aktualisierung abgeschlossen ist.
      callback(null, highscores);
    },
  );
}

 
// Aktualisieren Sie die Highscores alle 5 Minuten (300000 Millisekunden).
setInterval(() => {
  updateHighscores((err, highscores) => {
    if (err) {
      // Hier können Sie Fehlerbehandlung implementieren.
      console.error("Fehler bei der Aktualisierung der Highscores:", err);
    }
    // Hier können Sie weitere Aktionen nach der Aktualisierung durchführen.
  });
}, 3000000);

app.get("/highscores-coins/:token", verifyToken, (req, res) => {
  const token = req.params.token;
  const username = req.user.username;

  const highscores = app.get("highscores");

  // Hier können Sie die Highscores in der Response zurückgeben.
  res.json(highscores);
});

app.get("/user-count", (req, res) => {
  db.get("SELECT COUNT(*) AS userCount FROM users", (err, result) => {
    if (err) {
      return res.status(500).json({ message: "Interner Serverfehler." });
    }
    const userCount = result.userCount;
    res.json({ userCount });
  });
});

app.get("/user-profile/:token/:usernamed", verifyToken, (req, res) => {
  const { usernamed } = req.params;
  const token = req.params.token;
  const username = req.user.username;
  checkActiveSessions(req, res, () => {
    db.get(
      "SELECT equipped_item, equipped_item2, equipped_banner, equipped_pose, equipped_color, all_coins_earned, created_at, country_code FROM users WHERE username COLLATE NOCASE = ?",
      [usernamed],
      (err, userDetails) => {
        if (err) {
          return res.status(500).json({ message: "Interner Serverfehler." });
        }

        if (!userDetails) {
          return res.status(404).json({ message: "Benutzer nicht gefunden." });
        }

        const joinedTimestamp = new Date(userDetails.created_at).getTime();
        const currentTime = new Date().getTime();
        const timeSinceJoined = currentTime - joinedTimestamp;

        const daysSinceJoined = Math.floor(
          timeSinceJoined / (1000 * 60 * 60 * 24),
        );
        const monthsSinceJoined = Math.floor(daysSinceJoined / 30);
        const yearsSinceJoined = Math.floor(monthsSinceJoined / 12);

        let displayString;

        if (yearsSinceJoined > 0) {
          displayString = `${yearsSinceJoined} year${
            yearsSinceJoined > 1 ? "s" : ""
          }`;
        } else if (monthsSinceJoined > 0) {
          displayString = `${monthsSinceJoined} month${
            monthsSinceJoined > 1 ? "s" : ""
          }`;
        } else {
          displayString = `${daysSinceJoined} day${
            daysSinceJoined > 1 ? "s" : ""
          }`;
        }

        res.json({
          equipped_item: userDetails.equipped_item,
          equipped_item2: userDetails.equipped_item2,
          equipped_banner: userDetails.equipped_banner,
          equipped_pose: userDetails.equipped_pose,
          equipped_color: userDetails.equipped_color,
          all_coins_earned: userDetails.all_coins_earned,
          days_since_joined: displayString,
          country_code: userDetails.country_code,
        });
      },
    );
  });
});

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
});

rl.on("line", (input) => {
  const command = input.trim();
  if (command === "exit") {
    rl.close();
    return;
  }

  if (command.startsWith("/change-coins")) {
    const match = /\/change-coins\s+(\w+)\s+(\d+)/.exec(command);

    if (match) {
      const username = match[1];
      const newCoins = match[2];
      changeCoinsInConsole(db, username, newCoins);
    } else {
      console.log(
        'Invalid command. Use /change-coins <username> <newCoins> or "exit" to quit.',
      );
    }
  } else {
    console.log(
      'Invalid command. Use /change-coins <username> <newCoins> or "exit" to quit.',
    );
  }
});

function changeCoinsInConsole(db, username, newCoins) {
  const parsedCoins = parseInt(newCoins, 10);

  if (isNaN(parsedCoins)) {
    console.log("Invalid input for coins. The change was not performed.");
    return;
  }

  db.get("SELECT * FROM users WHERE username = ?", [username], (err, row) => {
    if (err) {
      console.error("Error checking the username in the database:", err);
    } else if (!row) {
      console.log(`The user ${username} does not exist.`);
    } else {
      db.run(
        "UPDATE users SET coins = ? WHERE username = ?",
        [parsedCoins, username],
        (updateErr) => {
          if (updateErr) {
            console.error("Error updating coins in the database:", updateErr);
          } else {
            console.log(
              `Coins for user ${username} successfully changed to ${parsedCoins}.`,
            );
          }
        },
      );
    }
  });
}

rl.on("line", (input) => {
  const command = input.trim().toLowerCase();
  if (command === "mt on") {
    maintenanceMode = true;
    console.log("Wartungsarbeiten sind jetzt aktiviert.");
  } else if (command === "mt off") {
    maintenanceMode = false;
    console.log("Wartungsarbeiten sind jetzt deaktiviert.");
  } else {
    console.log(
      'Invalid command. Use "/maintenance off or /maintenance on" or "exit" to quit.',
    );
  }
});

app.post("/change-password", (req, res) => {
  const { token, currentPassword, newPassword } = req.body;

  if (!token || !currentPassword || !newPassword) {
    return res
      .status(400)
      .json({ message: "Please provide all required information." });
  }

  const validationErrorNew = validateChangeCredentials(newPassword);

  if (validationErrorNew) {
    return res.status(400).json({ message: validationErrorNew });
  }

  jwt.verify(token, jwtSecret, (err, decoded) => {
    if (err) {
      return res.status(403).json({ message: "Invalid token." });
    }

    const username = decoded.username;

    db.get(
      "SELECT * FROM users WHERE username COLLATE NOCASE = ?",
      [username],
      (dbErr, user) => {
        if (dbErr) {
          console.error("Error checking user in the database:", dbErr);
          return res.status(500).json({ message: "Internal server error." });
        }

        if (!user) {
          return res.status(404).json({ message: "User not found." });
        }

        if (!bcrypt.compareSync(currentPassword, user.password)) {
          return res.status(401).json({ message: "Invalid current password." });
        }

        const saltRounds = 10;
        const salt = bcrypt.genSaltSync(saltRounds);
        const hashedNewPassword = bcrypt.hashSync(newPassword, salt);

        db.run(
          "UPDATE users SET password = ?, salt = WHERE username = ?",
          [hashedNewPassword, salt, username],
          (updateErr) => {
            if (updateErr) {
              console.error(
                "Error updating password in the database:",
                updateErr,
              );
              return res
                .status(500)
                .json({ message: "Internal server error." });
            }

            db.run(
              "UPDATE tokens SET token = ? WHERE username = ?",
              [0, username],
              (tokenUpdateErr) => {
                if (tokenUpdateErr) {
                  console.error(
                    "Error updating token in the database:",
                    tokenUpdateErr,
                  );
                  return res
                    .status(500)
                    .json({ message: "Internal server error." });
                }

                res.json({ message: "Password changed successfully." });
              },
            );
          },
        );
      },
    );
  });
});

app.post("/change-username", (req, res) => {
  const { currentUsername, currentPassword, newUsername } = req.body;

  if (!currentUsername || !currentPassword || !newUsername) {
    return res
      .status(400)
      .json({ message: "Please provide all required information." });
  }

  const validationErrorUsername = validateUserInput(username);

  if (validationErrorUsername) {
    return res.status(400).json({ message: validationErrorUsername });
  }

  db.get(
    "SELECT * FROM users WHERE username COLLATE NOCASE = ?",
    [currentUsername],
    (dbErr, user) => {
      if (dbErr) {
        console.error("Error checking user in the database:", dbErr);
        return res.status(500).json({ message: "Internal server error." });
      }

      if (!user) {
        return res.status(404).json({ message: "User not found." });
      }

      if (!bcrypt.compareSync(currentPassword, user.password)) {
        return res.status(401).json({ message: "Invalid current password." });
      }

      db.get(
        "SELECT * FROM users WHERE username COLLATE NOCASE = ?",
        [newUsername],
        (usernameCheckErr, existingUser) => {
          if (usernameCheckErr) {
            console.error(
              "Error checking new username in the database:",
              usernameCheckErr,
            );
            return res.status(500).json({ message: "Internal server error." });
          }

          if (existingUser) {
            return res.status(409).json({
              message:
                "Username already exists. Please choose a different username.",
            });
          }

          db.run(
            "UPDATE users SET username = ? WHERE username = ?",
            [newUsername, currentUsername],
            (updateErr) => {
              if (updateErr) {
                console.error(
                  "Error updating username in the database:",
                  updateErr,
                );
                return res
                  .status(500)
                  .json({ message: "Internal server error." });
              }

              res.json({ message: "Username changed successfully." });
            },
          );
        },
      );
    },
  );
});

app.get("/verify-token/:token", verifyToken, (req, res) => {
  const username = req.user.username;

  res.json({ message: `${username}` });
});

app.listen(port, () => {
  console.log(`Server läuft auf Port ${port}`);
});