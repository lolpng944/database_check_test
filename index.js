const express = require('express');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const helmet = require('helmet');
const axios = require('axios');
const validator = require('validator');
const { createHmac } = require('crypto');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken'); // Added JWT
const fs = require('fs');
const readline = require('readline');
require('dotenv').config();
const Discord = require('discord.js');
const webhookURL = process.env.DISCORD_KEY;


const app = express();
exports.app = app;
const port = 3000;

app.use(helmet({ poweredBy: false }));

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'"],
        fontSrc: ["'self'"],
        imgSrc: ['data:', "'self'"],
        // Add more directives as needed
      },
    },
  })
);

app.use(helmet({
  hsts: {
    maxAge: 31536000, // 1 year in seconds
    includeSubDomains: true,
    preload: true,
  },
}));

app.use(
  helmet({
    contentSecurityPolicy: false, // Disable Helmet's default CSP
    hidePoweredBy: true, // Enable hiding the "X-Powered-By" header
    xssFilter: true, // Enable XSS filtering
    frameguard: { action: 'deny' }, // Enable clickjacking protection
    expectCt: true, // Enable Certificate Transparency header
    dnsPrefetchControl: { allow: false }, // Disable DNS prefetching
    referrerPolicy: { policy: 'same-origin' }, // Set referrer policy
    featurePolicy: {
      features: {
        geolocation: ["'none'"],
      },
    }, // Enable Feature Policy header
    permittedCrossDomainPolicies: { permittedPolicies: 'none' }, // Disable Adobe Flash and Acrobat PDF plugins
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
  })
);



const limiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 Minute
  max: 100, // Maximale Anfragen pro IP-Adresse in diesem Zeitraum
  message: 'Zu viele Anfragen vom gleichen Ort, bitte versuche es später erneut.',
});

const registerLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 15 Minuten
  max: 20, // Maximale Anfragen pro IP-Adresse in diesem Zeitraum
  message: 'Zu viele Registrierungsanfragen von dieser IP-Adresse, bitte versuche es später erneut.',
});

const accountCreationLimiter = rateLimit({
  windowMs: 24 * 60 * 60 * 1000, // 24 Stunden (pro Tag)
  max: 1, // Maximal 2 Anfragen pro IP-Adresse pro Tag
  message: 'Sie haben bereits die maximale Anzahl von Benutzerkonten für heute erstellt.'
});




app.use(cors());


app.use(bodyParser.json());


app.set('trust proxy', ['loopback', 'linklocal', 'uniquelocal']);
app.use(limiter);
app.use(express.static('public'));


// Mittelware, um Anfragen von nicht autorisierten Ursprüngen abzulehnen
app.use((req, res, next) => {
  const allowedOrigins = ['https://turbowarp.org', 'https://serve.gamejolt.net' ,'tw-editor://.' ,'https://w7f5hz-3000.csb.app'];
  const origin = req.headers.origin;


  if (allowedOrigins.includes(origin)) {
    // Dies ist ein autorisierter Ursprung, erlauben Sie die Anfrage
    res.setHeader('Access-Control-Allow-Origin', origin);
    next();
  } else {
    // Dies ist ein nicht autorisierter Ursprung, lehnen Sie die Anfrage ab
    console.log('Abgelehnte Anfrage von nicht autorisiertem Ursprung:', origin);
    return res.status(403).json({ error: 'no contents' });
  }
});




// Verwende ein zufälliges und sicheres Verschlüsselungsschlüssel
// const encryptionKey = crypto.randomBytes(32).toString('hex');
const encryptionKey = process.env.ENCRYPTION_KEY;

const db = new sqlite3.Database('database.db');

// Aktiviere den WAL-Modus
db.run('PRAGMA journal_mode = WAL', err => {
  if (err) {
    console.error('Fehler beim Aktivieren des WAL-Modus:', err);
  } else {
    console.log('WAL-Modus aktiviert.');
  }
});

db.run('PRAGMA wal_autocheckpoint = 20');

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY,
      username TEXT NOT NULL,
      password TEXT NOT NULL,
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

});



let maintenanceMode = false;
// Middleware, um Wartungsarbeiten zu überprüfen
function checkMaintenanceMode(req, res, next) {
  if (maintenanceMode) {
    return res.status(503).send('Wartung');
  }
  next();
}


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
    return 'Ungültiger Benutzername.';
  }

  if (!passwordRegex.test(password)) {
    return 'Ungültiges Passwort.';
  }

  return null; // Eingabe ist gültig
}

const MAX_REQUEST_SIZE = 100; // Setze das gewünschte Zeichenlimit

// Erstelle eine Funktion, um die Anfragen auf das Zeichenlimit zu überprüfen
const checkRequestSize = (req, res, next) => {
  // Überprüfe die Anfragegröße in req.body
  if (req.body && JSON.stringify(req.body).length > MAX_REQUEST_SIZE) {
    return res.status(400).json({ message: 'Anfrage überschreitet das Zeichenlimit für req.body.' });
  }

  // Überprüfe die Anfragegröße in req.params
  if (JSON.stringify(req.params).length > MAX_REQUEST_SIZE) {
    return res.status(400).json({ message: 'Anfrage überschreitet das Zeichenlimit für req.params.' });
  }

  next();
};

// Middleware global hinzufügen


app.use(checkRequestSize);
app.use(checkMaintenanceMode);

app.use((req, res, next) => {
  // Sanitize specific inputs in the request object
  req.body = sanitizeInputs(req.body);
  req.query = sanitizeInputs(req.query);
  req.params = sanitizeInputs(req.params);

  // Continue to the next middleware or route handler
  next();
});

// Function to sanitize inputs using validator.escape
const sanitizeInputs = (inputs) => {
  const sanitizedInputs = {};

  for (const key in inputs) {
    if (Object.hasOwnProperty.call(inputs, key)) {
      sanitizedInputs[key] = validator.escape(inputs[key]);
    }
  }

  return sanitizedInputs;
};








const activeSessions = new Map();

// Middleware to check for active sessions after a successful login
function checkActiveSessions(req, res, next) {
  const username = req.body.username || req.params.username;
  const clientIp = req.ip; // Get the client's IP address

  // Check if the user has an active session with two different IP addresses
  if (activeSessions.has(username)) {
    const userSessions = activeSessions.get(username);
    
    // Remove inactive sessions
    for (const [ip, lastActiveTimestamp] of userSessions.entries()) {
      const currentTime = Date.now();
      if (currentTime - lastActiveTimestamp > INACTIVE_TIMEOUT) {
        userSessions.delete(ip);
      }
    }

    if (userSessions.size >= 2) {
      return res.status(401).json({ message: 'You already have two active sessions.' });
    }
  }

  // Add or update the current session's IP with a timestamp
  if (!activeSessions.has(username)) {
    activeSessions.set(username, new Map());
  }
  activeSessions.get(username).set(clientIp, Date.now());

  next();
}

function getCountryCode(userIp) {
    return axios.get(`https://ipinfo.io/${userIp}/json`)
    .then(response => {
      const ipInfo = response.data;
      if (ipInfo && ipInfo.country) {
        return ipInfo.country;
      }
      return 'Unknown';
    })
    .catch(error => {
      console.error('Error while detecting the country:', error);
      return 'Unknown';
    });

}

// Set an inactive timeout (e.g., 30 minutes in milliseconds)
const INACTIVE_TIMEOUT = 1 * 60 * 1000; // 30 minutes


const jwtSecret =  process.env.TOKEN_KEY;

// Middleware for JWT token generation upon login or registration
function generateToken(username) {
  const token = jwt.sign({ username }, jwtSecret, { expiresIn: '31d' }); // Generate a new token

  // Check if a token already exists for the given username
  const existingToken = db.get('SELECT token FROM tokens WHERE username = ?', [username]);

  if (existingToken) {
    // If a token already exists, update the existing token in the database
    db.run('UPDATE tokens SET token = ? WHERE username = ?', [token, username], (err) => {
      if (err) {
        console.error('Error updating token in the database:', err);
      }
    });
  } else {
    // If no token exists, insert the generated token in the database
    db.run('INSERT INTO tokens (username, token) VALUES (?, ?)', [username, token], (err) => {
      if (err) {
        console.error('Error storing token in the database:', err);
      }
    });
  }

  return token;
}


function verifyToken(req, res, next) {
  const token = req.params.token;

  if (!token) {
    return res.status(401).json({ message: 'Token is missing.' });
  }

  // Check if the token exists in the database
  db.get('SELECT username FROM tokens WHERE token = ?', token, (err, row) => {
    if (err) {
      console.error('Error checking token in the database:', err);
      return res.status(500).json({ message: 'Internal server error.' });
    }

    if (!row) {
      return res.status(403).json({ message: 'Invalid token.' });
    }

    // Token is valid; set the user information in the request
    req.user = { username: decoded.username };
    next();
  });
}





app.post('/register', registerLimiter, (req, res) => {
  const { username, password } = req.body;

  const validationError = validateUserInput(username, password);

  if (validationError) {
    return res.status(400).json({ message: validationError });
  }

  // Verwende ein sicheres Hashing-Verfahren (HMAC) für das Passwort
  const hmac = createHmac('sha256', encryptionKey);
  const hashedPassword = hmac.update(password).digest('hex');

 
  getCountryCode(req.ip)
   .then(countryCode => {
    const fallbackCountryCode = 'Unknown';
    const finalCountryCode = countryCode || fallbackCountryCode;

      db.get('SELECT * FROM users WHERE username COLLATE NOCASE = ?', [username], (err, row) => {
        if (err) {
          return res.status(500).json({ message: 'Interner Serverfehler.' });
        }

        if (row) {
          return res.status(400).json({ message: 'Benutzername bereits vergeben.' });
        }

        if (username === password()) {
          return res.status(400).json({ message: 'username and password identical' });
        }

        // When the IP address limit is not reached, create the user account
        db.run('INSERT INTO users (username, password, country_code) VALUES (?, ?, ?)', [username, hashedPassword, finalCountryCode], err => {
          if (err) {
            return res.status(500).json({ message: 'Interner Serverfehler.' });
          }

          accountCreationLimiter(req, res, () => {
            checkActiveSessions(req, res, () => {
            const token = generateToken(username); // Generate a token upon successful registration
            res.json({ message: 'Benutzerkonto erfolgreich erstellt.', token });
            });
          });
        });
      });
    })
    
   });




app.post('/login', registerLimiter, (req, res) => {
  const { username, password } = req.body;

  // Verwende ein sicheres Hashing-Verfahren (HMAC) für das Passwort
  const hmac = createHmac('sha256', encryptionKey);
  const hashedPassword = hmac.update(password).digest('hex');

  db.get('SELECT * FROM users WHERE username = ? AND password = ?', [username, hashedPassword], (err, row) => {
    if (err) {
      return res.status(500).json({ message: 'Interner Serverfehler.' });
    }

    if (!row) {
      return res.status(401).json({ message: 'Ungültige Anmeldeinformationen.' });
    }
    checkActiveSessions(req, res, () => {
    const token = generateToken(username); // Generate a token upon successful login
    res.json({ message: 'Anmeldung erfolgreich.', token });
  });
});
});


app.get('/get-coins/:token', (req, res) => {
  const token = req.params.token;

  if (!token) {
    return res.status(401).json({ message: 'Token is missing.' });
  }

  // Verify the token using the JWT secret key
  jwt.verify(token, jwtSecret, (err, decoded) => {
    if (err) {
      return res.status(403).json({ message: 'Invalid token.' });
    }

    // The token is valid, and decoded contains the user information
    const username = decoded.username;

    checkActiveSessions(req, res, () => {
      db.serialize(() => {
        db.run('BEGIN TRANSACTION');

        db.get('SELECT * FROM users WHERE username = ?', [username], (err, row) => {
          if (err) {
            rollbackAndRespond(res, 'Interner Serverfehler.');
            return;
          }

          if (!row) {
            rollbackAndRespond(res, 'Ungültige Anmeldeinformationen.');
            return;
          }

          checkActiveSessions(req, res, () => {
            const lastCollected = row.last_collected || 0;

            if (!canCollectCoins(lastCollected)) {
              rollbackAndRespond(res, 'Du kannst Coins erst alle 24 Stunden sammeln.');
              return;
            }

            // Logic to add coins
            function generateRandomNumber(min, max) {
              return Math.floor(Math.random() * (max - min + 1)) + min;
            }
            const coinsToAdd = generateRandomNumber(45, 80);

            db.run('UPDATE users SET coins = coins + ?, last_collected = ? WHERE username = ?', [coinsToAdd, Date.now(), username], (err) => {
              if (err) {
                rollbackAndRespond(res, 'Interner Serverfehler.');
                return;
              }

              db.run('UPDATE users SET all_coins_earned = all_coins_earned + ? WHERE username = ?', [coinsToAdd, username], (err) => {
                if (err) {
                  rollbackAndRespond(res, 'Interner Serverfehler.');
                  return;
                }

                db.get('SELECT coins FROM users WHERE username = ?', [username], (err, userRow) => {
                  if (err) {
                    rollbackAndRespond(res, 'Interner Serverfehler.');
                    return;
                  }

                  const coinsMessage = `${username} hat ${coinsToAdd} Coins erhalten.`;

                  // Send the message to the Discord Webhook
                  const webhook = new Discord.WebhookClient({ url: webhookURL });
                  webhook.send(coinsMessage);

                  // Commit the transaction
                  db.run('COMMIT', (err) => {
                    if (err) {
                      console.error('Fehler beim Beenden der Transaktion:', err);
                    }

                    // Respond with success message
                    res.json({ message: `Du hast ${coinsToAdd} Coins erhalten.`, coins: userRow.coins });
                  });
                });
              });
            });
          });
        });
      });
    });
  });
});

function rollbackAndRespond(res, message) {
  db.run('ROLLBACK', (err) => {
    if (err) {
      console.error('Fehler beim Rollback:', err);
    }

    res.status(500).json({ message: message });
  });
}


app.post('/buy-item/:token/:itemId', async (req, res) => {
  const { itemId } = req.params;
  const token = req.params.token;

  if (!token) {
    return res.status(401).json({ message: 'Token is missing.' });
  }

  // Verify the token using the JWT secret key
  jwt.verify(token, jwtSecret, (err, decoded) => {
    if (err) {
      return res.status(403).json({ message: 'Invalid token.' });
    }

    // The token is valid, and decoded contains the user information
    const username = decoded.username;

    // Check if the user is valid
    db.serialize(() => {
      db.run('BEGIN TRANSACTION');

      db.get('SELECT coins FROM users WHERE username = ?', [username], async (err, userRow) => {
        if (err) {
          rollbackAndRespond(res, 'Interner Serverfehler.');
          return;
        }

        if (!userRow) {
          rollbackAndRespond(res, 'Ungültige Anmeldeinformationen.');
          return;
        }

        checkActiveSessions(req, res, () => {
          // Check if the user already owns the selected item
          db.get('SELECT * FROM user_items WHERE username = ? AND item_id = ?', [username, itemId], (err, ownedItem) => {
            if (err) {
              rollbackAndRespond(res, 'Interner Serverfehler.');
              return;
            }

            if (ownedItem) {
              rollbackAndRespond(res, 'Du besitzt dieses Item bereits.');
              return;
            }

            // Read available item information from the text file
            fs.readFile('items.txt', 'utf8', (err, data) => {
              if (err) {
                rollbackAndRespond(res, 'Fehler beim Lesen der Item-Daten.');
                return;
              }

              const lines = data.split('\n');
              let selectedItem;

              lines.forEach(line => {
                const [itemLineId, itemName, itemPrice] = line.split(':');
                if (itemLineId === itemId) {
                  selectedItem = {
                    id: itemLineId,
                    name: itemName,
                    price: parseInt(itemPrice)
                  };
                }
              });

              if (!selectedItem) {
                rollbackAndRespond(res, 'Gegenstand nicht im Shop gefunden.');
                return;
              }

              // Check if the user has enough coins to buy the item
              if (userRow.coins < selectedItem.price) {
                rollbackAndRespond(res, 'Nicht genügend Coins, um den Gegenstand zu kaufen.');
                return;
              }

              // Update user's coins
              const newCoins = userRow.coins - selectedItem.price;
              db.run('UPDATE users SET coins = ? WHERE username = ?', [newCoins, username], (err) => {
                if (err) {
                  rollbackAndRespond(res, 'Interner Serverfehler.');
                  return;
                }

                // Insert the purchased item into the user_items table
                db.run('INSERT INTO user_items (username, item_id) VALUES (?, ?)', [username, itemId], (err) => {
                  if (err) {
                    rollbackAndRespond(res, 'Interner Serverfehler.');
                    return;
                  }

                  // Commit the transaction
                  db.run('COMMIT', (err) => {
                    if (err) {
                      console.error('Fehler beim Beenden der Transaktion:', err);
                    }

                    // Respond with success message
                    res.json({ message: `Du hast ${selectedItem.name} gekauft.` });
                  });
                });
              });
            });
          });
        });
      });
    });
  });
});



app.post('/equip-item1/:token/:itemId', (req, res) => {
  const { itemId } = req.params;

  const token = req.params.token;

  if (!token) {
    return res.status(401).json({ message: 'Token is missing.' });
  }

  // Verify the token using the JWT secret key
  jwt.verify(token, jwtSecret, (err, decoded) => {
    if (err) {
      return res.status(403).json({ message: 'Invalid token.' });
    }

    // The token is valid, and decoded contains the user information
    const username = decoded.username;



  // Überprüfen, ob der Benutzer gültig ist
  db.get('SELECT coins FROM users WHERE username = ?', [username], async (err, userRow) => {
    if (err) {
      return res.status(500).json({ message: 'Interner Serverfehler.' });
    }

    if (!userRow) {
      return res.status(401).json({ message: 'Ungültige Anmeldeinformationen.' });
    }

    checkActiveSessions(req, res, () => {

    // Überprüfen, ob der Benutzer das ausgewählte Item bereits besitzt
    db.get('SELECT * FROM user_items WHERE username = ? AND item_id = ?', [username, itemId], (err, ownedItem) => {
      if (err) {
        return res.status(500).json({ message: 'Interner Serverfehler.' });
      }

      if (!ownedItem) {
        return res.status(400).json({ message: 'Du besitzt dieses Item nicht.' });
      }

      if (!itemId.startsWith('A')) {
        return res.status(400).json({ message: 'Das zweite Item muss mit "B" beginnen.' });
      }

      // Aktualisiere das ausgerüstete Item für den Benutzer in der Datenbank
      db.run('UPDATE users SET equipped_item = ? WHERE username = ?', [itemId, username], (err) => {
        if (err) {
          return res.status(500).json({ message: 'Interner Serverfehler beim Ausrüsten des Items.' });
        }

          // Sende die Liste der im Besitz befindlichen Items und das ausgerüstete Item als JSON-Antwort
          res.json({
            message: `Du hast das Item ${itemId} erfolgreich ausgerüstet.`,
            equipped_item: itemId,
          });
        });
      });
    });
  });
});
});
 
 


app.post('/equip-item2/:token/:itemId2', (req, res) => {
  const { itemId2 } = req.params;

  const token = req.params.token;

  if (!token) {
    return res.status(401).json({ message: 'Token is missing.' });
  }

  // Verify the token using the JWT secret key
  jwt.verify(token, jwtSecret, (err, decoded) => {
    if (err) {
      return res.status(403).json({ message: 'Invalid token.' });
    }

    // The token is valid, and decoded contains the user information
    const username = decoded.username;


  // Überprüfen, ob der Benutzer gültig ist
  db.get('SELECT coins FROM users WHERE username = ?', [username], async (err, userRow) => {
    if (err) {
      return res.status(500).json({ message: 'Interner Serverfehler.' });
    }

    if (!userRow) {
      return res.status(401).json({ message: 'Ungültige Anmeldeinformationen.' });
    }
    checkActiveSessions(req, res, () => {

    // Überprüfen, ob der Benutzer das ausgewählte Item bereits besitzt
    db.get('SELECT * FROM user_items WHERE username = ? AND item_id = ?', [username, itemId2], (err, ownedItem) => {
      if (err) {
        return res.status(500).json({ message: 'Interner Serverfehler.' });
      }

      if (!ownedItem) {
        return res.status(400).json({ message: 'Du besitzt dieses Item nicht.' });
      }

      if (!itemId2.startsWith('B')) {
        return res.status(400).json({ message: 'Das zweite Item muss mit "B" beginnen.' });
      }

      // Aktualisiere das ausgerüstete Item für den Benutzer in der Datenbank
      db.run('UPDATE users SET equipped_item2 = ? WHERE username = ?', [itemId2, username], (err) => {
        if (err) {
          return res.status(500).json({ message: 'Interner Serverfehler beim Ausrüsten des Items.' });
        }        

          // Sende die Liste der im Besitz befindlichen Items und das ausgerüstete Item als JSON-Antwort
          res.json({
            message: `Du hast das Item ${itemId2} erfolgreich ausgerüstet.`,
            equipped_item2: itemId2,
          });
        });
      });
    });
  });
});
});


app.post('/equip-banner/:token/:banner', (req, res) => {
  const { banner } = req.params;

  const token = req.params.token;

  if (!token) {
    return res.status(401).json({ message: 'Token is missing.' });
  }

  // Verify the token using the JWT secret key
  jwt.verify(token, jwtSecret, (err, decoded) => {
    if (err) {
      return res.status(403).json({ message: 'Invalid token.' });
    }

    // The token is valid, and decoded contains the user information
    const username = decoded.username;

    db.get('SELECT coins FROM users WHERE username = ?', [username], async (err, userRow) => {
      if (err) {
        return res.status(500).json({ message: 'Interner Serverfehler.' });
      }
  
      if (!userRow) {
        return res.status(401).json({ message: 'Ungültige Anmeldeinformationen.' });
      }


  // Überprüfen, ob der Benutzer gültig ist


    checkActiveSessions(req, res, () => {

    // Überprüfen, ob der Benutzer das ausgewählte Item bereits besitzt
    db.get('SELECT * FROM user_items WHERE username = ? AND item_id = ?', [username, banner], (err, ownedItem) => {
      if (err) {
        return res.status(500).json({ message: 'Interner Serverfehler.' });
      }

      if (!ownedItem) {
        return res.status(400).json({ message: 'Du besitzt dieses Item nicht.' });
      }

      if (!banner.startsWith('I')) {
        return res.status(400).json({ message: 'Das zweite Item muss mit "I" beginnen.' });
      }

      // Aktualisiere das ausgerüstete Item für den Benutzer in der Datenbank
      db.run('UPDATE users SET equipped_banner = ? WHERE username = ?', [banner, username], (err) => {
        if (err) {
          return res.status(500).json({ message: 'Interner Serverfehler beim Ausrüsten des Items.' });
        }
  

          // Sende die Liste der im Besitz befindlichen Items und das ausgerüstete Item als JSON-Antwort
          res.json({
            message: `Du hast das Item ${banner} erfolgreich ausgerüstet.`,
            equipped_banner: banner,
          });
        });
      });
    });
  });
});
});


app.post('/equip-pose/:token/:pose', (req, res) => {
  const { pose } = req.params;

  const token = req.params.token;

  if (!token) {
    return res.status(401).json({ message: 'Token is missing.' });
  }

  // Verify the token using the JWT secret key
  jwt.verify(token, jwtSecret, (err, decoded) => {
    if (err) {
      return res.status(403).json({ message: 'Invalid token.' });
    }

    // The token is valid, and decoded contains the user information
    const username = decoded.username;


  // Überprüfen, ob der Benutzer gültig ist
  db.get('SELECT coins FROM users WHERE username = ?', [username], async (err, userRow) => {
    if (err) {
      return res.status(500).json({ message: 'Interner Serverfehler.' });
    }

    if (!userRow) {
      return res.status(401).json({ message: 'Ungültige Anmeldeinformationen.' });
    }

    checkActiveSessions(req, res, () => {

    // Überprüfen, ob der Benutzer das ausgewählte Item bereits besitzt
    db.get('SELECT * FROM user_items WHERE username = ? AND item_id = ?', [username, pose], (err, ownedItem) => {
      if (err) {
        return res.status(500).json({ message: 'Interner Serverfehler.' });
      }

      if (!ownedItem) {
        return res.status(400).json({ message: 'Du besitzt dieses Item nicht.' });
      }

      if (!pose.startsWith('P')) {
        return res.status(400).json({ message: 'Das zweite Item muss mit "I" beginnen.' });
      }

      // Aktualisiere das ausgerüstete Item für den Benutzer in der Datenbank
      db.run('UPDATE users SET equipped_pose = ? WHERE username = ?', [pose, username], (err) => {
        if (err) {
          return res.status(500).json({ message: 'Interner Serverfehler beim Ausrüsten des Items.' });
        }
  

          // Sende die Liste der im Besitz befindlichen Items und das ausgerüstete Item als JSON-Antwort
          res.json({
            message: `Du hast das Item ${pose} erfolgreich ausgerüstet.`,
            equipped_pose: pose,
          });
        });
      });
    });
  });
});
});

app.post('/equip-color/:token/:color', (req, res) => {
  const { color } = req.params;
  const token = req.params.token;

  if (!token) {
    return res.status(401).json({ message: 'Token is missing.' });
  }

  // Verify the token using the JWT secret key
  jwt.verify(token, jwtSecret, (err, decoded) => {
    if (err) {
      return res.status(403).json({ message: 'Invalid token.' });
    }

    // The token is valid, and decoded contains the user information
    const username = decoded.username;

    // Check if the user is valid
    db.get('SELECT coins FROM users WHERE username = ?', [username], async (err, userRow) => {
      if (err) {
        return res.status(500).json({ message: 'Interner Serverfehler.' });
      }

      if (!userRow) {
        return res.status(401).json({ message: 'Ungültige Anmeldeinformationen.' });
      }

      // Check if the color is within the valid range
      const parsedColor = parseInt(color, 10);
      if (isNaN(parsedColor) || parsedColor < -400 || parsedColor > 400) {
        return res.status(400).json({ message: 'Color must be a number between -200 and 200.' });
      }

      checkActiveSessions(req, res, () => {
        // Update the equipped color for the user in the database
        db.run('UPDATE users SET equipped_color = ? WHERE username = ?', [parsedColor, username], (err) => {
          if (err) {
            return res.status(500).json({ message: 'Internal Server Error while equipping color.' });
          }

          // Send the list of owned items and the equipped color as a JSON response
          res.json({
            message: `You have successfully equipped color ${parsedColor}.`,
            equipped_color: parsedColor,
          });
        });
      });
    });
  });
});


  app.get('/get-user-inventory/:token', (req, res) => {
   
    const token = req.params.token;

  if (!token) {
    return res.status(401).json({ message: 'Token is missing.' });
  }

  // Verify the token using the JWT secret key
  jwt.verify(token, jwtSecret, (err, decoded) => {
    if (err) {
      return res.status(403).json({ message: 'Invalid token.' });
    }

    // The token is valid, and decoded contains the user information
    const username = decoded.username;
  
  
    db.get('SELECT * FROM users WHERE username = ?', [username], (err, userRow) => {
      if (err) {
        return res.status(500).json({ message: 'Interner Serverfehler.' });
      }
  
      if (!userRow) {
        return res.status(401).json({ message: 'Ungültige Anmeldeinformationen.' });
      }

      checkActiveSessions(req, res, () => {
  
      db.get('SELECT equipped_item, equipped_item2, equipped_banner, equipped_pose, equipped_color FROM users WHERE username = ?', [username], (err, equippedItems) => {
        if (err) {
          return res.status(500).json({ message: 'Interner Serverfehler.' });
        }
      
        // Abfrage der Items, die diesem Benutzer gehören
        db.all('SELECT item_id FROM user_items WHERE username = ?', [username], (err, items) => {
          if (err) {
            return res.status(500).json({ message: 'Interner Serverfehler.' });
          }
      
          const userItemsList = items.map(item => item.item_id); // Erstelle ein Array der Item-IDs
      
          // Fügen Sie das ausgerüstete Item zur Antwort hinzu
          const response = {
            coins: userRow.coins,
            items: userItemsList,
            last_collected: userRow.last_collected
          };
      
          if (equippedItems) {
            response.equipped_item = equippedItems.equipped_item;
            response.equipped_item2 = equippedItems.equipped_item2;
            response.equipped_banner = equippedItems.equipped_banner;
            response.equipped_pose = equippedItems.equipped_pose;
            response.equipped_color = equippedItems.equipped_color;
          }
      
          res.json(response);
        });
      });
    });
  });
});
});

app.post('/reset-equipped-items/:token', (req, res) => {
  
  const token = req.params.token;

  if (!token) {
    return res.status(401).json({ message: 'Token is missing.' });
  }

  // Verify the token using the JWT secret key
  jwt.verify(token, jwtSecret, (err, decoded) => {
    if (err) {
      return res.status(403).json({ message: 'Invalid token.' });
    }

    // The token is valid, and decoded contains the user information
    const username = decoded.username;

 

  // Check if the user is valid
  db.get('SELECT * FROM users WHERE username = ?', [username], (err, userRow) => {
    if (err) {
      return res.status(500).json({ message: 'Internal Server Error.' });
    }

    if (!userRow) {
      return res.status(401).json({ message: 'Invalid login credentials.' });
    }

    checkActiveSessions(req, res, () => {
      // Update the equipped items for the user in the database
      db.run('UPDATE users SET equipped_item = 0, equipped_item2 = 0, equipped_banner = 0, equipped_pose = 0, equipped_color = 0 WHERE username = ?', [username], (err) => {
        if (err) {
          return res.status(500).json({ message: 'Internal Server Error while resetting equipped items.' });
        }

        // Send a success response
        res.json({
          message: 'Equipped items have been reset successfully.',
          equipped_item: 0,
          equipped_item2: 0,
          equipped_banner: 0,
          equipped_pose: 0,
          equipped_color: 0,
        });
      });
    });
  });
});
});


function readAndRedeemCodeFromFile (username, code, db, res)  {
  const filePath = 'codes.txt';

  fs.readFile(filePath, 'utf8', (err, data) => {
    if (err) {
      return res.status(500).json({ message: 'Fehler beim Lesen der Codes aus der Datei.' });
    }

    const lines = data.split('\n');
    const codeList = [];

    lines.forEach(line => {
      const trimmedLine = line.trim();
      if (trimmedLine) {
        codeList.push(trimmedLine);
      }
    });

    let codeFound = false;
    let updatedCodeList = [];

    codeList.forEach(line => {
      const [fileCode, reward, rewardType] = line.split(':');
      if (fileCode === code) {
        codeFound = true;

        if (rewardType === 'coins') {
          const coinsToAdd = parseInt(reward, 10);

          if (isNaN(coinsToAdd)) {
            return res.status(500).json({ message: 'Ungültige Belohnung für Coins.' });
          }

          db.run('UPDATE users SET coins = coins + ? WHERE username = ?', [coinsToAdd, username], (err) => {
            if (err) {
              return res.status(500).json({ message: 'Interner Serverfehler.' });
            }

            res.json({ message: 'Der Code wurde erfolgreich eingelöst.', reward: { coins: coinsToAdd } });

            // Code aus der Liste entfernen
            updatedCodeList = codeList.filter(line => line !== `${code}:${reward}:${rewardType}`);
            
            // Aktualisierte Liste in die Datei schreiben
            fs.writeFile(filePath, updatedCodeList.join('\n'), 'utf8', (err) => {
              if (err) {
                console.error('Fehler beim Aktualisieren der Codes in der Datei.');
              }
            });
          });
        } else if (rewardType === 'item') {
          db.run('INSERT INTO user_items (username, item_id) VALUES (?, ?)', [username, reward], (err) => {
            if (err) {
              return res.status(500).json({ message: 'Interner Serverfehler beim Hinzufügen des Items.' });
            }

            res.json({ message: 'Der Code wurde erfolgreich eingelöst.', reward: { item: reward } });

            // Code aus der Liste entfernen
            updatedCodeList = codeList.filter(line => line !== `${code}:${reward}:${rewardType}`);
            
            // Aktualisierte Liste in die Datei schreiben
            fs.writeFile(filePath, updatedCodeList.join('\n'), 'utf8', (err) => {
              if (err) {
                console.error('Fehler beim Aktualisieren der Codes in der Datei.');
              }
            });
          });
        } else {
          res.status(500).json({ message: 'Ungültiger Belohnungstyp.' });
        }
      } else {
        updatedCodeList.push(line);
      }
    });

    if (!codeFound) {
      res.status(404).json({ message: 'Der Code existiert nicht.' });
    }
  });
}

// Route zum Einlösen eines Codes
app.post('/redeem-code/:token/:code', (req, res) => {
  const { code } = req.params;
  const token = req.params.token;

  if (!token) {
    return res.status(401).json({ message: 'Token is missing.' });
  }

  // Verify the token using the JWT secret key
  jwt.verify(token, jwtSecret, (err, decoded) => {
    if (err) {
      return res.status(403).json({ message: 'Invalid token.' });
    }

    // The token is valid, and decoded contains the user information
    const username = decoded.username;


  db.get('SELECT * FROM users WHERE username = ?', [username], (err, userRow) => {
    if (err) {
      return res.status(500).json({ message: 'Interner Serverfehler.' });
    }

    if (!userRow) {
      return res.status(401).json({ message: 'Ungültige Anmeldeinformationen.' });
    }

    checkActiveSessions(req, res, () => {

    // Rufe die Funktion zum Einlösen des Codes aus der Datei auf
    readAndRedeemCodeFromFile(username, code, db, res);
  });
});
});
});


app.get('/highscores-coins', checkRequestSize, checkMaintenanceMode, (req, res) => {
  db.all('SELECT username, all_coins_earned FROM users WHERE username != "Liquem" ORDER BY all_coins_earned DESC LIMIT 50', (err, rows) => {
    if (err) {
      return res.status(500).json({ message: 'Interner Serverfehler.' });
    }

    const highscores = rows.map(row => ({
      username: row.username,
      all_coins_earned: row.all_coins_earned
    }));

    res.json(highscores);
  });
});

app.get('/global-place/:token', (req, res) => {
  const token = req.params.token;

  if (!token) {
    return res.status(401).json({ message: 'Token is missing.' });
  }

  // Verify the token using the JWT secret key
  jwt.verify(token, jwtSecret, (err, decoded) => {
    if (err) {
      return res.status(403).json({ message: 'Invalid token.' });
    }

    // The token is valid, and decoded contains the user information
    const username = decoded.username;

  db.get(
    'SELECT COUNT(*) AS place FROM users WHERE username != "Liquem" AND all_coins_earned >= (SELECT all_coins_earned FROM users WHERE username = ?)',
    [username],
    (err, row) => {
      if (err) {
        return res.status(500).json({ message: 'Interner Serverfehler.' });
      }

      if (row) {
        const place = row.place + 0; // Add 1 to get the actual place
        res.json({ place });
      } else {
        // User not found in the highscores
        res.status(404).json({ message: 'Benutzer nicht gefunden.' });
      }
    }
  );
});
});


app.get('/user-count', (req, res) => {
  db.get('SELECT COUNT(*) AS userCount FROM users', (err, result) => {
    if (err) {
      return res.status(500).json({ message: 'Interner Serverfehler.' });
    }
    const userCount = result.userCount;
    res.json({ userCount });
  });
});

app.get('/server-time', (req, res) => {
  const currentTimestamp = new Date().getTime();
  res.json({ serverTime: currentTimestamp });
});

app.get('/global-coin-average', (req, res) => {
  db.get('SELECT AVG(all_coins_earned) AS average FROM users WHERE username != "Liquem"', (err, row) => {
    if (err) {
      return res.status(500).json({ message: 'Interner Serverfehler.' });
    }

    const averageCoins = row.average;

    res.json({ averageCoins });
  });
});

app.get('/user-profile/:token/:usernamed', (req, res) => {
  const { usernamed } = req.params;

  const token = req.params.token;

  if (!token) {
    return res.status(401).json({ message: 'Token is missing.' });
  }

  // Verify the token using the JWT secret key
  jwt.verify(token, jwtSecret, (err, decoded) => {
    if (err) {
      return res.status(403).json({ message: 'Invalid token.' });
    }

    // The token is valid, and decoded contains the user information
    const username = decoded.username;

    db.get('SELECT coins FROM users WHERE username = ?', [username], async (err, userRow) => {
      if (err) {
        return res.status(500).json({ message: 'Interner Serverfehler.' });
      }
  
      if (!userRow) {
        return res.status(401).json({ message: 'Ungültige Anmeldeinformationen.' });
      }
  



    checkActiveSessions(req, res, () => {
  // Abrufen der ausgerüsteten Items und der Anzahl der Coins für den Benutzer
  db.get('SELECT equipped_item, equipped_item2, equipped_banner, equipped_pose, equipped_color, all_coins_earned, created_at, country_code FROM users WHERE username COLLATE NOCASE = ?', [usernamed], (err, userDetails) => {
    if (err) {
      return res.status(500).json({ message: 'Interner Serverfehler.' });
    }

    if (!userDetails) {
      return res.status(404).json({ message: 'Benutzer nicht gefunden.' });
    }

    const joinedTimestamp = new Date(userDetails.created_at).getTime();
    const currentTime = new Date().getTime();
    const timeSinceJoined = currentTime - joinedTimestamp;

// Calculate days, months, and years
    const daysSinceJoined = Math.floor(timeSinceJoined / (1000 * 60 * 60 * 24));
    const monthsSinceJoined = Math.floor(daysSinceJoined / 30);
    const yearsSinceJoined = Math.floor(monthsSinceJoined / 12);

    let displayString;

    
    if (yearsSinceJoined > 0) {
    displayString = `${yearsSinceJoined} year${yearsSinceJoined > 1 ? 's' : ''}`;
    } else if (monthsSinceJoined > 0) {
    displayString = `${monthsSinceJoined} month${monthsSinceJoined > 1 ? 's' : ''}`;
    } else {
    displayString = `${daysSinceJoined} day${daysSinceJoined > 1 ? 's' : ''}`;
    }

    res.json({
      equipped_item: userDetails.equipped_item,
      equipped_item2: userDetails.equipped_item2,
      equipped_banner: userDetails.equipped_banner,
      equipped_pose: userDetails.equipped_pose,
      equipped_color: userDetails.equipped_color,
      all_coins_earned: userDetails.all_coins_earned,
      days_since_joined: displayString,
      country_code: userDetails.country_code, // Include the country code in the response
    });
  });
});
});
});
});

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});


// Funktion zum Ändern der Coins eines Benutzers in der Konsole
rl.on('line', (input) => {
  const command = input.trim();
  if (command === 'exit') {
    rl.close();
    return;
  }

  if (command.startsWith('/change-coins')) {
    // Extract username and newCoins from the command
    const match = /\/change-coins\s+(\w+)\s+(\d+)/.exec(command);

    if (match) {
      const username = match[1];
      const newCoins = match[2];
      changeCoinsInConsole(db, username, newCoins);
    } else {
      console.log('Invalid command. Use /change-coins <username> <newCoins> or "exit" to quit.');
    }
  } else {
    console.log('Invalid command. Use /change-coins <username> <newCoins> or "exit" to quit.');
  }
});

function changeCoinsInConsole(db, username, newCoins) {
  const parsedCoins = parseInt(newCoins, 10);

  if (isNaN(parsedCoins)) {
    console.log('Invalid input for coins. The change was not performed.');
    return;
  }

  // check liquem games auth
  db.get('SELECT * FROM users WHERE username = ?', [username], (err, row) => {
    if (err) {
      console.error('Error checking the username in the database:', err);
    } else if (!row) {
      console.log(`The user ${username} does not exist.`);
    } else {
      // User exists, update the coins in the database
      db.run('UPDATE users SET coins = ? WHERE username = ?', [parsedCoins, username], (updateErr) => {
        if (updateErr) {
          console.error('Error updating coins in the database:', updateErr);
        } else {
          console.log(`Coins for user ${username} successfully changed to ${parsedCoins}.`);
        }
      });
    }
  });
}



rl.on('line', (input) => {
  const command = input.trim().toLowerCase();
  if (command === 'mt on') {
    maintenanceMode = true;
    console.log('Wartungsarbeiten sind jetzt aktiviert.');
  } else if (command === 'mt off') {
    maintenanceMode = false;
    console.log('Wartungsarbeiten sind jetzt deaktiviert.');
  } else {
    console.log('Invalid command. Use "/maintenance off or /maintenance on" or "exit" to quit.');
  }
});

app.post('/change-password/:token/:currentPassword/:newPassword', (req, res) => {
  const { currentPassword, newPassword } = req.params;

  const token = req.params.token;

  if (!token) {
    return res.status(401).json({ message: 'Token is missing.' });
  }

  // Verify the token using the JWT secret key
  jwt.verify(token, jwtSecret, (err, decoded) => {
    if (err) {
      return res.status(403).json({ message: 'Invalid token.' });
    }

    // The token is valid, and decoded contains the user information
    const username = decoded.username;


  // Validiere die Eingabe
  const currentPasswordError = validateUserInput(username, currentPassword);
  const newPasswordError = validateUserInput(username, newPassword);

  if (currentPasswordError || newPasswordError) {
    return res.status(400).json({ message: 'Ungültige Eingabe.' });
  }

  // Hash das eingegebene aktuelle Passwort und vergleiche es mit dem in der Datenbank gespeicherten Hash
  const hmac = createHmac('sha256', encryptionKey);
  const currentPasswordHash = hmac.update(currentPassword).digest('hex');

  db.get('SELECT * FROM users WHERE username = ? AND password = ?', [username, currentPasswordHash], (err, userRow) => {
    if (err) {
      return res.status(500).json({ message: 'Interner Serverfehler.' });
    }

    if (!userRow) {
      return res.status(401).json({ message: 'Ungültiges aktuelles Passwort.' });
    }

    // Hash das neue Passwort
    const newHmac = createHmac('sha256', encryptionKey);
    const newHashedPassword = newHmac.update(newPassword).digest('hex');

    // Aktualisiere das Passwort in der Datenbank
    db.run('UPDATE users SET password = ? WHERE username = ?', [newHashedPassword, username], (err) => {
      if (err) {
        return res.status(500).json({ message: 'Interner Serverfehler beim Aktualisieren des Passworts.' });
      }

      res.json({ message: 'Passwort erfolgreich geändert.' });
    });
  });
});
});


app.get('/verify-token/:token', (req, res) => {

  const token = req.params.token;

  if (!token) {
    return res.status(401).json({ message: 'Token is missing.' });
  }

  // Verify the token using the JWT secret key
  jwt.verify(token, jwtSecret, (err, decoded) => {
    if (err) {
      return res.status(403).json({ message: 'Invalid token.' });
    }

    // The token is valid, and decoded contains the user information
    const username = decoded.username;
    res.json({
      message: `${username}`,
  });
});
});



app.listen(port, () => {
  console.log(`Server läuft auf Port ${port}`);
});
