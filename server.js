const express = require('express'); // Import the Express framework for building the server
const cors = require('cors'); // Import CORS middleware to handle cross-origin requests
const { BlobServiceClient } = require('@azure/storage-blob'); // Azure Blob Storage SDK for handling blob storage operations
const multer = require('multer'); // Multer for handling file uploads
require('dotenv').config(); // Loads environment variables from a .env file
const axios = require('axios'); // Import Axios for making HTTP requests
const sqlite3 = require('sqlite3').verbose(); // Import SQLite3 with verbose mode for detailed error messages
const app = express(); // Create an instance of the Express application
const bodyParser = require('body-parser'); // Body-parser to parse incoming request bodies
const bcrypt = require('bcrypt'); // Import bcrypt for password hashing
const PORT = process.env.PORT; // Port from environment variables

// Middleware setup
app.use(cors()); // Use CORS middleware
app.options('*', cors()); // Enable preflight for all routes
app.use(express.json()); // Automatically parse incoming JSON payloads

// Middleware for parsing URL-encoded bodies and JSON requests
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// Initialize Azure Blob Storage client
const blobServiceClient = BlobServiceClient.fromConnectionString(process.env.AZURE_STORAGE_CONNECTION_STRING);
const containerName = process.env.AZURE_IMAGE_CONTAINER_NAME; // Name of the image container in Azure

// Multer configuration for handling file uploads
const upload = multer({ storage: multer.memoryStorage() }); // Files will be stored in memory for temporary use

const path = require('path'); // Import path module to handle file paths
const dbPath = path.resolve(__dirname, 'SwineFluDatabaseV3.db'); // Resolve path to the SQLite database
const db = new sqlite3.Database(dbPath, (err) => { // Create a new SQLite database instance
  if (err) {
    console.error('Error opening database:', err.message);
  } else {
    console.log('Connected to the database.');
  }
});

const fs = require('fs'); // Import the file system module to handle file operations
if (!fs.existsSync(dbPath)) { // Check if the database file exists
  console.error('Database file not found at', dbPath);
}

const dbDir = path.dirname(dbPath); // Get the directory of the database file
if (!fs.existsSync(dbDir)) { // Check if the database directory exists
  fs.mkdirSync(dbDir, { recursive: true }); // Create the directory if it does not exist
}

// Sign-in endpoint
app.post('/api/signin', (req, res) => {
  const { username, password } = req.body;

  // Check if all required fields are provided
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required.' });
  }

  // Query the database for the user
  db.get('SELECT * FROM users WHERE username = ?', [username], (err, row) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ error: 'Internal server error.' });
    }

    if (!row) {
      return res.status(401).json({ error: 'Invalid username or password.' });
    }

    // Compare the password (assuming you're hashing passwords)
    const isValidPassword = bcrypt.compareSync(password, row.password);
    if (!isValidPassword) {
      return res.status(401).json({ error: 'Invalid username or password.' });
    }

    // Sign-in successful
    return res.status(200).json({ message: 'Sign-in successful.', username: row.username, organization: row.organization });
  });
});

// Sign-up endpoint
app.post('/api/signup', (req, res) => {
  const { email, username, password, organization } = req.body;

  // Check if all required fields are provided
  if (!username || !password || !organization) {
    return res.status(400).json({ error: 'Organization, username, and password are required.' });
  }

  // Check if the user already exists with the same email
  db.get('SELECT * FROM users WHERE email = ?', [email], (err, row) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ error: 'Internal server error.' });
    }

    // Check if the username is already taken
    db.get('SELECT * FROM users WHERE username = ?', [username], (err, row) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ error: 'Internal server error.' });
      }

      if (row) {
        return res.status(400).json({ error: 'Username is already taken.' });
      }

      // Hash the password for security
      const hashedPassword = bcrypt.hashSync(password, 10);

      // Insert new user into the database
      db.run('INSERT INTO users (email, username, password, organization) VALUES (?, ?, ?, ?)', [email, username, hashedPassword, organization], function(err) {
        if (err) {
          console.error('Insert error:', err);
          return res.status(500).json({ error: 'Internal server error.' });
        }
        return res.status(201).json({ message: 'User registered successfully.', username: username, organization: organization });
      });
    });
  });
});

/**
 * Endpoint to handle submission of test data.
 * Expects JSON payload with latitude (lat), longitude (lng), and result (result).
 * Saves the test data into the model_results table in the database.
 */
app.post('/api/submit_test', (req, res) => {
  const { lat, lng, result, username, organization, date, prob } = req.body; // Destructure latitude, longitude, and result from request body

  // Save data to the database
  db.run(`INSERT INTO model_results (lat, lng, result, user, org, date, prob) VALUES (?, ?, ?, ?, ?, ?, ?)`, [lat, lng, result, username, organization, date, prob], function (err) {
    if (err) {
      console.error('Error saving test data:', err);
      res.status(500).json({ error: 'Failed to save data' });
    } else {
      console.log('Test data saved successfully');
      res.status(200).json({ message: 'Data saved successfully' });
    }
  });
});

// Close the database connection when the application shuts down
process.on('SIGINT', () => {
  db.close((err) => { // Close the database connection
    if (err) {
      console.error('Error closing database:', err.message);
    } else {
      console.log('Database connection closed.');
    }
    process.exit(0); // Exit the process
  });
});

/**
 * API endpoint to fetch all positive test cases from the database.
 * Queries the 'model_results' table for entries where result = 1 (positive result).
 * Returns the results as an array of cases.
 */
app.get('/api/cases', (req, res) => {
  // Query the database for all positive test results
  db.all('SELECT lat, lng, result, date, prob, user, org FROM model_results WHERE result = 1', [], (err, cases) => { // Query to get positive cases
    if (err) {
      console.error('Error fetching cases:', err);
      return res.status(500).json({ message: 'Internal Server Error' });
    }
    if (!cases || cases.length === 0) {
      return res.status(404).json({ message: 'No cases found' });
    }
    // Send the cases as a JSON response
    res.json(cases);
  });
});

/**
 * API endpoint to check if a username exists in the database.
 * Expects a 'username' in the request body.
 * Responds with 'true' if the username is available, otherwise 'false'.
 */
app.post('/api/check-username', upload.none(), async (req, res) => {
  const username = req.body.username; // Extract the username from the request body
  console.log('Received username:', username);

  try {
    // Query the database to count occurrences of the username
    db.get('SELECT COUNT(*) AS count FROM model_results WHERE user = ?', [username], (err, row) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ error: 'Database query error' });
      }

      if (row.count > 0) {
        res.json(false); // Username exists
      } else {
        res.json(true); // Username is available
      }
    });
  } catch (error) {
    console.error('Error checking username:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * API endpoint to fetch the count of positive cases from the database.
 * Queries the database for results where result = 1 (positive).
 * Responds with the count of positive cases.
 */
app.get('/api/positive-count', (req, res) => {
  db.get('SELECT COUNT(*) AS positiveCount FROM model_results WHERE result = 1', [], (err, posRow) => { // Query to count positive cases
    if (err) {
      console.error('Error fetching positive case count:', err);
      return res.status(500).json({ message: 'Internal Server Error' });
    }
    res.json({ positiveCount: posRow.positiveCount }); // Respond with the count of positive cases
  });
});

/**
 * API endpoint to fetch the count of negative cases.
 * Queries the database for results where result = 0 (negative).
 * Responds with the count of negative cases.
 */
app.get('/api/negative-count', (req, res) => {
  db.get('SELECT COUNT(*) AS negativeCount FROM model_results WHERE result = 0', [], (err, negRow) => { // Query to count negative cases
    if (err) {
      console.error('Error fetching negative cases count:', err);
      return res.status(500).json({ message: 'Internal Server Error' });
    }
    res.json({ negativeCount: negRow.negativeCount }); // Respond with the count of negative cases
  });
});

/**
 * API endpoint to retrieve all images stored in Azure Blob Storage.
 * Returns an array of image URLs.
 */
app.get('/retrieve-images', async (req, res) => {
  try {
      const containerClient = blobServiceClient.getContainerClient(containerName);
      const images = [];

      // List all blobs in the container and push their URLs to the images array
      for await (const blob of containerClient.listBlobsFlat()) {
        const blockBlobClient = containerClient.getBlockBlobClient(blob.name); //blockBlobClient is the mediator between the app and the blob storage
        const imageUrl = `https://${process.env.AZURE_STORAGE_ACCOUNT_NAME}.blob.core.windows.net/${containerName}/${blob.name}`;

        // Get the blob properties, which include metadata
        const blobProperties = await blockBlobClient.getProperties();
        const metadata = blobProperties.metadata; // Retrieve the metadata from the blob properties
        images.push({ _id: blob.name, url: imageUrl, metadata: metadata || {} }); // Store the blob name and URL in the images array
      }

      res.json(images);
  } catch (error) {
      console.error('Error fetching images:', error);
      res.status(500).send('Error fetching images');
  }
});

/**
 * API endpoint to fetch detailed information about all cases.
 * Returns all data from the 'model_results' table, including result, date, probability, username, and organization.
 */
app.get('/gallery-info', (req, res) => {
  db.all('SELECT result, date, prob, user, org FROM model_results', [], (err, cases) => {
    if (err) {
      console.error('Error fetching cases:', err);
      return res.status(500).json({ message: 'Internal Server Error' });
    }
    if (!cases || cases.length === 0) {
      return res.status(404).json({ message: 'No cases found' });
    }
    res.json(cases); // Respond with the list of cases
  });
});

/**
 * API endpoint for image upload and prediction.
 * Uploads an image to Azure Blob Storage and sends it to a machine learning model for prediction.
 */
app.post('/predict', upload.single('image'), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded.' });
  }

  try {
    const apiKey = process.env.AZURE_PREDICTION_KEY; // Retrieve the Azure Prediction key from environment variables
    
    // Send the image to your Azure Machine Learning model for prediction
    const modelResponse = await axios.post(
      process.env.AZURE_MODEL_ENDPOINT,
      req.file.buffer, // Send the image file buffer directly to the model API
      {
        headers: {
          'Prediction-Key': apiKey, // Add your Prediction-Key header
          'Content-Type': 'application/octet-stream', // Set content type to application/octet-stream
        },
      }
    );

    // Parse the prediction response
    if (modelResponse.data) {
      const predictions = modelResponse.data.predictions; // Extract the predictions from the API response
      let highestProbability = 0.0;
      let recognition = {
        tagName: "error",
        probability: 0.0,
      };

      // Loop through predictions to find the one with the highest probability
      for (let i = 0; i < predictions.length; i++) {
        const prediction = predictions[i];
        const probability = prediction.probability;

        // Keep track of the highest probability prediction
        if (probability > highestProbability) {
          highestProbability = probability;
          recognition = {
            tagName: prediction.tagName,
            probability: probability,
          };
        }
      }

      // Save the prediction result in the database
      let result;
      switch (recognition.tagName) {
        case 'positive':
          result = 1;
          break;
        case 'negative':
          result = 0;
          break;
        case 'non-image':
          result = 2;
          break;
        default:
          result = -1;
      }

      const lat = req.body.lat; // Latitude from the request body
      const lng = req.body.lng; // Longitude from the request body
      const user = req.body.user; // Username from the request body
      const org = req.body.org; // Organization name from the request body
      const prob = recognition.probability; // Probability value from the model prediction
      const currentDate = new Date(); // Get the current date
      const date = `${currentDate.getFullYear()}-${String(currentDate.getMonth() + 1).padStart(2, '0')}-${String(currentDate.getDate()).padStart(2, '0')}`; // Format the date

      if(result !== 2) {
        // Insert the prediction result into the database
        db.run(`INSERT INTO model_results (lat, lng, result, prob, date, user, org) VALUES (?, ?, ?, ?, ?, ?, ?)`, [lat, lng, result, prob, date, user, org], function (err) {
          if (err) {
            console.error('Error saving test data:', err);
            return res.status(500).json({ error: 'Failed to save data to the database' });
          } else {
            console.log('Test data saved successfully');
            console.log(user);
          }
        });
      }

      // Upload the image to Azure Blob Storage
      const blobName = Date.now() + '-' + req.file.originalname; // Create a unique name for the uploaded file using the current timestamp
      const containerClient = blobServiceClient.getContainerClient(containerName); // Get the container client for Azure Blob Storage
      const blockBlobClient = containerClient.getBlockBlobClient(blobName); // Get the block blob client to upload the file

      // Define metadata to attach to the blob
      const metadata = {
        result: recognition.tagName || 'unknown',
        probability: prob.toString() || 'unknown',
        user: user.toString() || 'anonymous',
        org: org || 'unknown',
        date: date.toString() || 'unknown'
      };

      // Upload the file to Azure Blob Storage with metadata
      await blockBlobClient.upload(req.file.buffer, req.file.size, {
        metadata: metadata
      });
      
      res.json(recognition); // Send the prediction result back to the client
    } else {
      res.status(500).json({ error: 'No predictions found in the response' });
    }
  } catch (error) {
    console.error('Error processing image:', error);
    res.status(500).json({ error: 'Error processing image' });
  }
});

// Start the server and listen on the specified port
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`); // Log server status
});