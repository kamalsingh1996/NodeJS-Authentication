// Import the mongoose library
const mongoose = require('mongoose');
const { encode } = require('querystring'); 

// Encode the password
const password = 'Sakshi12345shar';
const encodedPassword = encode('Sakshi12345shar', 'utf8'); 

// Create the MongoDB connection URL with the encoded password
const dbURI = `mongodb+srv://sakshisharma:${password}@cluster0.rhakgv2.mongodb.net/?retryWrites=true&w=majority`;

// Connect to the MongoDB server with the provided URL and options 
mongoose.connect(dbURI, {
    // Options can be added here if needed
});






// Get a reference to the default Mongoose connection
const db = mongoose.connection;

db.on('error', console.error.bind(console, "Error connecting to MongoDB"));

db.once('open', function () {
    console.log('Connected to Database :: MongoDB');
});


module.exports = db;