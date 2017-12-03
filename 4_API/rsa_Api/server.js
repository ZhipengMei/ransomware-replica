var express = require('express'),
  app = express(),
  port = process.env.PORT || 3000,
  mongoose = require('mongoose'),
  Task = require('./api/models/rsaModel'), //created model loading here
  bodyParser = require('body-parser');

// mongoose instance connection url connection
mongoose.Promise = global.Promise;
// mongoose.connect('mongodb://localhost/rsadb');
mongoose.connect('http://ec2-13-58-22-230.us-east-2.compute.amazonaws.com:3000/rsadb');


app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// //middleware code to intercepts incoming http request
// app.use(function(req, res) {
//   res.status(404).send({url: req.originalUrl + ' not found'})
// });

var routes = require('./api/routes/rsaRoutes'); //importing route
routes(app); //register the route


app.listen(port);


console.log('rsa RESTful API server started on: ' + port);
