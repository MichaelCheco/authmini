const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs')
const db = require('./database/dbConfig.js');
const jwt = require('jsonwebtoken');

const server = express();

server.use(express.json());
server.use(cors());



server.post('/api/register', (req, res) => {
  // grab usernames and passwords from body
  const creds = req.body;
  // generate the hash from the user's password
  const hash = bcrypt.hashSync(creds.password, 14) // rounds is 2^X
  // override the user.password with the hash
  creds.password = hash;
 // save the user to the database
db('users').insert(creds).then(
  ids => {
    res.status(201).json(ids);
  }
).catch(err => json({message: err}));
});

function protected(req, res, next) {
  const token = req.headers.authorization;
  if (token) {
   jwt.verify(token, jwtSecret, (err, decodedToken) => {
     if(err) {
       res.status(401).json({message: 'invalid token'})
     } else {
       req.decodedToken = decodedToken;
       next();
     }
   })
  }  else {
    res.status(401).json({message: 'no token'})
  }
}

function checkRole(role) {
  return function(req, res, next) {
    if (req.decodedToken && req.decodedToken.roles.includes(role)) {
      next()
    } else {
      res.status(403).json({message: 'Forbidden'})
    }
  }
}

const jwtSecret = 'nobody tosses a dwarf';

function generateToken(user) {

  const jwtPayload = {
    ...user,
    hello: 'FSW14',
    roles: ['admin', 'other']
  }


  const jwtOptions = {
    expiresIn: '5m'
  }
  return jwt.sign(jwtPayload, jwtSecret, jwtOptions)
}

server.post('/api/login', (req, res) => {
  // grab usernames and passwords from body
  const creds = req.body;

  db('users').where({ username: creds.username }).first()
  .then( user => {
      if(user && bcrypt.compareSync(creds.password, user.password)) {
        // passwords match and user exists by that username 
        const token = generateToken(user)
        res.status(200).json({message: 'Welcome!', token })
      } else {
        res.status(401).json({message: 'You shall not pass!'})
      }}).catch(err => json(err))
});



// protect this route, only authenticated users should see it
server.get('/api/users', protected, (req, res) => {
  db('users')
    .select('id', 'username', 'password') // added password to the select
    .then(users => {
      res.json({users});
    })
    .catch(err => res.send(err));
});

server.listen(3300, () => console.log('\nrunning on port 3300\n'));
