const jwt 		= require('jwt-simple');
const User 		= require('../models/user');
const config 	= require('../config');

/**
 * Create JWT Token
 * https://jwt.io/
 */
function tokenForUser(user) {

	const timestamp = new Date().getTime();

	// "sub" = "subject" of the token
	// "iat" = "issued at time"
	return jwt.encode({ 
		sub: user.id, 
		iat: timestamp 
	}, config.secret);
}

exports.signin = function(req, res, next) {
	// Already had email and password auth'd
	// We just need to give them a token
	
	// Passport makes user availabke on req as part of
	// done() callback (see localLogin() strategy)
	const user = req.user;

	res.send( {token: tokenForUser(user) });
};


exports.signup = function(req, res, next) {
	
	const email 	= req.body.email;	
	const password 	= req.body.password;

	if (!email || !password) {
		return res.status(422).send({
			error: 'You must provide both email and password'
		})
	}

	// See if a user with the given email exists
	User.findOne({ email: email }, function(err, existingUser) {
		if (err) { return next(err); }
	
		// If a user with email already exists, return an error 
		// along with appropriate HTTP status code
		if (existingUser) {
			return res.status(422).send({ error: 'Email is already in use' });
		}
		
		// If a user with email does NOT exist (fresh email), 
		// create and save User record
		const user = new User({
			email: email,
			password: password
		});

		// Save the new User
		user.save(function(err) {
			if (err) { return next(err); }

			// Respond to request providing a JWR that
			// user can use to auth subsequent requests
			res.json({ token: tokenForUser(user) });
		});

	});
}