const passport 		= require('passport');
const User 			= require('../models/user');
const config 		= require('../config');

// This is a particular "Passport" Strategy - there are many 
// others such as "Facebook" or "Twitter" strategies
const JwtStrategy 	= require('passport-jwt').Strategy;
const ExtractJwt 	= require('passport-jwt').ExtractJwt;

const LocalStrategy = require('passport-local').Strategy;


/**
 * LOCAL STRATEGY
 */
const localOptions = {
	usernameField: 'email' // tell passport we're using email as the 'username'
};

const localLogin = new LocalStrategy(localOptions, function(email, password, done) {
	// Verify this username and passport
	// call done() with the user if it is correct email/pass
	// otherwise call done() with false
	
	User.findOne({ email: email }, function(err, user){
		// Error
		if (err) { return done(err); }

		// User not found
		if (!user) { return done(null, false); }

		// Compare passwords
		user.comparePassword(password, function(err, isMatch) {
			if (err) { return done(err); }
			if (!isMatch) { return done(null, false); }

			return done(null, user);
		});
		
	});
});


/**
 * JWT STRATEGY
 */
const jwtOptions = {
	// Tell Passport to look at request HEADER for JWT token
	jwtFromRequest: ExtractJwt.fromHeader('authorization'),
	secretOrKey: config.secret 	
};

// Create JWT Strategy
const jwtLogin = new JwtStrategy(jwtOptions, function(payload, done) {

	 // "payload" - decoded JWT payload
	 // "done"    - a callback function expects error and user object args

	// See if the user ID in the payload exists in the database
	// If it does, call done with that 
	// otherwise, call done without a user object
	// Remember: the "sub" property is the UserID
	User.findById(payload.sub, function(err, user) {
		if (err) { return done(err,false) };

		if (user) {
			// No error but we found a User!
			done(null, user);
		} else {
			// No error but no User either
			done(null, false);
		}
	});
});


// Tell Passport to use this strategy
passport.use(jwtLogin);
passport.use(localLogin);
