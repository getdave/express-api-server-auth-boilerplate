const mongoose 	= require('mongoose');
const Schema 	= mongoose.Schema;
const bcrypt 	= require('bcrypt-nodejs');

const userSchema = new Schema({
	email: {
		type: String,
		unique: true,
		lowercase: true
	},
	password: String
});

userSchema.pre('save', function(next){
	// Access the instance of the User model
	const user = this;

	bcrypt.genSalt(10, function(err, salt) {
		if (err) { return next(err); }

		bcrypt.hash(user.password, salt, null, function(err, hash) {
			if (err) { return next(err); }

			user.password = hash;
			next();
		});
	});
});


userSchema.methods.comparePassword = function(candidatePassword, callback) {
	// Bcrypt will pull off salt from password in the DB
	// use it to encrypt the candidate (submitted) password
	// and then compare the result against the password in the DB
	// the password is never "de-crypted" as such...obviously
	bcrypt.compare(candidatePassword, this.password, function(err, isMatch) {
		if (err) { return callback(err); }
		// isMatch is true/false depending on success vs failure
		callback(null, isMatch);
	});
};


// Note: this is the Model Class not an instance
const ModelClass = mongoose.model('user', userSchema);


module.exports = ModelClass;