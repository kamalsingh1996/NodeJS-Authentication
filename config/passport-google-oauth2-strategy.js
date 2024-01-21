const passport = require('passport');
const googleStretegy = require('passport-google-oauth').OAuth2Strategy;
// require crypto for generating random password

const crypto = require('crypto');
const User = require('../models/User');

// tell passport to use new stretegy for google login
passport.use(new googleStretegy({
        clientID: '1095055357557-1boue64b980rsv5qilc9esu7jo4fclpv.apps.googleusercontent.com',
        clientSecret: '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',
        callbackURL: 'http://localhost:8000/user/auth/google/callback',
        passReqToCallback: true,
    },
    async function(request, accessToken, refreseToken, profile, done) {

        try {
            const user = await User.findOne({ email: profile.emails[0].value });
            if (user) {
                return done(null, user);
            }
            if (!user) {
                // if not found, creat user and set it as req.user
                const newUser = await User.create({
                    name: profile.displayName,
                    email: profile.emails[0].value,
                    password: crypto.randomBytes(20).toString('hex')
                })
                if (newUser) {
                    return done(null, newUser);
                }
            }
        } catch (error) {
            console.log('error in google stretegy passport', error);
        }
    }
));
module.exports = passport;

