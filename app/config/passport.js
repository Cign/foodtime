const LocalStrategy = require('passport-local')
const User = require('../models/user')
const bcrypt = require('bcrypt')

  function init(passport){
    passport.use(new LocalStrategy({ usernameField: 'email' }, async (email, password, done) => {
        //Login

        //CHeck if email exist
        const user = await User.findOne({ email: email })
        if(!user){(null, false, {message: "No user with this email"})
            return done
        }

        bcrypt.compare(password, user.password).then(match => {
            if(match){
                return done(null, user, {message: "Welcome"})
            }
            
            return done(null, false, {message: "Wrong username or password"})
        
        }).catch(err => {
            return done(null, false, {message: "Something went wrong"})
        })
    }))

    passport.serializeUser((user, done) => {
        done(null, user._id)
    })

    passport.deserializeUser((id, done) => {
        User.findById({ _id: id }, (err, user) =>{
            return done(err, user)
        })
    })
}

module.exports = init