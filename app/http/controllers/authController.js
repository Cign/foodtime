const User = require('../../models/user')
const bcrypt = require('bcrypt')
const passport = require('passport')

function authController() {

    const _getRedirectUrl = (req) => {
        return req.user.role === 'admin' ? '/admin/orders' : '/customers/orders'
    }
     
    return {
        login(req, res){
            res.render('auth/login')
        },
        register(req, res){
            res.render('auth/register')
        },
        async postRegister(req, res){
            const { name, email, tel, password, rpassword } = req.body
            //Validate
            if(!name || !email || !password || password!= rpassword){
                req.flash('error', 'All fields are required')
                req.flash('name', name)
                req.flash('email', email)
                req.flash('tel', tel)

                return res.redirect('/register')
            }

            //Check if email exist
            User.exists({ email: email }, (err, result) => {
                if(result){
                    req.flash('error', 'Email already exists')
                    req.flash('name', name)
                    req.flash('email', email)
                    req.flash('tel', tel)
                    return res.redirect('/register')
                }
            })

            //Hash passwd
            const hash = await bcrypt.hash(password, 10)

            //Create User
            const user = new User({
                name: name,
                email: email,
                password: hash,
                tel: tel,
            })

            user.save().then((user) => {
                //Login 
                console.log(user)

            }).catch((err) => {
                req.flash('error', err)
                    return res.redirect('/register')
            })
            console.log(req.body)
         },
         postLogin(req, res, next){
            passport.authenticate('local', (err, user, info) => {
                if(err){
                    req.flash('error', info.message)
                    return next(err)
                }
                if(!user){
                    req.flash('error', info.message)
                    return res.redirect('/login')
                }
                req.logIn(user, (err) => {
                    if(err){
                        req.flash('error', info.message)
                        return next(err)
                    }

                    return res.redirect(_getRedirectUrl(req))
                })
            })(req, res, next)
         },
         logout(req, res){
            req.logout()
            return res.redirect('/')
         }
    }
}

module.exports = authController;