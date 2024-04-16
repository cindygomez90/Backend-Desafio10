const passport = require ('passport')
const { Router } = require ("express")
const { passportCall}  = require ('../middleware/pasportCall.js')
const { authorization } = require ('../middleware/authentication.js')
const SessionController = require('../controllers/sessions.controller.js')
const ResetPasswordController = require('../controllers/resetPassword.controller.js')


const sessionsRouter = Router ()
const { register, failregister, login, faillogin, current, logout, GitHub } = new SessionController ()
const { requestPasswordReset, resetPassword } = new ResetPasswordController()

//Endpoint para el registro del usuario
sessionsRouter.post ('/register', register)
sessionsRouter.get('/failregister', failregister)

//Endpoint para el ingreso del usuario
sessionsRouter.post ('/login', login)
sessionsRouter.get('/faillogin', faillogin)


//Endpoint para acceder a current
sessionsRouter.get('/current', passportCall ('jwt'), authorization (['ADMIN']), current)

//Endpoint para el cierre de sesión del usuario
sessionsRouter.post('/logout', logout)

//Endpoint para solicitar restablecimiento de contraseña 
sessionsRouter.post('/forgot-password', requestPasswordReset)

//Endpoint para restablecer contraseña 
sessionsRouter.post('/reset-password/:token', resetPassword)

//Endpoint para github
sessionsRouter.get('/github', passport.authenticate('github', { scope: ['user:email'] }))
sessionsRouter.get('/githubcallback', passport.authenticate('github', { session: false, failureRedirect: '/api/sessions/login' }), GitHub)


module.exports = sessionsRouter