require('dotenv').config()

const jwt = require('jsonwebtoken')
const { sendMail } = require('../utils/sendMail.js')
const { isValidPassword } = require('../utils/hashBcrypt.js')
const { userService } = require ('../repositories/index.js')


class ResetPasswordController {

    constructor() {
        this.userService = userService
    }

    async requestPasswordReset(req, res) {
        try {
            const { email } = req.body
            const user = await this.userService.getUser({ email })

            if (!user) {
            return res.status(404).json({ message: 'No se encontró un usuario con este correo electrónico.' })
            }

            const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET_KEY, { expiresIn: '1h' })
            const resetLink = `${process.env.BASE_URL}/reset-password/${token}`

            await sendMail(
                user.email, 
                'Restablecer contraseña', 
                `<p>Haga clic en el siguiente enlace para restablecer su contraseña:</p><a href="${resetLink}">${resetLink}</a>`)

            return res.status(200).json({ message: 'Se ha enviado un correo electrónico con instrucciones para restablecer la contraseña.' })

        } catch (error) {            
            console.error(error)
            return res.status(500).json({ message: 'Ocurrió un error al solicitar el restablecimiento de contraseña.' })
        }
    }

    async resetPassword(req, res) {
        try {
            const { token } = req.params
            const { newPassword, repeatPassword } = req.body

            if (newPassword !== repeatPassword) {
            return res.status(400).json({ message: 'Las contraseñas no coinciden.' })
            }

            const decodedToken = jwt.verify(token, process.env.JWT_SECRET_KEY);
            const user = await this.userService.getUser({ _id: decodedToken.userId })

            if (!user) {
            return res.status(404).json({ message: 'No se encontró un usuario asociado a este token.' })
            }

            if (isValidPassword(newPassword, user.password)) {
            return res.status(400).json({ message: 'La nueva contraseña no puede ser igual a la anterior.' })
            }

            user.password = newPassword
            await this.userService.updateUser(decodedToken.userId, { password: newPassword })
            return res.status(200).json({ message: 'Contraseña restablecida exitosamente.' })

        } catch (error) {
            if (error.name === 'TokenExpiredError') {
            return res.status(400).json({ message: 'El enlace para restablecer la contraseña ha expirado. Por favor, solicite uno nuevo.' })
            }
            console.error(error);
            return res.status(500).json({ message: 'Ocurrió un error al restablecer la contraseña.' })
        }
    }
}


module.exports = ResetPasswordController
