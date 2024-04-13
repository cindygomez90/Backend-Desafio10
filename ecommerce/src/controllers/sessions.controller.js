const bcrypt = require('bcrypt')
const { generateToken }  = require ('../utils/jsonwebtoken.js')
const { userService, productService } = require ('../repositories/index.js')
const { UserDto } = require('../dto/userDto.js')

class SessionController {

    constructor () {
        this.userService = userService
        this.productService = productService
    }

    register = async (request, responses)=>{
        try {        
            const {first_name, last_name, email, password, role} = request.body       
            console.log (first_name, last_name, email, password, role)
            if (first_name === '' || password === '') {
                return responses.send ('Faltan llenar campos obligatorios')
            } 
    
            const existingUser = await this.userService.getUser({ email })
            if (existingUser) {
                return responses.send({
                    status: 'error',
                    error: 'El correo electrónico ya está registrado',
                })
            }
    
            const hashedPassword = await bcrypt.hash(password, 10)
        
            const newUser = {
                first_name,
                last_name,
                email,
                password: hashedPassword,
                role: role || 'USER'
            }
            const result = await this.userService.createUser (newUser)
            
            const userDto = new UserDto(result)
            const token = generateToken({
                id: result._id
            })
            responses.cookie('cookieToken', token, {
                maxAge: 60 * 60 * 1000 * 24,       
                httpOnly: true  
            }).send({   
                status: 'success',
                usersCreate: userDto, 
                token   
            })
        } catch (error) {
            responses.send ({
                status:'error', 
                error:error.message
            })        
        }
    }

    failregister = async (request, responses) => {
        responses.send({error: 'falla en el register'})
    }

    login = async (request, responses)=>{
        const {email, password} = request.body       
        
        const user = await this.userService.getUser ({email}) 
        console.log (user)
        if (!user) {
            return responses.send ({
                status: 'error', 
                error: 'Usuario con ese mail no existe'
            })
        }
    
        const isPasswordValid = await bcrypt.compare(password, user.password)
    
        if (!isPasswordValid) {
            return responses.send({ status: 'error', error: 'Contraseña incorrecta' })
        }
        
        const userDto = new UserDto(user)

        const token = generateToken({
            fullname: userDto.full_name,
            id: user._id,
            email: userDto.email,
            role: userDto.role
        })
        responses.cookie('cookieToken', token, {
            maxAge: 60*60*1000*24,  
            httpOnly: true 
        })
    
        const products = await this.productService.getProducts()
        responses.render('products', { user: userDto, products})
    }

    faillogin = async (request, responses) => {
        responses.send({error: 'falla en el register'})
    }

    current = async (request, responses) => {       
        try {
            console.log('Objeto user recibido:', request.user)
            const userDto = new UserDto (request.user)
            
            if (!userDto) {
                return responses.status(404).json({
                    status: 'error', 
                    error: 'Usuario no encontrado' 
                })
            }
            const responseData = {
                fullname: userDto.full_name,
                email: userDto.email,
                role: userDto.role
            }

            responses.json(responseData)
            
        } catch (error) {
            console.error('Error al recuperar datos del usuario:', error)
            responses.status(500).json({ 
                status: 'error', 
                error: 'Error del servidor' 
            })
        }
    }

    logout = (request, responses) => {
        responses.clearCookie('cookieToken') 
        responses.redirect('/login')
    }

    GitHub = async(request, responses) => {
        console.log('request.user:', request.user)
        const user = request.user.user
        const products = await this.productService.getProducts()
        responses.render('products', { user: user, products })
    }
}

module.exports = SessionController