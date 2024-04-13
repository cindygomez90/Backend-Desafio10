const { productService } = require ('../repositories/index.js')
const { CustomError } = require ('../utils/errors/customError.js')
const { EErrors } = require ('../utils/errors/enums.js')
const { generateProductErrorInfo } = require ('../utils/errors/info.js')


    class ProductController {

        constructor () {
            this.productService = productService 
        }

        getProducts = async (req, res) => {
            try {
                const { limit = 10, pageQuery = 1, category, order, status } = req.query
        
                const filter = {}
                if (category) {
                    filter.category = category
                }
        
                if (status !== undefined) {
                    filter.status = status === 'true' ? true : status === 'false' ? false : undefined
                }
        
                const sortOptions = {}
                if (order === 'asc') {
                    sortOptions.price = 1
                } else {
                    sortOptions.price = -1
                }
        
                const {
                    docs,
                    hasPrevPage,
                    hasNextPage,
                    prevPage,
                    nextPage,
                    page,
                    totalPages,
                } = await this.productService.getProducts(filter, { limit, page: pageQuery, sort: sortOptions, lean: true })
        
                res.json({
                    status: 'success',
                    result: {
                        products: docs,
                        totalPages: totalPages,
                        hasPrevPage,
                        hasNextPage,
                        prevPage,
                        nextPage,
                        page,
                    },
                })
            } catch (error) {
                console.log(error);
                res.status(500).json({
                    status: 'error',
                    error: error.message,
                })
            }
        }
        
        getProduct = async (req, res)=>{  
            try {      
                const { pid } = req.params        
                const product = await this.productService.getProduct (pid)
                res.json({
                    status: 'success',
                    result: product
                })
            } catch (error) {
                console.log(error)
                res.status(500).json({
                    status: 'error',
                    message: 'Error al obtener el producto por ID.'
                })
            }
        }
        
        createProduct = async (request, responses, next)=>{                
            try {                               
                const productNew  = request.body

                //si alguno de los campos no viene se va a instanciar el error
                if (!productNew.title || !productNew.price || !productNew.stock) {
                    CustomError.createError({
                        name: 'Error en la creación de producto',
                        cause: generateProductErrorInfo(productNew),
                        message: 'Error al intentar crear el producto',
                        code: EErrors.PRODUCT_CREATION_ERROR
                    })
                }

                const result = await this.productService.createProduct (productNew)
        
                responses.send({
                    status: 'success',
                    result
                })
            } catch (error) {
                next(error)  
            }
        }
        
        updateProduct = async (req, res)=>{
            try {
            const { pid } = req.params
            const productToUpdate = req.body
            const product = await this.productService.updateProduct (pid, productToUpdate)
            
            res.status(200).send({
                status: 'success',
                message: product
            })
            } catch (error) {
                console.log(error)
            }
        }
        
        deleteProduct = async (request, responses) => {
            try {
                const { pid } = request.params
                const result = await this.productService.deleteProduct (pid)
        
                if (!result) {
                    return responses.status(404).json({ success: false, message: 'Producto no encontrado.' })
                }
                responses.json({ success: true, message: 'Producto eliminado correctamente.' })
            } catch (error) {
                console.log(error);
                responses.status(500).json({ success: false, message: 'Error al eliminar el producto.' })
            }
        }
    }


    module.exports = ProductController