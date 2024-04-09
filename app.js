const express = require("express");
const app = express();
const port = 5000;
const jwt = require('jsonwebtoken');
const keys = require('./claves/keys')

app.set('key', keys.key)
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

app.get('/', (req, res) => {
    res.send('Hello World!')
  })

/**Funcion para logear el usuario y verificando que sean correctas  las credenciales y si son correctas
 * devolvera el token con el cual puedo acceder a la aplicacion. este token que devuelve se enviara en
 * la cabecera de la peticion  
 */
app.post('/login', (req, res) => {
  if(req.body.user === 'admin' && req.body.password === 'admin123'){

    //este es el payload  de la informacion que vamos a enviar
    const payload = {
      check: true
    };

    const token = jwt.sign(payload, app.get('key'), {
      expiresIn: '1h'
    });
    res.json({msj: 'El Usuario es correcto', token: token})
  }else{
    res.json({msj: 'El Usuario es incorrecto'})
  }
});


//middleware tipo de autenticacion y de acceso
const verificacion = express.Router();
verificacion.use((req, res, next) => {
  let token = req.headers['x-access-token'] || req.headers['authorization'];
  // console.log(token); esta linea me muestra el token por consola
  //condicion para saber si  viene el token dentro de la peticion o no
  if(!token){
    res.status(401).json({msj: 'No hay token debes iniciar sesion'})
    return
  }
  //condicion para quitar palabra bearer del token
  if(token.startsWith('Bearer ')){
    token = token.slice(7, token.length).trimLeft();
    console.log(token);
  }

  //validar si el token que estoy recibiendo desde postman es correcto
  if(token){
    jwt.verify(token, app.get('key'), (err, decoded) => {
      if(err){
        return res.status(401).json({msj: 'Token no valido'})
      }else{
        req.decoded = decoded;
        next();
      }
    })
  }
})

/**Funcion que me permite validar el tokeny la manera como salia que 
 * viene con el bearer y que toca quitarselo
*/
app.get('/info', verificacion, (req, res) => {
  res.json({msj: 'Acceso permitido'})
})




// listen  me sirve para escuchar peticiones
app.listen(port, () => {
  console.log(
    `Servidor escuchando en el puerto ${port} http://localhost:5000/ `
  );
});
