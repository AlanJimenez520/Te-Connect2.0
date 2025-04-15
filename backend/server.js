require('dotenv').config();

// Importar dependencias
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs'); // Para encriptar contraseñas
const jwt = require('jsonwebtoken'); // Para generar/verificar tokens JWT
const validator = require('validator'); // Para validar email, etc.

const app = express();

// Middlewares
app.use(cors()); // Permite solicitudes desde otros orígenes
app.use(express.json()); // Permite recibir JSON en las peticiones

// Conexión a MongoDB
mongoose.connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => {
    console.log('✅ Conectado a MongoDB');
}).catch((err) => {
    console.error('❌ Error en MongoDB:', err);
});

// Esquema y modelo de usuario para MongoDB
const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    lastName: { type: String, required: true },
    phone: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true }
});
const User = mongoose.model('User', userSchema);

// Función para generar un token JWT usando el ID del usuario
function generateToken(userId) {
    return jwt.sign({ userId }, process.env.JWT_SECRET, { expiresIn: '1d' });
}

// Middleware para verificar que el token JWT es válido
function authMiddleware(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
        return res.status(401).json({ success: false, error: 'Falta token' });
    }
    const token = authHeader.split(' ')[1];
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.userId = decoded.userId; // Guardar el ID en la solicitud
        next(); // Continuar con la ruta
    } catch (error) {
        return res.status(401).json({ success: false, error: 'Token inválido o expirado' });
    }
}

// 1. Registro de usuario: POST /api/register
app.post('/api/register', async(req, res) => {
    try {
        let { name, lastName, phone, email, password } = req.body;

        // Validar que todos los campos estén presentes
        if (!name || !lastName || !phone || !email || !password) {
            return res.status(400).json({ success: false, error: 'Faltan datos' });
        }

        // Normalizar email
        email = email.trim().toLowerCase();

        // Validar formato de email
        if (!validator.isEmail(email)) {
            return res.status(400).json({ success: false, error: 'Correo inválido' });
        }

        // Validar longitud mínima de la contraseña
        if (password.length < 8) {
            return res.status(400).json({ success: false, error: 'Contraseña muy corta (mín. 8)' });
        }

        // Verificar si el correo ya existe
        const emailExists = await User.findOne({ email });
        if (emailExists) {
            return res.status(400).json({ success: false, error: 'Correo ya registrado' });
        }

        // Verificar si el teléfono ya existe
        const phoneExists = await User.findOne({ phone });
        if (phoneExists) {
            return res.status(400).json({ success: false, error: 'Teléfono ya registrado' });
        }

        // Encriptar contraseña
        const hashedPassword = await bcrypt.hash(password, 10);

        // Crear y guardar nuevo usuario
        const newUser = new User({
            name,
            lastName,
            phone,
            email,
            password: hashedPassword
        });
        await newUser.save();

        console.log('Usuario registrado:', newUser._id);
        return res.json({ success: true, message: 'Usuario registrado correctamente' });
    } catch (error) {
        console.error('Error en /api/register:', error);
        return res.status(400).json({ success: false, error: 'No se pudo registrar' });
    }
});

// 2. Login de usuario: POST /api/login
app.post('/api/login', async(req, res) => {
    try {
        let { emailOrPhone, password } = req.body;
        emailOrPhone = emailOrPhone.trim();

        // Buscar usuario por email o teléfono
        let user = await User.findOne({ email: emailOrPhone });
        if (!user) {
            user = await User.findOne({ phone: emailOrPhone });
        }
        if (!user) {
            return res.status(401).json({ success: false, error: 'Usuario no encontrado' });
        }

        // Comparar contraseña ingresada con la almacenada
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ success: false, error: 'Contraseña incorrecta' });
        }

        // Generar token JWT
        const token = generateToken(user._id);
        return res.json({
            success: true,
            token,
            user: {
                id: user._id,
                name: user.name,
                lastName: user.lastName,
                email: user.email,
                phone: user.phone
            }
        });
    } catch (error) {
        console.error('Error en /api/login:', error);
        return res.status(400).json({ success: false, error: 'No se pudo iniciar sesión' });
    }
});

// 3. Ruta protegida que requiere autenticación: GET /api/protegido
app.get('/api/protegido', authMiddleware, (req, res) => {
    return res.json({
        success: true,
        message: 'Acceso concedido',
        userId: req.userId
    });
});

// Iniciar servidor en el puerto especificado
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 Servidor corriendo en http://localhost:${PORT}`);
});