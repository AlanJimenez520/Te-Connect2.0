// script.js

// ============================
// 1. Captcha local y verificador de contraseña (para registro)
// ============================
let captchaX = 0;
let captchaY = 0;

function generateCaptcha() {
    captchaX = Math.floor(Math.random() * 10) + 1;
    captchaY = Math.floor(Math.random() * 10) + 1;
    const captchaLabel = document.getElementById('captchaQuestion');
    if (captchaLabel) {
        captchaLabel.textContent = `Resuelve: ${captchaX} + ${captchaY} =`;
    }
}

function checkPasswordStrength(password) {
    const minLength = password.length >= 8;
    const hasDigit = /\d/.test(password);
    const hasUpper = /[A-Z]/.test(password);
    const hasSymbol = /[^A-Za-z0-9]/.test(password);
    let strengthMsg = 'Contraseña débil. Debe tener: min. 8 caracteres, dígitos, mayúsculas y símbolos.';
    if (minLength && hasDigit && hasUpper && hasSymbol) {
        strengthMsg = 'Contraseña fuerte.';
    }
    return strengthMsg;
}

if (window.location.pathname.endsWith('register.html')) {
    generateCaptcha();
    const regPassword = document.getElementById('regPassword');
    const passwordHelp = document.getElementById('passwordHelp');
    if (regPassword && passwordHelp) {
        regPassword.addEventListener('input', () => {
            const strength = checkPasswordStrength(regPassword.value);
            passwordHelp.textContent = strength;
        });
    }
}

// ============================
// 2. Manejo del formulario de registro
// ============================
const registerForm = document.getElementById('registerForm');
if (registerForm) {
    registerForm.addEventListener('submit', async(e) => {
        e.preventDefault();
        const name = document.getElementById('regName').value.trim();
        const lastName = document.getElementById('regLastName').value.trim();
        const phone = document.getElementById('regPhone').value.trim();
        const email = document.getElementById('regEmail').value.trim();
        const password = document.getElementById('regPassword').value.trim();
        const captchaResult = document.getElementById('captchaResult') ?
            document.getElementById('captchaResult').value :
            null;

        if (captchaResult == null) {
            Swal.fire('Error', 'Falta captcha', 'error');
            return;
        }
        if (parseInt(captchaResult) !== (captchaX + captchaY)) {
            Swal.fire('Captcha Incorrecto', 'Resuelve la suma correctamente.', 'error');
            generateCaptcha();
            return;
        }

        try {
            const response = await fetch('http://localhost:3000/api/register', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ name, lastName, phone, email, password }),
            });
            const data = await response.json();
            if (data.success) {
                Swal.fire('Registro Exitoso', data.message || 'Te has registrado correctamente', 'success')
                    .then(() => {
                        window.location.href = 'login.html';
                    });
            } else {
                Swal.fire('Error', data.error || 'No se pudo registrar', 'error');
                generateCaptcha();
            }
        } catch (error) {
            console.error(error);
            Swal.fire('Error de Conexión', 'No se pudo conectar al servidor', 'error');
            generateCaptcha();
        }
    });
}

// ============================
// 3. Manejo del formulario de login
// ============================
const loginForm = document.getElementById('loginForm');
if (loginForm) {
    loginForm.addEventListener('submit', async(e) => {
        e.preventDefault();
        const emailOrPhone = document.getElementById('loginEmailOrPhone').value.trim();
        const password = document.getElementById('loginPassword').value.trim();

        try {
            const response = await fetch('http://localhost:3000/api/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ emailOrPhone, password }),
            });
            const data = await response.json();
            if (data.success && data.token) {
                localStorage.setItem('token', data.token);
                Swal.fire('Login Exitoso', 'Bienvenido', 'success')
                    .then(() => {
                        window.location.href = 'home.html';
                    });
            } else {
                Swal.fire('Error', data.error || 'Error al iniciar sesión', 'error');
            }
        } catch (error) {
            console.error(error);
            Swal.fire('Error de Conexión', 'No se pudo conectar al servidor', 'error');
        }
    });
}

// ============================
// 4. Manejo de home.html
// ============================
if (window.location.pathname.endsWith('home.html')) {
    const token = localStorage.getItem('token');
    if (!token) {
        Swal.fire('No Autorizado', 'No hay token, inicia sesión', 'error')
            .then(() => {
                window.location.href = 'login.html';
            });
    } else {
        fetch('http://localhost:3000/api/protegido', {
                method: 'GET',
                headers: { Authorization: `Bearer ${token}` },
            })
            .then(res => res.json())
            .then(data => {
                if (data.success) {
                    const userInfo = document.getElementById('userInfo');
                    userInfo.textContent = `UserID: ${data.userId} | ${data.message}`;
                    // Inicializar el mapa
                    initLeafletMap();
                } else {
                    Swal.fire('No Autorizado', data.error || 'Token inválido', 'error')
                        .then(() => {
                            window.location.href = 'login.html';
                        });
                }
            })
            .catch(err => {
                console.error(err);
                Swal.fire('Error de Conexión', 'No se pudo conectar al servidor', 'error')
                    .then(() => {
                        window.location.href = 'login.html';
                    });
            });
    }

    // Botón Cerrar Sesión
    const logoutBtn = document.getElementById('logoutBtn');
    if (logoutBtn) {
        logoutBtn.addEventListener('click', () => {
            localStorage.removeItem('token');
            Swal.fire('Sesión Cerrada', 'Tu sesión ha sido cerrada', 'info')
                .then(() => {
                    window.location.href = 'login.html';
                });
        });
    }

    // Botón Solicitar Código
    const requestCodeBtn = document.getElementById('requestCodeBtn');
    if (requestCodeBtn) {
        requestCodeBtn.addEventListener('click', () => {
            Swal.fire({
                title: 'Código de Acceso al Chat',
                text: 'Este código lo compartes con el admin para que te agregue al chat de WhatsApp.',
                icon: 'info',
                input: 'text',
                inputLabel: 'Ingresa un nombre o clave única',
                showCancelButton: true,
                confirmButtonText: 'Generar',
            }).then(result => {
                if (result.isConfirmed && result.value) {
                    const code = Math.floor(100000 + Math.random() * 900000).toString();
                    Swal.fire('Tu Código', `Hola ${result.value}, tu código es: ${code}`, 'success');
                }
            });
        });
    }

    // Botones de chat
    const chatButtons = document.querySelectorAll('.chat-btn');
    chatButtons.forEach(btn => {
        btn.addEventListener('click', () => {
            if (!localStorage.getItem('token')) {
                Swal.fire('No Autorizado', 'Debes iniciar sesión para acceder al chat', 'error');
                return;
            }
            const ruta = btn.getAttribute('data-ruta');
            if (ruta === '50') {
                window.open('https://chat.whatsapp.com/GuweIldJnIM8Fzg1nLTiJD', '_blank');
            } else if (ruta === '25') {
                window.open('https://chat.whatsapp.com/GRUPO_RUTA_25', '_blank');
            }
        });
    });
}

// ============================
// 5. Función para inicializar Leaflet y mostrar rutas
// ============================
function initLeafletMap() {
    const mapDiv = document.getElementById('map');
    if (!mapDiv) return;

    // Crear mapa centrado en Aguascalientes
    const map = L.map('map').setView([21.8833, -102.291], 12);

    // Cargar tiles de OpenStreetMap
    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
        maxZoom: 19,
    }).addTo(map);

    // -------------------------------
    // Especificaciones de la RUTA-50
    // -------------------------------
    const ruta50 = {
        nombre: "RUTA-50",
        color: "#F7C500", // Amarillo
        horarios: ["06:00 AM", "10:00 PM"],
        coordenadas: [
            [21.951934, -102.350864], //Punto final
            [21.951939, -102.348398],
            [21.952502, -102.345700], //Parada 58
            [21.953079, -102.343294],
            [21.953312, -102.340476], //Parada 57
            [21.953320, -102.339815],
            [21.953491, -102.339597], //Parada 56
            [21.953832, -102.338831],
            [21.954025, -102.338662], //Parada 55
            [21.954080, -102.338500],
            [21.954200, -102.338406], //Parada 54
            [21.954008, -102.338202],
            [21.953866, -102.338004], //Parada 53
            [21.953089, -102.336918], //Parada 52
            [21.952725, -102.335103], //Parada 51
            [21.952338, -102.332933], //Parada 50
            [21.951625, -102.329233], //Parada 49
            [21.951233, -102.327266], //Parada 48
            [21.949713, -102.318471], //Parada 47
            [21.946838, -102.302427], //Parada 46
            [21.945528, -102.295107], //Parada 45
            [21.943592, -102.285996], //Parada 44
            [21.941796, -102.279026], //Parada 43
            [21.928481, -102.267523], //Parada 42
            [21.925361, -102.263728], //Parada 41
            [21.922318, -102.261967], //Parada 40
            [21.919945, -102.261532], //Parada 39
            [21.917749, -102.261864], //Parada 38
            [21.915837, -102.261373], //Parada 37
            [21.909886, -102.259316], //Parada 36
            [21.907347, -102.257087], //Parada 35
            [21.901562, -102.254263], //Parada 34
            [21.898638, -102.253344], //Parada 33
            [21.896178, -102.253171], //Parada 32
            [21.893015, -102.253492], //Parada 31
            [21.891226, -102.252882], //Parada 30
            [21.882334, -102.249205], //Parada 29
            [21.873864, -102.245932], //Parada 28
            [21.869145, -102.244034], //Parada 27
            [21.868249, -102.244184], //Parada 26
            [21.866306, -102.245057], //Parada 25
            [21.865517, -102.246241], //Parada 24
            [21.862127, -102.248274], //Parada 23
            [21.857992, -102.250472], //Parada 22
            [21.856419, -102.252112], //Parada 21
            [21.855596, -102.254464], //Parada 20
            [21.853567, -102.262889], //Parada 19
            [21.851577, -102.270793], //Parada 18
            [21.851171, -102.271662], //Parada 17
            [21.848281, -102.275035], //Parada 16
            [21.846444, -102.280677], //Parada 15
            [21.845106, -102.289231], //Parada 14
            [21.844624, -102.291205], //Parada 13
            [21.844774, -102.298101], //Parada 12
            [21.845595, -102.305045], //Parada 11
            [21.845478, -102.306665], //Parada 10
            [21.843804, -102.312733], //Parada 9
            [21.842411, -102.317929], //Parada 8
            [21.843291, -102.323758], //Parada 7
            [21.843710, -102.327008], //Parada 6
            [21.844318, -102.328651], //Parada 5
            [21.850232, -102.347401], //Parada 4
            [21.850558, -102.349211], //Parada 3
            [21.851719, -102.352429], //Parada 2
            [21.841340, -102.354386] //Parada 1
        ]
    };

    // -------------------------------
    // Ruta 25 (Ejemplo)
    // -------------------------------
    const ruta25 = {
        nombre: "RUTA-25",
        color: "#00B2A9", // Turquesa
        horarios: ["06:00 AM", "10:00 PM"],
        coordenadas: [
            [21.8850, -102.2900],
            [21.8870, -102.2880],
            [21.8890, -102.2870],
            [21.8910, -102.2860],
            [21.8930, -102.2850],
            [21.8950, -102.2840],
            [21.8970, -102.2830],
            [21.8990, -102.2820]
        ]
    };

    // Dibujar Ruta 50
    const poly50 = L.polyline(ruta50.coordenadas, { color: ruta50.color, weight: 5 }).addTo(map);
    poly50.bindPopup(`
    <strong>${ruta50.nombre}</strong><br>
    Horarios: ${ruta50.horarios[0]} - ${ruta50.horarios[1]}
  `);
    // Al hacer clic en la polilínea, se muestra el popup
    poly50.on('click', (e) => {
        poly50.openPopup(e.latlng);
    });

    // Dibujar Ruta 25
    const poly25 = L.polyline(ruta25.coordenadas, { color: ruta25.color, weight: 5 }).addTo(map);
    poly25.bindPopup(`
    <strong>${ruta25.nombre}</strong><br>
    Horarios: ${ruta25.horarios[0]} - ${ruta25.horarios[1]}
  `);
    // Al hacer clic en la polilínea, se muestra el popup
    poly25.on('click', (e) => {
        poly25.openPopup(e.latlng);
    });

    // Geolocalización
    if ('geolocation' in navigator) {
        navigator.geolocation.getCurrentPosition(
            (position) => {
                const userLat = position.coords.latitude;
                const userLng = position.coords.longitude;
                const userMarker = L.marker([userLat, userLng]).addTo(map);
                userMarker.bindPopup('Estás aquí').openPopup();
                map.setView([userLat, userLng], 14);
            },
            (error) => {
                console.error('Geolocalización falló:', error);
            }
        );
    }

    // Agregar una pequeña leyenda en la esquina superior derecha
    const info = L.control({ position: 'topright' });
    info.onAdd = function() {
        this._div = L.DomUtil.create('div', 'info legend');
        // Aquí detallamos las rutas con color y horarios
        this._div.innerHTML = `
      <h5 class="mb-1">Rutas Disponibles</h5>
      <div style="margin-bottom:5px;">
        <span style="background:${ruta50.color}; width:20px; height:5px; display:inline-block; margin-right:6px;"></span>
        <strong>${ruta50.nombre}</strong> 
        <br>Horarios: ${ruta50.horarios[0]} - ${ruta50.horarios[1]}
      </div>
      <div>
        <span style="background:${ruta25.color}; width:20px; height:5px; display:inline-block; margin-right:6px;"></span>
        <strong>${ruta25.nombre}</strong> 
        <br>Horarios: ${ruta25.horarios[0]} - ${ruta25.horarios[1]}
      </div>
    `;
        return this._div;
    };
    info.addTo(map);
}