# WebAuthn API Documentation

Esta documentación describe la API de WebAuthn para la integración con el frontend usando SimpleWebAuthn.

## Configuración Base

### URL Base
```
http://localhost:3030/webauthn
```
> **Nota**: El puerto por defecto es 3030 según la configuración actual. Ajusta según tu configuración específica.

### Headers Requeridos
```
Content-Type: application/json
```

### Autenticación
Para endpoints protegidos, incluir el token JWT:
```
Authorization: Bearer <jwt_token>
```

## Endpoints

### 1. Iniciar Registro de Credencial

**POST** `/webauthn/register/begin`

Inicia el proceso de registro de una nueva credencial WebAuthn para un usuario.

#### Request Body
```json
{
  "userId": 1,
  "deviceName": "Mi iPhone" // opcional
}
```

#### Response (200 OK)
```json
{
  "options": {
    "rp": {
      "name": "EasyRoom",
      "id": "6000-firebase-studio-1753876320293.cluster-kc2r6y3mtba5mswcmol45orivs.cloudworkstations.dev"
    },
    "user": {
      "id": "base64url-encoded-user-handle",
      "name": "user@example.com",
      "displayName": "Usuario"
    },
    "challenge": "base64url-encoded-challenge",
    "pubKeyCredParams": [
      {
        "type": "public-key",
        "alg": -7
      },
      {
        "type": "public-key", 
        "alg": -257
      }
    ],
    "timeout": 60000,
    "excludeCredentials": [
      {
        "id": "existing-credential-id",
        "type": "public-key",
        "transports": ["usb", "nfc"]
      }
    ],
    "authenticatorSelection": {
      "residentKey": "preferred",
      "userVerification": "preferred"
    },
    "attestation": "none"
  }
}
```

#### Errores
- `404 Not Found`: Usuario no encontrado
- `500 Internal Server Error`: Error interno del servidor

---

### 2. Finalizar Registro de Credencial

**POST** `/webauthn/register/finish`

Completa el proceso de registro verificando la respuesta del autenticador.

#### Request Body
```json
{
  "userId": 1,
  "response": {
    "id": "credential-id",
    "rawId": "credential-raw-id",
    "type": "public-key",
    "response": {
      "clientDataJSON": "base64url-encoded-client-data",
      "attestationObject": "base64url-encoded-attestation-object",
      "transports": ["usb", "nfc"]
    },
    "clientExtensionResults": {}
  },
  "deviceName": "Mi iPhone" // opcional
}
```

#### Response (201 Created)
```json
{
  "verified": true,
  "credentialId": "base64url-encoded-credential-id",
  "message": "Registration successful"
}
```

#### Response (400 Bad Request) - Fallo en verificación
```json
{
  "verified": false,
  "message": "Registration verification failed"
}
```

#### Errores
- `400 Bad Request`: Error en la verificación o credencial ya registrada
- `404 Not Found`: Usuario no encontrado
- `500 Internal Server Error`: Error interno del servidor

---

### 3. Iniciar Autenticación

**POST** `/webauthn/authenticate/begin`

Inicia el proceso de autenticación WebAuthn.

#### Request Body
```json
{
  "email": "user@example.com", // opcional - recomendado para mejor UX
  "userHandle": "base64url-encoded-user-handle" // opcional
}
```

#### Response (200 OK)
```json
{
  "options": {
    "challenge": "base64url-encoded-challenge",
    "timeout": 60000,
    "rpId": "6000-firebase-studio-1753876320293.cluster-kc2r6y3mtba5mswcmol45orivs.cloudworkstations.dev",
    "allowCredentials": [
      {
        "id": "credential-id",
        "type": "public-key",
        "transports": ["usb", "nfc"]
      }
    ],
    "userVerification": "preferred"
  }
}
```

#### Errores
- `500 Internal Server Error`: Error interno del servidor

---

### 4. Finalizar Autenticación

**POST** `/webauthn/authenticate/finish`

Completa el proceso de autenticación y devuelve un token JWT si es exitoso.

#### Request Body
```json
{
  "response": {
    "id": "credential-id",
    "rawId": "credential-raw-id", 
    "type": "public-key",
    "response": {
      "clientDataJSON": "base64url-encoded-client-data",
      "authenticatorData": "base64url-encoded-authenticator-data",
      "signature": "base64url-encoded-signature",
      "userHandle": "base64url-encoded-user-handle"
    },
    "clientExtensionResults": {}
  },
  "expectedChallenge": "base64url-encoded-challenge" // opcional
}
```

#### Response (200 OK)
```json
{
  "verified": true,
  "token": "jwt-token",
  "user": {
    "id": 1,
    "email": "user@example.com",
    "nombre_usuario": "Usuario"
  },
  "message": "Authentication successful"
}
```

#### Errores
- `401 Unauthorized`: Fallo en la autenticación
- `500 Internal Server Error`: Error interno del servidor

---

### 5. Obtener Credenciales del Usuario

**GET** `/webauthn/credentials`

Obtiene todas las credenciales WebAuthn registradas para el usuario autenticado.

#### Headers
```
Authorization: Bearer <jwt_token>
```

#### Response (200 OK)
```json
{
  "credentials": [
    {
      "id": 1,
      "credentialID": "base64url-encoded-credential-id",
      "deviceName": "Mi iPhone",
      "credentialDeviceType": "singleDevice",
      "credentialBackedUp": false,
      "createdAt": "2024-01-15T10:30:00.000Z",
      "lastUsed": "2024-01-20T14:45:00.000Z",
      "transports": ["usb", "nfc"]
    }
  ],
  "count": 1
}
```

#### Errores
- `401 Unauthorized`: Token JWT inválido o faltante
- `500 Internal Server Error`: Error interno del servidor

---

### 6. Eliminar Credencial

**DELETE** `/webauthn/credentials/:id`

Elimina una credencial WebAuthn específica del usuario autenticado.

#### Headers
```
Authorization: Bearer <jwt_token>
```

#### Parámetros de URL
- `id`: ID de la credencial (credentialID, no el ID de base de datos)

#### Response (204 No Content)
Sin contenido en el cuerpo de la respuesta.

#### Errores
- `400 Bad Request`: ID de credencial faltante o inválido
- `401 Unauthorized`: Token JWT inválido o faltante
- `404 Not Found`: Credencial no encontrada o no pertenece al usuario
- `500 Internal Server Error`: Error interno del servidor

## Integración con SimpleWebAuthn (Frontend)

### Instalación
```bash
npm install @simplewebauthn/browser
```

### Ejemplo de Registro

```javascript
import { startRegistration } from '@simplewebauthn/browser';

async function registerWebAuthn(userId, deviceName) {
  try {
    // 1. Obtener opciones de registro
    const beginResponse = await fetch('/webauthn/register/begin', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ userId, deviceName })
    });
    
    const { options } = await beginResponse.json();
    
    // 2. Iniciar registro con el navegador
    const attResp = await startRegistration(options);
    
    // 3. Enviar respuesta al servidor
    const finishResponse = await fetch('/webauthn/register/finish', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        userId,
        response: attResp,
        deviceName
      })
    });
    
    const result = await finishResponse.json();
    
    if (result.verified) {
      console.log('Registro exitoso!');
      return result;
    } else {
      throw new Error(result.message || 'Registro fallido');
    }
  } catch (error) {
    console.error('Error en registro WebAuthn:', error);
    throw error;
  }
}
```

### Ejemplo de Autenticación

```javascript
import { startAuthentication } from '@simplewebauthn/browser';

async function authenticateWebAuthn(email) {
  try {
    // 1. Obtener opciones de autenticación
    const beginResponse = await fetch('/webauthn/authenticate/begin', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email }) // recomendado para mejor UX
    });
    
    const { options } = await beginResponse.json();
    
    // 2. Iniciar autenticación con el navegador
    const authResp = await startAuthentication(options);
    
    // 3. Enviar respuesta al servidor
    const finishResponse = await fetch('/webauthn/authenticate/finish', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        response: authResp,
        expectedChallenge: options.challenge // opcional
      })
    });
    
    const result = await finishResponse.json();
    
    if (result.verified) {
      // Guardar token JWT
      localStorage.setItem('authToken', result.token);
      console.log('Autenticación exitosa!', result.user);
      return result;
    } else {
      throw new Error(result.message || 'Autenticación fallida');
    }
  } catch (error) {
    console.error('Error en autenticación WebAuthn:', error);
    throw error;
  }
}
```

### Ejemplo de Gestión de Credenciales

```javascript
// Obtener credenciales del usuario
async function getUserCredentials() {
  const token = localStorage.getItem('authToken');
  
  const response = await fetch('/webauthn/credentials', {
    headers: {
      'Authorization': `Bearer ${token}`
    }
  });
  
  return await response.json();
}

// Eliminar credencial
async function deleteCredential(credentialId) {
  const token = localStorage.getItem('authToken');
  
  const response = await fetch(`/webauthn/credentials/${credentialId}`, {
    method: 'DELETE',
    headers: {
      'Authorization': `Bearer ${token}`
    }
  });
  
  if (response.status === 204) {
    console.log('Credencial eliminada exitosamente');
  }
}
```

## Configuración del Servidor

### Variables de Entorno

```env
# Configuración del Servidor
NODE_ENV=development
PORT=3030

# JWT Configuration  
JWT_SECRET=your_super_secret_jwt_key_at_least_32_characters_long
JWT_EXPIRATION=1h

# WebAuthn Configuration
WEBAUTHN_RP_ID=localhost
WEBAUTHN_RP_NAME=EasyRoom
WEBAUTHN_ORIGIN=https://localhost:3030
ALLOWED_ORIGINS=*
WEBAUTHN_TIMEOUT=60000
WEBAUTHN_REQUIRE_RESIDENT_KEY=false
WEBAUTHN_USER_VERIFICATION=preferred

# Development Configuration (Solo para desarrollo/testing)
WEBAUTHN_DISABLE_COUNTER_CHECK=false

# Database Configuration
DATABASE_PATH=db.sqlite
```

### Configuración para Producción

Para producción, asegúrate de:

1. **Configurar WEBAUTHN_RP_ID** con tu dominio real:
   ```env
   WEBAUTHN_RP_ID=tudominio.com
   ```

2. **Configurar ALLOWED_ORIGINS** con orígenes específicos:
   ```env
   ALLOWED_ORIGINS=https://tudominio.com,https://www.tudominio.com
   ```

3. **Configurar WEBAUTHN_ORIGIN** explícitamente:
   ```env
   WEBAUTHN_ORIGIN=https://tudominio.com
   ```

4. **Deshabilitar counter check** solo en desarrollo:
   ```env
   WEBAUTHN_DISABLE_COUNTER_CHECK=false
   ```

5. **Usar HTTPS** - WebAuthn requiere conexiones seguras en producción.

## Flujo Completo de Integración

### 1. Registro de Usuario (Flujo Completo)
```javascript
// Paso 1: Usuario se registra normalmente (email/password)
const user = await registerUser({ email, password, nombre_usuario });

// Paso 2: Registrar credencial WebAuthn
const webauthnResult = await registerWebAuthn(user.id, 'Mi Dispositivo');

console.log('Usuario registrado con WebAuthn:', {
  userId: user.id,
  credentialId: webauthnResult.credentialId
});
```

### 2. Login de Usuario (Flujo Completo)
```javascript
// Opción A: Login solo con WebAuthn (sin password)
const authResult = await authenticateWebAuthn('user@example.com');

// Opción B: Login híbrido (password + WebAuthn opcional)
const loginResult = await traditionalLogin({ email, password });
if (loginResult.hasWebAuthn) {
  const webauthnResult = await authenticateWebAuthn(email);
  // Usar token de WebAuthn que es más seguro
}
```

### 3. Gestión de Credenciales
```javascript
// Listar credenciales del usuario
const credentials = await getUserCredentials();

// Eliminar credencial específica
await deleteCredential(credentials[0].credentialID);

// Agregar nueva credencial a usuario existente
await registerWebAuthn(userId, 'Nuevo Dispositivo');
```

## Troubleshooting

### Errores Comunes y Soluciones

#### 1. "Unexpected registration response origin"
**Problema**: El origin del frontend no coincide con la configuración del backend.
**Solución**: 
```env
WEBAUTHN_ORIGIN=https://tu-dominio-exacto.com
ALLOWED_ORIGINS=https://tu-dominio-exacto.com
```

#### 2. "Invalid counter value - possible replay attack"
**Problema**: Counter de replay protection en desarrollo.
**Solución**: 
```env
WEBAUTHN_DISABLE_COUNTER_CHECK=true  # Solo para desarrollo
```

#### 3. "allowCredentialsCount: 0"
**Problema**: No se encuentran credenciales para el usuario.
**Solución**: Asegúrate de enviar el `email` en el request de autenticación:
```javascript
body: JSON.stringify({ email: "user@example.com" })
```

#### 4. "User not found"
**Problema**: El usuario no existe en la base de datos.
**Solución**: Verifica que el usuario esté registrado antes de intentar WebAuthn.

## Notas Importantes

1. **Compatibilidad del Navegador**: WebAuthn es compatible con navegadores modernos. Verifica la compatibilidad antes de implementar.

2. **HTTPS Requerido**: En producción, WebAuthn requiere HTTPS. Solo funciona con HTTP en localhost para desarrollo.

3. **Gestión de Errores**: Implementa manejo robusto de errores, especialmente para casos donde el usuario cancela la operación o el autenticador no está disponible.

4. **Fallback de Autenticación**: Considera mantener métodos de autenticación tradicionales como respaldo.

5. **Experiencia de Usuario**: Proporciona instrucciones claras al usuario sobre cómo usar sus autenticadores (Touch ID, Face ID, llaves de seguridad, etc.).

## Códigos de Error Comunes

- **NotAllowedError**: Usuario canceló la operación
- **InvalidStateError**: Autenticador ya está registrado
- **NotSupportedError**: Navegador no soporta WebAuthn
- **SecurityError**: Origen no permitido o conexión insegura
- **UnknownError**: Error general del autenticador

Maneja estos errores apropiadamente en tu frontend para proporcionar una buena experiencia de usuario.