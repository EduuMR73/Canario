# Secretos de Canario

Este directorio contiene los secretos que usan los servicios de Docker Compose (contraseñas, claves y la configuración de ACL de Redis). Cada secreto vive en su propio fichero y Compose lo monta como secreto de fichero en `/run/secrets/`.

**Git ignora todo el contenido de este directorio salvo este `README.md` y `.gitkeep`.** Ningún secreto debe llegar nunca al repositorio.

## Ficheros

| Fichero | Para qué sirve | Qué servicio lo usa |
| ------- | -------------- | ------------------- |
| `contrasena_redis.txt` | Contraseña del usuario `aplicacion` de Redis | La API y el healthcheck de Redis |
| `redis_acl.conf` | ACL de Redis, derivada de `contrasena_redis.txt` (guarda su hash, no la contraseña) | Servicio `redis` |
| `contrasena_postgres_superusuario.txt` | Contraseña del superusuario de PostgreSQL | Solo la inicialización de PostgreSQL |
| `contrasena_migrador.txt` | Contraseña del rol de base de datos `migrador` | Migraciones |
| `contrasena_aplicacion.txt` | Contraseña del rol de base de datos `aplicacion` | La API |
| `contrasena_plataforma.txt` | Contraseña del rol de base de datos `plataforma` | Alta de empresas |
| `clave_hmac_codigos.txt` | Clave del HMAC de los códigos de seguimiento | La API |
| `clave_maestra.txt` | Clave maestra para el cifrado de las claves de empresa | La API |
| `clave_firma_tokens.txt` | Clave de la firma (HMAC-SHA256) de los JWT de acceso del personal | La API |
| `clave_hmac_identidades.txt` | Clave del HMAC del identificador de una cuenta externa (Google o GitHub) vinculada, lo único que se guarda de él. Separada de `clave_hmac_codigos.txt`: rotar una no toca la otra | La API |
| `clave_flujo_externo.txt` | Clave AES-256-GCM de las cookies del login externo (la del flujo hacia el proveedor y la del ticket de vuelta) | La API |
| `google_client_id.txt` | Client ID de Google Cloud para el login con Google | Servicio `broker` |
| `google_client_secret.txt` | Client secret de Google Cloud para el login con Google | Servicio `broker` |

Las cinco contraseñas y las cinco claves contienen un único valor de 64 caracteres, sin salto de línea final. Las contraseñas usan el alfabeto `A-Za-z0-9_-` (48 bytes aleatorios en base64 URL-safe) y las claves son 32 bytes aleatorios en hexadecimal minúscula.

Los dos ficheros de Google no son aleatorios. El script los crea con un marcador (`sin-configurar:client-id` y `sin-configurar:client-secret`) y el login con Google queda desactivado hasta que quien opera ponga en ellos los valores de Google Cloud: ASCII imprimible, sin espacios ni salto de línea final, hasta 255 caracteres. El broker no arranca si solo uno de los dos está puesto.

## Cómo generarlos y comprobarlos

Desde la raíz del repositorio.

PowerShell (Windows):

```powershell
python scripts\generar_secretos.py              # crea lo que falte y después comprueba
python scripts\generar_secretos.py --comprobar  # solo comprueba, no crea nada
```

Linux:

```bash
python3 scripts/generar_secretos.py              # crea lo que falte y después comprueba
python3 scripts/generar_secretos.py --comprobar  # solo comprueba, no crea nada
```

**El script nunca sobrescribe.** Si un fichero ya existe, lo deja como está y lo indica. No existe ninguna opción para forzar el reemplazo, a propósito: una clave maestra regenerada dejaría ilegibles los datos ya cifrados.

Antes de crear nada, el script comprueba con Git que este directorio está ignorado y se niega a continuar si no lo está. La comprobación devuelve código de salida 0 solo si todo es correcto: ficheros presentes, formato exacto, valores distintos entre sí, hash del ACL coherente con la contraseña de Redis y, en Linux, permisos exactos.

## Por qué `redis_acl.conf` guarda un SHA-256 sin sal

Redis solo admite en sus ACL hashes SHA-256 **sin sal** (`#hash`). Esto es seguro aquí porque la contraseña es aleatoria y larga (unos 384 bits de entropía): no hay diccionario ni tabla precalculada que atacar, y la sal solo protege a las contraseñas que elige una persona. **No se debe "arreglar" añadiendo una sal**: Redis dejaría de reconocer la contraseña.

La contraseña en claro nunca aparece en `redis_acl.conf`.

## Avisos importantes

- **Copia segura de `clave_maestra.txt`, `clave_hmac_codigos.txt` y `clave_hmac_identidades.txt`.** Guarda una copia aparte en un gestor de contraseñas. Perder o regenerar la clave maestra deja ilegibles los datos cifrados, perder o regenerar la clave HMAC de los códigos invalida los códigos de seguimiento existentes, y perder o regenerar la de las identidades rompe todos los vínculos con cuentas externas. Regenerar `clave_firma_tokens.txt` o `clave_flujo_externo.txt` no pierde datos: solo invalida los JWT de acceso ya emitidos y los logins externos en curso.
- **No pegues nunca el contenido de estos ficheros** en chats, issues ni commits. Si ocurre, regenera todos los secretos antes de usar el sistema: borra los ficheros y vuelve a ejecutar el script.
- **No guardes el proyecto en carpetas sincronizadas con la nube** (OneDrive, Dropbox, Google Drive). Las claves saldrían de la máquina sin que Git intervenga.
- **No crees nunca un `__init__.py` dentro de `secrets/`.** El nombre coincide con el módulo estándar `secrets` de Python y podría ocultarlo.

## Permisos en Linux

En Linux los ficheros se montan en los contenedores con los permisos que tienen en el host: Compose no aplica `uid`, `gid` ni `mode` a los secretos de fichero. Por eso el script fija explícitamente `0700` en el directorio (protege frente a otros usuarios del host) y `0644` en los ficheros (los contenedores sin privilegios los leen por el bind mount). Esto se verificará en el despliegue.

En Windows no se aplican modos.

## Rotación de claves

La rotación de claves queda para un procedimiento propio posterior. Hasta entonces, no se regeneran secretos en un sistema que ya tenga datos.
