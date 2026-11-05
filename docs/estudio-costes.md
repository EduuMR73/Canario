# Estudio de costes de explotación

Cuánto cuesta mantener Canario en producción en Render, AWS, Microsoft Azure y Google Cloud, comparado con lo que cuesta hoy en el VPS de OVHcloud donde está desplegado. Precios consultados el 5 de noviembre de 2026 en las páginas, calculadoras y API oficiales de cada proveedor.

## 1. Objetivo y alcance

La actividad pide:

> Desplegar la aplicación web de la entrega anterior en render.com. En el repositorio de actividades, incluir la url donde queda publicado.
>
> Realizar un estudio comparativo del coste de explotar la aplicación usando: Render, AWS, MS Azure, Google Cloud.

Con el visto bueno del profesor, Canario no se desplegó en Render sino en un VPS de OVHcloud, donde ya estaba en producción (`docs/operacion.md`). Ese VPS es la quinta columna del estudio: es el único coste real y facturado contra el que comparar los otros cuatro.

"Explotar" se entiende como el coste **recurrente** de tener la aplicación en producción: cómputo, base de datos, caché, almacenamiento, copias, red, registro de imágenes, secretos y logs. No incluye el desarrollo ni el tiempo de administración, que se comenta aparte (sección 8).

Convenciones:

- Precios **sin IVA**. El 21 % se aplica igual a todos, así que no cambia la comparación.
- AWS, Google Cloud y Render publican en USD. Se pasan a EUR con el cambio de referencia del BCE del 5/11/2026: **1 EUR = 1,1224 USD**.
- Mes de 730 horas.
- Región de la UE en todos: España cuando existe (AWS `eu-south-2`, Azure Spain Central, Google `europe-southwest1` Madrid), Frankfurt en Render y Estrasburgo en OVHcloud.
- Lo que no se pudo comprobar en una fuente oficial va marcado como **sin verificar**.

## 2. Qué hay que explotar

Sacado de `docker-compose.yml` y `compose.produccion.yaml`. En producción corren seis servicios:

| Servicio | Qué hace | Límite de memoria |
|---|---|---|
| `caddy` | Proxy inverso; sirve la SPA Angular, que va dentro de la imagen | 128 MB |
| `api` | API REST (FastAPI, Python 3.12) | 256 MB |
| `broker` | Canje del login con Google; único servicio de aplicación con salida a internet para eso | 128 MB |
| `cartero` | Entrega del correo por SMTP a Mailjet (puerto 465) | 128 MB |
| `postgres` | PostgreSQL 18 con RLS forzado y roles propios sin superusuario | 512 MB |
| `redis` | Redis 8 con ACL de varios usuarios | 128 MB |

`gestion` (administración por línea de órdenes) y `mailpit` (correo de desarrollo) no corren en producción.

Comunes a todos los proveedores y fuera de la comparación: el dominio `eduumr.dev` y el plan gratuito de Mailjet.

## 3. Supuestos de carga

Una pyme con un canal de denuncias:

- tráfico de salida de unos 10 GB al mes;
- base de datos de menos de 5 GB (se reservan 20 GB de disco);
- funcionamiento 24/7;
- unos 2 GB de logs al mes y unos 15 secretos.

Con esta carga el tráfico apenas pesa: AWS, Azure y Render incluyen al menos 25 GB de salida al mes, y OVHcloud no cobra el tráfico.

## 4. Variantes y criterio

Para cada proveedor se calculan dos variantes:

- **A, una VM con Docker Compose:** la misma arquitectura que en OVHcloud, con las mismas imágenes, el mismo endurecimiento y las mismas pruebas. Una VM de 2 vCPU y 4 GB, 40 GB de disco, IP pública, copias del disco y salida a internet.
- **B, servicios gestionados:** contenedores gestionados para `caddy`, `api`, `broker` y `cartero`, PostgreSQL gestionado y Redis (o compatible) gestionado, más lo que una explotación profesional necesita: registro de imágenes, almacén de secretos, entrada con TLS, salida a internet, logs y copias de 7 días. Render solo tiene esta variante, porque no admite Docker Compose.

Criterio de la variante B, el mismo para todos los proveedores:

1. Cada componente en el **nivel más pequeño que el proveedor documenta como apto para producción y con SLA**. Lo que el proveedor marca como solo para desarrollo o pruebas queda fuera.
2. Los mismos recursos por servicio en todos los proveedores: `caddy`, `broker` y `cartero` con 0,25 vCPU y 0,5 GB; `api` con 0,5 vCPU y 1 GB; PostgreSQL con al menos 1 vCPU, 2 GB y 20 GB; Redis con al menos 0,5 GB. Si un proveedor no ofrece la combinación, se usa la siguiente válida hacia arriba.
3. Las capas gratuitas no entran en el total, porque son temporales o pueden cambiar.

En Google Cloud y en Azure, una base de datos o un Redis **sin alta disponibilidad no tiene SLA**:

- Cloud SQL: "single-zone Instances … are excluded" ([SLA de Cloud SQL](https://cloud.google.com/sql/sla)).
- Memorystore: "If the instance is configured without high availability (0 replicas), then the SLA does not apply".
- Azure Managed Redis: "doesn't have access to the availability SLA. Don't run in non-HA mode outside of development and test scenarios" ([arquitectura de Azure Managed Redis](https://learn.microsoft.com/en-us/azure/redis/architecture)).

En esos casos la alta disponibilidad es el **mínimo profesional** y entra en el total. La tabla de la sección 6 muestra también el coste sin ella, por transparencia.

## 5. Variante A: una VM con Docker Compose

| Proveedor | Máquina | EUR/mes | Con compromiso de 1 año | Veces OVHcloud |
|---|---|---|---|---|
| **OVHcloud** | VPS-1: 2 vCores, 4 GB, 40 GB NVMe | **3,81** (4,16 con backup) | ya es el de 12 meses | 1 |
| AWS | EC2 t4g.medium, EBS gp3 40 GB, IPv4, snapshots | 32,10 | 23,26 | 8,4 (6,1) |
| Google Cloud | e2-medium, disco balanceado 40 GB, IPv4, snapshots | 36,31 | 26,79 | 9,5 (7,0) |
| Azure | B2als v2, disco P6, IP Standard, Azure Backup | 55,00 | 41,88 | 14,4 (11,0) |

Detalle:

- **OVHcloud.** La factura real (28/07/2026) es de 45,72 EUR al año por el VPS y coincide con el precio de lista con compromiso de 12 meses del catálogo oficial. Sin compromiso son 4,49 EUR al mes. El backup automatizado Standard cuesta 0,35 EUR al mes y el primer año viene regalado. El tráfico es ilimitado.
- **AWS** (`eu-south-2`). t4g.medium a 0,0368 USD/h (26,86 USD), gp3 a 0,088 USD/GB (3,52), IPv4 pública a 0,005 USD/h (3,65) y snapshots de hasta 2,00 USD. Los 10 GB de salida entran en los 100 GB gratuitos permanentes. Total: 36,03 USD. Con instancia reservada de 1 año sin pago adelantado: 26,11 USD.
- **Google Cloud** (Madrid). e2-medium a 0,039538 USD/h (28,86 USD), disco de 40 GiB (4,80), IPv4 (3,65), snapshots (2,36) y salida Premium (1,08). Total: 40,75 USD; con CUD de 1 año, 30,07 USD. La e2-medium es de núcleo compartido: sostiene 2 vCPU al 50 %. E2 no tiene descuento por uso continuado.
- **Azure** (Spain Central). B2als v2 a 0,0439 EUR/h (32,05), disco Premium P6 de 64 GiB (10,08; el P4 de 32 GiB no llega a 40), IP Standard (3,29) y Azure Backup (8,98 más 0,60 de bóveda). La B2als v2 tiene una base de CPU del 30 %. La IP Basic se retiró el 30/09/2025.

Las tres VM equivalentes son de rendimiento con ráfagas, como la de OVHcloud. La diferencia de precio no se debe a que estén mejor dimensionadas.

## 6. Variante B: servicios gestionados

### Totales

| Proveedor | Sin alta disponibilidad | **Mínimo con SLA** | Veces OVHcloud | SLA de la base de datos |
|---|---|---|---|---|
| Render | 122,06 | **no hay SLA** fuera de Enterprise | 32,0 | no |
| AWS | 143,07 | **143,07** | 37,6 | 99,5 % (Single-AZ) |
| Google Cloud | 221,01 (sin SLA en la base de datos ni en Valkey) | **300,93** | 79,0 | 99,95 % (con HA) |
| Azure | 296,00 (Redis sin SLA) | **308,45** | 81,0 | 99,9 % (sin HA) |

En EUR al mes, sin IVA. "Veces OVHcloud" se calcula sobre la columna del mínimo con SLA, y en Render sobre la de sin alta disponibilidad.

### Render (Frankfurt): 137,00 USD, 122,06 EUR

| Concepto | USD/mes |
|---|---|
| Workspace Pro ("For teams deploying production-grade apps") | 25,00 |
| `caddy`, `broker` y `cartero`: 3 × `0.5c-512mb` | 21,00 |
| `api`: `1c-2g`, porque 1 GB no cabe en 512 MB y no hay plan intermedio | 25,00 |
| Postgres `1c-2g` | 40,00 |
| Disco de Postgres, 20 GB a 0,30 USD/GB | 6,00 |
| Key Value de 1 GB (no hay plan de 0,5 GB) | 20,00 |
| TLS, secretos, 25 GB de salida, logs de 14 días y PITR de 7 días | incluidos |

- El SLA contractual solo existe en Enterprise, con precio a consultar: "Contractual uptime SLAs" ([precios de Render](https://render.com/pricing)).
- Con alta disponibilidad (Postgres en espera y una segunda instancia de cada servicio): unos 229 USD, 204,03 EUR.

### AWS (`eu-south-2`): 160,58 USD, 143,07 EUR

| Concepto | USD/mes |
|---|---|
| Fargate ARM: 1,25 vCPU y 2,5 GB en total, en subred privada | 41,44 |
| RDS PostgreSQL db.t4g.small Single-AZ (2 vCPU, 2 GiB) y 20 GB gp3 | 28,09 |
| ElastiCache cache.t4g.micro (0,5 GiB) | 12,41 |
| ALB: hora, 1 LCU y 2 IPv4 (exige dos zonas) | 31,54 |
| NAT Gateway: hora, IPv4 y 20 GB procesados | 39,65 |
| ECR, Secrets Manager (15 secretos) y CloudWatch Logs | 7,45 |

- Las tareas van en subred privada, sin IP pública. Por eso hace falta el NAT Gateway para que `broker` y `cartero` salgan a internet, y **cuesta más que la base de datos**.
- La documentación de RDS no excluye las clases T de producción; solo desaconseja las antiguas db.t2 ([tipos de instancia de RDS](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Concepts.DBInstanceClass.Types.html)). Por eso db.t4g.small cumple el criterio.
- Con alta disponibilidad (RDS Multi-AZ y réplica de ElastiCache): 201,08 USD, 179,15 EUR.

### Google Cloud (Madrid): 337,77 USD, 300,93 EUR

| Concepto | USD/mes |
|---|---|
| Cloud Run: `broker` y `cartero` con 1 vCPU y facturación por instancia; `caddy` y `api` con 1 vCPU, facturación por petición y una instancia mínima | 134,96 |
| Cloud SQL Enterprise con HA: 1 vCPU, 3,75 GiB y 20 GB SSD, más copias | 128,41 |
| Memorystore for Valkey, `custom-pico` con una réplica | 53,00 |
| Balanceador externo global, certificado y salida | 19,15 |
| Artifact Registry, Secret Manager y Cloud Logging | 2,25 |

- Cloud Run con menos de 1 vCPU obliga a concurrencia 1 y a facturación por petición. Eso no sirve para la API ni para servicios que trabajan fuera de las peticiones, como el hilo de reparto de `cartero`.
- El mínimo de Cloud SQL Enterprise es 1 vCPU y 3,75 GB. Las instancias compartidas "aren't included in the Cloud SQL SLA. Don't use them for production instances".
- El mapeo de dominio de Cloud Run está en vista previa y no existe en Madrid, así que hace falta el balanceador.
- La actividad de `caddy` y la `api` se supone del 10 % del mes. Con facturación por instancia, el total sube a unos 405 USD.

### Azure (Spain Central): 308,45 EUR

| Concepto | EUR/mes |
|---|---|
| Container Apps, siempre activo: 1,25 vCPU y 2,75 GiB | 130,74 |
| PostgreSQL Flexible, General Purpose D2ds_v5 (2 vCore, 8 GiB), 32 GiB, copias de 7 días | 142,86 |
| Azure Managed Redis B0 con HA (sin verificar si la tarifa es por nodo) | 24,90 |
| Container Registry Basic, Key Vault y Log Analytics | 9,95 |

- El nivel Burstable queda descartado por la propia Microsoft: "Not recommended for production workloads" ([cómputo de PostgreSQL Flexible](https://learn.microsoft.com/en-us/azure/postgresql/compute-storage/concepts-compute)). General Purpose no tiene 1 vCore, así que el mínimo son 2 vCore y 8 GiB.
- Container Apps se calcula siempre activo porque `broker` y `cartero` superan el umbral de inactividad de Azure.
- Con alta disponibilidad también en PostgreSQL: unos 451 EUR (sin verificar que el nodo en espera cueste exactamente lo mismo).

## 7. Compatibilidad: lo que el precio no dice

La variante A ejecuta Canario tal cual. La variante B **no**, en ningún proveedor:

| Pieza | Render | AWS | Google Cloud | Azure |
|---|---|---|---|---|
| PostgreSQL 18 | sí | sí (18.6) | sí (18.6) | sí (18.6) |
| Roles sin superusuario y RLS | sin verificar | el usuario maestro tiene `CREATEROLE` | `cloudsqlsuperuser` con `CREATEROLE` | el administrador tiene `CREATEROLE` |
| Redis 8 | no: Valkey 8 | no: Valkey o Redis OSS 7.x | no: Valkey | no: Redis 7.4 |
| ACL con varios usuarios y contraseña | sin verificar (solo documenta `default`) | sin verificar | políticas ACL con IAM o Basic Auth | sin verificar (clave o Entra ID) |
| `caddy` | se queda, pero sin TLS | detrás del ALB | sobra con el balanceador | sobra con el ingreso de Container Apps |
| `read_only`, `cap_drop` y `no-new-privileges` | sin verificar | sin verificar | sin verificar | sin verificar |

- **PostgreSQL encaja.** Todos los roles de Canario se crean `NOSUPERUSER … NOBYPASSRLS` (`db/init/01_roles.sh:43-60`), así que el diseño no necesita superusuario. Lo que hay que probar en cada proveedor son los `REVOKE` sobre las bases `postgres` y `template1` (líneas 64-66).
- **Redis no encaja.** Canario comprueba al arrancar que el usuario `default` no responde sin autenticar (`app/limitador.py`). Pasar a Valkey o a Redis 7.x con otro modelo de usuarios obliga a cambiar código y pruebas.
- **El endurecimiento no está garantizado.** No consta que se pueda aplicar en la variante B lo que hoy aplica `docker-compose.yml` (redes internas, sistema de ficheros de solo lectura, sin capacidades, usuario no root). En Render, además, los secretos se guardan en texto plano en la plataforma.

Migrar a la variante B no es solo pagar más: es **rehacer y volver a probar** parte de lo que ya está probado.

## 8. Criterio más allá del precio

- **Datos personales y Ley 2/2023.** Canario trata denuncias con datos personales y del informante. Todos los proveedores ofrecen región en la UE, pero AWS, Microsoft, Google y Render son empresas de EE. UU.; OVHcloud es europea. Para un canal de denuncias, que la empresa que custodia los datos esté sujeta solo al derecho de la UE es una ventaja que el precio no recoge (RGPD, capítulo V, sobre transferencias internacionales).
- **Disponibilidad.** La VM de OVHcloud no tiene alta disponibilidad, y su SLA no está verificado para este estudio. Las variantes B con SLA dan entre el 99,5 % y el 99,95 % en la base de datos. Render no da ninguno en el plan Pro.
- **Administración.** En la variante A (también en OVHcloud), el sistema operativo, Docker, los parches y las copias son responsabilidad propia. Canario ya lo tiene resuelto: imágenes fijadas por digest, escaneos, vigilancia y despliegue documentado (`docs/operacion.md`). La variante B quita parte de ese trabajo, pero añade el de la migración (sección 7).
- **Copias.** El backup automático de OVHcloud está en el mismo proveedor y guarda una sola copia, así que no sustituye a una copia externa y cifrada de la base de datos. Ese plan está pendiente y se puede hacer sin coste dentro de la capa gratuita de Backblaze B2, que no se suma aquí.

## 9. Conclusión

1. **Para Canario hoy, el VPS de OVHcloud es la opción racional.** Con su configuración actual cuesta **3,81 EUR al mes**. Una VM equivalente en AWS, Google Cloud o Azure cuesta entre **6 y 14 veces más**, y los servicios gestionados con SLA, entre **38 y 81 veces más**.
2. **Es la única opción que ejecuta exactamente lo que se probó**: el mismo Compose, el mismo endurecimiento y las mismas baterías. Además, es un proveedor europeo con centro de datos en la UE.
3. **Si el negocio exigiera alta disponibilidad con SLA**, la opción más barata sería **AWS (143,07 EUR al mes)**. Antes habría que migrar Redis a Valkey o a Redis 7.x, revisar el modelo de usuarios y volver a pasar las pruebas.
4. **Render es el gestionado más barato (122,06 EUR), pero no tiene SLA** fuera de Enterprise. Para un canal de denuncias de la Ley 2/2023 eso pesa más que el ahorro.
5. **Los riesgos de quedarse en OVHcloud**, que deben quedar cubiertos:
   - una sola máquina, sin alta disponibilidad;
   - la renovación del VPS es manual y vence el 28/07/2027;
   - las copias externas de la base de datos todavía están pendientes.

## 10. Fuentes

Consultadas el 5/11/2026.

- **Cambio:** [BCE, tipos de referencia del euro](https://www.ecb.europa.eu/stats/eurofxref/eurofxref-daily.xml).
- **OVHcloud:**
  - [VPS](https://www.ovhcloud.com/es-es/vps/)
  - [catálogo de la API](https://eu.api.ovh.com/v1/order/catalog/public/vps?ovhSubsidiary=ES)
  - factura del 28/07/2026
- **Render:**
  - [precios](https://render.com/pricing)
  - [planes de cómputo](https://render.com/docs/compute-plans)
  - [plan gratuito](https://render.com/docs/free)
  - [Key Value](https://render.com/docs/key-value)
  - [copias de Postgres](https://render.com/docs/postgresql-backups)
  - [alta disponibilidad de Postgres](https://render.com/docs/postgresql-high-availability)
- **AWS:**
  - [Price List API](https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/index.json) (EC2, VPC, ECS, RDS, ElastiCache, ELB, ECR, Secrets Manager, CloudWatch)
  - [SLA de RDS](https://aws.amazon.com/rds/sla/)
  - [SLA de ECS](https://aws.amazon.com/ecs/sla/)
  - [SLA de ElastiCache](https://aws.amazon.com/elasticache/sla/)
  - [versiones de RDS PostgreSQL](https://docs.aws.amazon.com/AmazonRDS/latest/PostgreSQLReleaseNotes/postgresql-versions.html)
- **Azure:**
  - [API de precios](https://prices.azure.com/api/retail/prices)
  - [SLA de los servicios en línea](https://www.microsoft.com/licensing/docs/view/Service-Level-Agreements-SLA-for-Online-Services)
  - [versiones de PostgreSQL](https://learn.microsoft.com/en-us/azure/postgresql/configure-maintain/concepts-supported-versions)
  - [serie Basv2](https://learn.microsoft.com/en-us/azure/virtual-machines/sizes/general-purpose/basv2-series)
  - [IP públicas](https://learn.microsoft.com/en-us/azure/virtual-network/ip-services/public-ip-addresses)
- **Google Cloud:**
  - [precios de Compute Engine](https://cloud.google.com/products/compute/pricing/general-purpose)
  - [precios de Cloud Run](https://cloud.google.com/run/pricing)
  - [precios de Cloud SQL](https://cloud.google.com/sql/pricing)
  - [precios de Memorystore for Valkey](https://cloud.google.com/memorystore/docs/valkey/pricing)
  - [precios de red](https://cloud.google.com/vpc/network-pricing)
  - [SLA de Cloud SQL](https://cloud.google.com/sql/sla)
  - [SLA de Memorystore](https://cloud.google.com/memorystore/sla)
  - [SLA de Cloud Run](https://cloud.google.com/run/sla)
