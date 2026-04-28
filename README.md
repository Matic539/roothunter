# 🔍 RootHunter

> Suite de auditoría de seguridad Linux: recolección de evidencia + análisis ofensivo defensivo de vectores de escalada de privilegios.

![Bash](https://img.shields.io/badge/bash-5.x-green?logo=gnubash&logoColor=white)
![Python](https://img.shields.io/badge/python-3.7+-blue?logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/platform-Linux-blue)
![License](https://img.shields.io/badge/license-MIT-lightgrey)
![roothunter](https://img.shields.io/badge/roothunter.sh-2.1.0-orange)
![rh-analyze](https://img.shields.io/badge/rh--analyze-1.0-orange)

---

## ⚠️ Aviso Legal / Disclaimer

> **Estas herramientas deben usarse únicamente en sistemas sobre los que tienes autorización explícita para auditar.**
> El uso no autorizado en sistemas ajenos puede constituir un delito. El autor no se hace responsable del mal uso de estas herramientas.
>
> `rh-analyze`: no ejecuta exploits ni automatiza ataques. Solo razona sobre la evidencia recolectada por `roothunter.sh` para sugerir vectores y priorizar remediaciones.

---

## 📋 Descripción

**RootHunter** es una suite de auditoría para sistemas Linux. Está diseñada para pentesters, administradores y equipos de seguridad que quieren detectar y priorizar los vectores de escalada de privilegios más comunes antes de que un atacante los explote.

La suite separa dos responsabilidades:

- **`roothunter.sh`** — Recolección de evidencia. Bash sin dependencias pesadas, ejecutable directo en el host objetivo. Emite un reporte JSON con contrato estable.
- **`rh-analyze`** — Análisis sobre la evidencia. Python stdlib, ejecutable offline, lee el JSON y razona: sugerencias de exploits con PoCs, attack paths encadenados, score de riesgo y diff entre auditorías.

---

## 🧩 Módulos de `roothunter.sh`

| # | Módulo | Descripción |
|---|--------|-------------|
| 1 | Sistema | Información general del host, entorno y detección de contenedor |
| 2 | SUID / SGID | Binarios con bits especiales cruzados contra GTFOBins (sin cruzar filesystems con `-xdev`) |
| 3 | Sudo | Configuración de sudo, NOPASSWD, grupos privilegiados |
| 4 | Cron Jobs | Tareas programadas con scripts escribibles |
| 5 | Permisos de Archivos | `/etc/passwd`, `/etc/shadow`, claves SSH, configs con credenciales |
| 6 | Linux Capabilities | Capabilities peligrosas asignadas a binarios |
| 7 | Kernel y CVEs | ASLR, ptrace, dmesg, kptr_restrict, symlinks protegidos + consulta live de CVEs |
| 8 | NFS | Shares con `no_root_squash`, exports inseguros |
| 9 | Historial | Contraseñas y secretos en bash, zsh, fish, python, mysql y psql history |
| 10 | Servicios y Puertos | Servicios locales, interfaces expuestas, Docker socket accesible |
| 11 | Variables de Entorno | PATH hijacking, `LD_PRELOAD`, secretos en variables del proceso actual |
| 12 | Usuarios y Cuentas | UIDs duplicados con root, usuarios sin contraseña, shells interactivas |
| 13 | Contenedores | Escape Docker/LXC, socket escribible, namespaces compartidos, tokens Kubernetes |
| 14 | Cloud IMDS | Credenciales AWS (IMDSv1/v2), GCP y Azure vía metadata server y archivos locales |
| 15 | Systemd | Units y timers escribibles, binarios de servicios activos, reglas Polkit, PwnKit (CVE-2021-4034) |
| 16 | PAM y SSH Keys | Backdoors PAM, módulos no estándar, `authorized_keys` con comandos forzados, `sshd_config` inseguro |

---

## 🚀 Uso de `roothunter.sh`

```bash
# Clonar el repositorio
git clone https://github.com/Matic539/roothunter.git
cd roothunter
chmod +x roothunter.sh rh-analyze

# Ejecución básica (todos los módulos)
bash roothunter.sh

# Ejecutar solo módulos específicos
bash roothunter.sh -m suid,sudo,kernel

# Guardar reporte en texto plano
bash roothunter.sh -o reporte.txt

# Exportar reporte en JSON (necesario para rh-analyze)
bash roothunter.sh -j reporte.json

# Modo verbose (referencias y detalles extra) --> ¡Recomendado!
bash roothunter.sh -v

# Combinado
bash roothunter.sh -v -o reporte.txt -j reporte.json
```

### Opciones

| Flag | Descripción |
|------|-------------|
| `-o <archivo>` | Guarda el reporte en texto plano (sin colores ANSI) |
| `-j <archivo>` | Exporta el reporte completo en formato JSON |
| `-m <módulos>` | Ejecuta solo los módulos indicados, separados por coma |
| `-v` | Modo verbose: muestra referencias GTFOBins/HackTricks y detalles extra |
| `-h` | Muestra la ayuda |

### Módulos disponibles para `-m`

```
sysinfo, suid, sudo, cron, files, caps, kernel, nfs,
history, services, env, users, containers, cloud, systemd, pam
```

---

## 🧠 Uso de `rh-analyze`

`rh-analyze` consume el JSON producido por `roothunter.sh -j` y aplica lógica de análisis defensivo. Solo Python 3.7+ stdlib — sin dependencias externas.

```bash
# Análisis estándar (score + exploits + attack paths + resumen)
./rh-analyze reporte.json

# Solo el score de riesgo
./rh-analyze reporte.json --score

# Solo exploits sugeridos con CVE y PoC
./rh-analyze reporte.json --exploits

# Solo attack paths encadenados
./rh-analyze reporte.json --paths

# Comparar dos auditorías (ej: antes y después de aplicar parches)
./rh-analyze --diff antes.json despues.json

# Priorizar una flota completa por score
./rh-analyze --batch /var/audits/*.json

# Exportar el análisis a Markdown para compartir
./rh-analyze reporte.json -o analisis.md
```

### Opciones

| Flag | Descripción |
|------|-------------|
| `--score` | Muestra solo la puntuación de riesgo y su desglose |
| `--exploits` | Muestra solo los exploits aplicables con CVE y PoC |
| `--paths` | Muestra solo los attack paths encadenados |
| `--diff OLD NEW` | Compara dos reportes y muestra hallazgos nuevos / remediados |
| `--batch` | Procesa múltiples reportes y los prioriza por score |
| `-o <archivo.md>` | Exporta el análisis a Markdown |
| `--no-color` | Desactiva colores ANSI (útil en pipes y CI) |

### 🎯 Qué detecta

**Exploits sugeridos** — Base local de CVEs públicos contrastada contra los hallazgos:

| CVE | Vector | Severidad |
|-----|--------|-----------|
| CVE-2021-3156 | Baron Samedit (sudo heap overflow) | crítica |
| CVE-2021-4034 | PwnKit (pkexec) | crítica |
| CVE-2022-0847 | Dirty Pipe (kernel) | crítica |
| CVE-2023-4911 | Looney Tunables (glibc) | crítica |
| GTFOBins | Grupo `docker` = root en host | crítica |
| Container escape | Docker socket escribible | crítica |

**Attack paths encadenados** — Construye rutas de escalada combinando hallazgos:

- Cron escribible → ejecución como root
- SUID peligroso → escalada vía GTFOBins
- Sudo NOPASSWD → shell como root inmediato
- PATH hijacking + cron → ejecución como root
- Kernel/glibc vulnerable → exploit local
- Clave SSH privada legible → movimiento lateral
- Token Kubernetes accesible → pivote en cluster
- Credenciales cloud vía IMDS → pivote en cuenta

**Score de riesgo (0–100)** — Combina cantidad de hallazgos críticos, advertencias, y bonus contextuales (acceso a Docker, sudo NOPASSWD, shadow legible, IMDS sin token, credenciales cloud, PAM backdoor).

| Score | Nivel |
|-------|-------|
| 70–100 | 🔴 CRÍTICO
| 40–69 | 🟡 ALTO
| 15–39 | 🔵 MEDIO
| 0–14 | 🟢 BAJO

---

## 🔄 Flujo de trabajo recomendado

```bash
# Día 1: auditoría inicial
bash roothunter.sh -j /tmp/host01.json
./rh-analyze /tmp/host01.json

# Día 1: revisar prioridades en flota completa
./rh-analyze --batch /var/audits/*.json

# Día 7: tras aplicar parches, comparar
bash roothunter.sh -j /tmp/host01_v2.json
./rh-analyze --diff /tmp/host01.json /tmp/host01_v2.json

# Generar reporte para compartir con el equipo
./rh-analyze /tmp/host01.json -o /tmp/analisis_host01.md
```

---

## 📤 Formatos de Salida

### Terminal (color)
Los hallazgos se clasifican visualmente:
- 🔴 `[CRÍTICO]` — Vectores explotables directamente
- 🟡 `[ADVERTENCIA]` — Configuraciones débiles o sospechosas
- 🔵 `[INFO]` — Datos informativos del sistema

Al finalizar, se imprime un **resumen consolidado** con todos los hallazgos críticos y advertencias agrupadas.

### JSON (contrato entre las dos herramientas)
El reporte JSON incluye metadata del host, SHA256 del script, resumen de hallazgos y los resultados organizados por módulo:

```json
{
  "report": {
    "tool": "roothunter.sh",
    "version": "1.1.0",
    "timestamp": "2025-01-01T00:00:00Z",
    "script_sha256": "abc123...",
    "target": { "hostname": "...", "kernel": "...", "user": "...", "uid": 1000 },
    "summary": { "critical": 3, "warnings": 7, "info": 25 },
    "modules": [
      {
        "module": "SUID/SGID",
        "critical": ["SUID peligroso: /usr/bin/find ..."],
        "warnings": [],
        "info": ["Total SUID: 12"]
      }
    ]
  }
}
```

### Markdown (`rh-analyze -o`)
Reporte ejecutivo listo para compartir: tabla de resumen, exploits sugeridos con PoC, attack paths paso a paso y recomendaciones priorizadas.

---

## 🛠️ Requisitos

**`roothunter.sh`**
- Bash 4.x o superior
- Linux (probado en Ubuntu, Debian, CentOS, Fedora)
- `curl` + `python3` *(opcionales — requeridos para consulta live de CVEs y JSON pretty-print)*
- Ejecutar como usuario regular. Algunos checks requieren permisos elevados para mayor cobertura.

**`rh-analyze`**
- Python 3.7 o superior (solo stdlib, sin dependencias externas)
- Funciona offline — útil para analizar reportes en una estación de trabajo aislada

---

## 📁 Estructura del Proyecto

```
roothunter/
├── roothunter.sh       # Recolección de evidencia (Bash)
├── rh-analyze          # Análisis sobre la evidencia (Python)
├── LICENSE
└── README.md
```

---

## 🔗 Referencias

- [GTFOBins](https://gtfobins.github.io)
- [HackTricks — Linux Privilege Escalation](https://book.hacktricks.xyz/linux-hardening/privilege-escalation)
- [Linux Kernel CVEs](https://www.linuxkernelcves.com)

---

## 👤 Autor

**Matias López**
- GitHub: [@Matic539](https://github.com/Matic539)

---

## 📄 Licencia

Este proyecto está bajo la licencia MIT. Consulta el archivo [LICENSE](LICENSE) para más detalles.
