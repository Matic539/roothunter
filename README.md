# 🔍 RootHunter

> Suite de auditoría ofensiva para Linux: recolección de evidencia + análisis de vectores de escalada de privilegios con priorización tipo pentester.

![Bash](https://img.shields.io/badge/bash-5.x-green?logo=gnubash&logoColor=white)
![Python](https://img.shields.io/badge/python-3.7+-blue?logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/platform-Linux-blue)
![License](https://img.shields.io/badge/license-MIT-lightgrey)
![roothunter](https://img.shields.io/badge/roothunter.sh-1.2.0-orange)
![rh-analyze](https://img.shields.io/badge/rh--analyze-1.2-orange)

---

## ⚠️ Aviso Legal / Disclaimer

> **Estas herramientas deben usarse únicamente en sistemas sobre los que tienes autorización explícita para auditar.**
> El uso no autorizado en sistemas ajenos puede constituir un delito. El autor no se hace responsable del mal uso de estas herramientas.
>
> `rh-analyze` no ejecuta exploits ni automatiza ataques: razona sobre la evidencia recolectada por `roothunter.sh` para sugerir vectores priorizados, atacando paths y comandos exactos para revisión manual.

---

## 📋 Descripción

**RootHunter** es una suite de auditoría con enfoque ofensivo para sistemas Linux. Está diseñada para pentesters, red teams y administradores que quieren detectar y priorizar los vectores de escalada de privilegios más explotados antes de que un atacante los encuentre.

La suite separa tres responsabilidades en tres capas:

- **`roothunter.sh`** — Recolección de evidencia. Bash sin dependencias pesadas, ejecutable directo en el host objetivo. Emite un reporte JSON con schema v2 estructurado (cada finding lleva `type`, `severity`, `data` parseable).
- **`lib/gtfobins.py`** — Base local de técnicas de escalada por binario (SUID, sudo, capabilities) con verificación en 3 niveles y scoring `reliability/stealth/speed`.
- **`rh-analyze`** — Análisis sobre la evidencia. Python stdlib, ejecutable offline. Lee el JSON y produce: exploits CVE aplicables con `confidence`, attack paths encadenados, score 0–100, comandos exactos priorizados por tier, modo playbook copy-paste, diff entre auditorías.

---

## 📁 Estructura del Proyecto

```
roothunter/
├── roothunter.sh          # Recolección de evidencia (Bash)
├── rh-analyze             # Análisis y priorización (Python)
├── lib/
│   ├── gtfobins.py        # Base local de técnicas SUID/sudo/capabilities
│   └── suid_whitelist.py  # Whitelist de SUID legítimos por distro
├── LICENSE
└── README.md
```

`gtfobins.py` y `suid_whitelist.py` se cargan automáticamente desde `lib/` cuando ejecutas `rh-analyze` o `roothunter.sh -V`. No hay que instalarlos ni configurar PYTHONPATH — la suite descubre los módulos relativos al script.

---

## 🧩 Módulos de `roothunter.sh`

| # | Módulo | Descripción |
|---|--------|-------------|
| 1 | sysinfo | Información del host, glibc, detección de contenedor |
| 2 | suid | Binarios SUID / SGID cruzados contra GTFOBins (`-xdev`, no cruza filesystems) |
| 3 | sudo | Configuración sudo, NOPASSWD parseado por regla, grupos privilegiados |
| 4 | cron | Tareas programadas con scripts escribibles |
| 5 | files | `/etc/passwd`, `/etc/shadow`, claves SSH legibles, configs con credenciales |
| 6 | caps | Linux capabilities peligrosas (`cap_setuid`, `cap_sys_admin`, `cap_dac_read_search`, etc.) |
| 7 | kernel | ASLR, ptrace, kptr_restrict, symlinks, user namespaces + consulta de CVEs |
| 8 | nfs | Shares con `no_root_squash`, exports inseguros |
| 9 | history | Contraseñas y secretos en bash, zsh, fish, python, mysql, psql history |
| 10 | services | Servicios locales, interfaces expuestas, Docker socket |
| 11 | env | PATH hijacking, `LD_PRELOAD`, secretos en variables del proceso actual |
| 12 | users | UIDs duplicados con root, usuarios sin contraseña, shells interactivas |
| 13 | containers | Escape Docker/LXC, socket escribible, namespaces compartidos, tokens K8s |
| 14 | cloud | Credenciales AWS (IMDSv1/v2), GCP y Azure vía metadata server |
| 15 | systemd | Units y timers escribibles, reglas Polkit, PwnKit (CVE-2021-4034) |
| 16 | pam | Backdoors PAM, módulos no estándar, `authorized_keys`, `sshd_config` |
| 17 | processes | Procesos root con binarios escribibles, secretos en `/proc/<pid>/environ`, sockets unix relajados, `.bashrc`/`profile.d` ajenos |

---

## 🚀 Uso de `roothunter.sh`

```bash
# Clonar
git clone https://github.com/Matic539/roothunter.git
cd roothunter
chmod +x roothunter.sh rh-analyze

# Ejecución básica (todos los módulos)
bash roothunter.sh

# Ejecutar solo módulos específicos
bash roothunter.sh -m suid,sudo,kernel

# Generar JSON estructurado para rh-analyze
bash roothunter.sh -j reporte.json

# Modo verbose con referencias GTFOBins / HackTricks
bash roothunter.sh -v

# Verificación opt-in de vectores (opt-in, requiere lib/gtfobins.py + python3)
bash roothunter.sh -V -j reporte.json

# Combinado típico para pentest
bash roothunter.sh -v -V -o reporte.txt -j reporte.json
```

### Opciones

| Flag | Descripción |
|------|-------------|
| `-o <archivo>` | Guarda reporte en texto plano (sin colores ANSI) |
| `-j <archivo>` | Exporta reporte en JSON schema v2 (entrada para `rh-analyze`) |
| `-m <módulos>` | Ejecuta solo los módulos indicados, separados por coma |
| `-v` | Modo verbose: referencias GTFOBins/HackTricks y detalles extra |
| `-V`, `--verify-vectors` | Verifica precondition+capability de vectores SUID/sudo/cap usando `lib/gtfobins.py`. Marca `verified=true/false` en el JSON. **No ejecuta exploits**, solo chequeos no destructivos. |
| `-h` | Ayuda |

### Módulos disponibles para `-m`

```
sysinfo, suid, sudo, cron, files, caps, kernel, nfs,
history, services, env, users, containers, cloud, systemd, pam, processes
```

### Sobre `-V` (verificación de vectores)

Cuando un módulo detecta un vector potencial (ej: `find` con SUID), por defecto solo registra el path y dueño. Con `-V`, la herramienta consulta `lib/gtfobins.py` para ejecutar dos chequeos no destructivos:

- **precondition**: el vector existe (ej: `stat` muestra bit SUID activo).
- **capability**: el binario tiene la feature necesaria (ej: `vim` compilado con `+python3`).

El JSON resultante incluye `verified=true|false|unknown` por finding. `rh-analyze` muestra esa marca como `✓ VERIFICADO` o `✗ NO VIABLE`, ahorrándote tiempo persiguiendo falsos positivos.

---

## 🧠 Uso de `rh-analyze`

`rh-analyze` consume el JSON producido por `roothunter.sh -j` y aplica análisis ofensivo. Solo Python 3.7+ stdlib — sin dependencias externas.

```bash
# Análisis estándar (score + exploits + comandos + paths + resumen)
./rh-analyze reporte.json

# Comandos exactos priorizados por tier (requiere reporte schema v2)
./rh-analyze reporte.json --commands

# Modo playbook copy-paste, sin colores ni metadata (ideal para notas .txt)
./rh-analyze reporte.json --playbook > playbook.sh

# Confirmar técnicas con dry-runs no destructivos EN EL HOST OBJETIVO
./rh-analyze reporte.json --confirm

# Solo el score
./rh-analyze reporte.json --score

# Solo exploits CVE aplicables
./rh-analyze reporte.json --exploits

# Solo attack paths encadenados
./rh-analyze reporte.json --paths

# Comparar dos auditorías
./rh-analyze --diff antes.json despues.json

# Priorizar una flota completa por score
./rh-analyze --batch /var/audits/*.json

# Cobertura de la base local (binarios SUID/sudo/caps documentados)
./rh-analyze --list-techniques

# Exportar análisis a Markdown
./rh-analyze reporte.json -o analisis.md
```

### Opciones

| Flag | Descripción |
|------|-------------|
| `--score` | Score de riesgo y desglose |
| `--exploits` | CVEs aplicables con PoC y `confidence` |
| `--commands` | Comandos exactos sugeridos, agrupados por tier (requiere schema v2) |
| `--playbook` | Solo comandos en orden de prioridad, plain text |
| `--confirm` | Ejecuta dry-runs no destructivos en el host actual |
| `--paths` | Attack paths encadenados |
| `--diff OLD NEW` | Compara dos reportes |
| `--batch` | Procesa múltiples reportes y los prioriza por score |
| `--list-techniques` | Cobertura de `lib/gtfobins.py` y `lib/suid_whitelist.py` |
| `-o <archivo.md>` | Exporta el análisis a Markdown |
| `--no-color` | Desactiva colores ANSI (útil en pipes y CI) |

### 🎯 Qué detecta

**Exploits CVE sugeridos** — Base local de CVEs públicos contrastada contra los hallazgos. Cada exploit lleva `confidence` (high/medium/low) con nota de contexto:

| CVE / Vector | Nombre | Severidad | Confianza |
|--------------|--------|-----------|-----------|
| CVE-2021-3156 | Baron Samedit (sudo heap overflow) | crítica | high |
| CVE-2021-4034 | PwnKit (pkexec) | crítica | high |
| CVE-2022-0847 | Dirty Pipe (kernel) | crítica | high |
| CVE-2023-22809 | Sudoedit env injection | crítica | high |
| CVE-2025-32463 | Sudo `--chroot` path resolution | crítica | medium |
| CVE-2023-4911 | Looney Tunables (glibc) | crítica | high |
| CVE-2024-1086 | nf_tables double-free | crítica | medium |
| CVE-2023-0386 | OverlayFS UID mapping | crítica | high |
| CVE-2023-32233 | Netfilter nf_tables UAF | crítica | medium |
| CVE-2022-2588 | cls_route UAF | alta | medium |
| CVE-2021-22555 | Netfilter heap overflow | alta | medium |
| CVE-2025-6019 | libblockdev/udisks LPE | alta | low |
| GTFOBins | Grupo `docker` = root en host | crítica | high |
| Container escape | Docker socket escribible | crítica | high |

**Comandos exactos priorizados por tier** (`--commands`) — Cada técnica accionable lleva:

- `verify` — comando para confirmar precondition
- `exploit` — comando que abre shell o eleva privilegios
- `why` — explicación en una línea
- `success` — qué se ve si funcionó
- Score `reliability × 2 + stealth + speed` (rango 4–25)

| Tier | Score | Significado |
|------|-------|-------------|
| 🟢 Tier 1 | 18–25 | Win fácil, intentar primero |
| 🟡 Tier 2 | 12–17 | Plan B si tier 1 falla |
| 🔴 Tier 3 | 4–11 | Último recurso (frágil o ruidoso) |

**Attack paths encadenados** — Construye rutas de escalada combinando hallazgos:

- Cron escribible → ejecución como root
- SUID peligroso → escalada vía GTFOBins
- Sudo NOPASSWD → shell como root inmediato
- PATH hijacking + cron → ejecución como root
- Kernel/glibc vulnerable → exploit local
- Clave SSH privada legible → movimiento lateral
- Token Kubernetes accesible → pivote en cluster
- Credenciales cloud vía IMDS → pivote en cuenta
- Secretos en `/proc/<pid>/environ` → robo de credenciales de daemons
- Binario root escribible → escalada al reinicio del proceso
- `profile.d`/`.bashrc` ajenos escribibles → escalada al login
- Socket unix escribible (Redis/Docker/Postgres) → RCE según daemon

**Score de riesgo (0–100)** — Combina cantidad de hallazgos críticos, advertencias y bonus contextuales (acceso a Docker, sudo NOPASSWD, shadow legible, IMDS sin token, credenciales cloud, PAM backdoor, secretos en `/proc`, profile.d escribible, socket unix relajado). Los SUID legítimos del sistema (matched contra `lib/suid_whitelist.py`) se descuentan del bucket de críticos.

| Score | Nivel |
|-------|-------|
| 70–100 | 🔴 CRÍTICO |
| 40–69 | 🟡 ALTO |
| 15–39 | 🔵 MEDIO |
| 0–14 | 🟢 BAJO |

---

## 🔄 Flujo de trabajo recomendado

```bash
# Día 1: auditoría inicial con verificación de vectores
bash roothunter.sh -V -j /tmp/host01.json

# Día 1: análisis con comandos priorizados por tier
./rh-analyze /tmp/host01.json --commands

# Día 1: confirmar las técnicas tier 1 con dry-runs no destructivos
./rh-analyze /tmp/host01.json --confirm

# Día 1: revisar prioridades en flota completa
./rh-analyze --batch /var/audits/*.json

# Día 7: tras aplicar parches, comparar
bash roothunter.sh -V -j /tmp/host01_v2.json
./rh-analyze --diff /tmp/host01.json /tmp/host01_v2.json

# Generar playbook para notas
./rh-analyze /tmp/host01.json --playbook > /tmp/playbook_host01.txt

# Generar reporte ejecutivo en Markdown
./rh-analyze /tmp/host01.json -o /tmp/analisis_host01.md
```

---

## 📤 Formatos de Salida

### Terminal (color)

Los hallazgos se clasifican visualmente:

- 🔴 `[CRÍTICO]` — Vectores explotables directamente
- 🟡 `[ADVERTENCIA]` — Configuraciones débiles o sospechosas
- 🔵 `[INFO]` — Datos informativos del sistema

Al finalizar, se imprime un resumen con todos los hallazgos críticos y advertencias agrupados.

### JSON schema v2 (contrato entre las dos herramientas)

El reporte JSON incluye metadata del host, SHA256 del script, summary, findings estructurados (cada uno con `type`, `severity`, `message`, `data` parseable) y resultados por módulo:

```json
{
  "report": {
    "tool": "roothunter.sh",
    "version": "1.2.0",
    "schema_version": "2",
    "timestamp": "2025-01-01T00:00:00Z",
    "script_sha256": "abc123...",
    "target": {
      "hostname": "...", "kernel": "...", "os": "...",
      "user": "...", "uid": 1000, "groups": "..."
    },
    "summary": { "critical": 3, "warnings": 7, "info": 25, "structured_findings": 12 },
    "findings": [
      {
        "type": "suid_dangerous",
        "severity": "critical",
        "message": "SUID peligroso: /usr/bin/find (owner: root, perms: 4755)",
        "data": {
          "binary": "find", "path": "/usr/bin/find",
          "owner": "root", "perms": "4755",
          "verified": "true", "verified_at_level": "capability"
        }
      }
    ],
    "modules": [ /* findings agrupados por módulo */ ]
  }
}
```

### Markdown (`rh-analyze -o`)

Reporte ejecutivo listo para compartir: tabla de resumen, exploits CVE con PoC y confidence, attack paths paso a paso y recomendaciones priorizadas según el score.

### Playbook (`rh-analyze --playbook`)

Plain text sin colores, comandos en orden de tier+score. Ideal para volcar a notas o pasar a un compañero del red team:

```
# ─── TIER 1 — WIN FÁCIL (intenta primero) ───

# SUID en find  [score 22/25]
# Path: /usr/bin/find  |  Owner: root  |  Perms: 4755
#   verify:
stat -c "%U %a" /usr/bin/find 2>/dev/null
#   exploit:
/usr/bin/find . -exec /bin/sh -p \; -quit
```

---

## 🛠️ Requisitos

**`roothunter.sh`**

- Bash 4.x o superior
- Linux (probado en Ubuntu, Debian, CentOS, Fedora, Alpine)
- `curl` + `python3` *(opcionales — requeridos para consulta live de CVEs, pretty-print y `-V`)*
- Ejecutar como usuario regular. Algunos checks requieren permisos elevados para mayor cobertura.

**`rh-analyze`**

- Python 3.7 o superior (solo stdlib, sin dependencias externas)
- Funciona offline — útil para analizar reportes en una estación de trabajo aislada
- Carga automáticamente `lib/gtfobins.py` y `lib/suid_whitelist.py` desde el directorio del script

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
