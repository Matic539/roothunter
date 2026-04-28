#!/usr/bin/env bash
# =============================================================================
#  roothunter.sh — Script de Auditoría de Seguridad Linux v1.1.0
#  Detecta vectores comunes de escalada de privilegios
#  Autor: Matias López | Portafolio: github.com/Matic539
#
#  Uso: bash roothunter.sh [-o reporte.txt] [-j reporte.json] [-m módulos] [-v] [-h]
#    -o  Guardar reporte en texto plano
#    -j  Exportar reporte en formato JSON
#    -m  Ejecutar solo módulos específicos (ej: -m suid,sudo,kernel)
#        Módulos: sysinfo,suid,sudo,cron,files,caps,kernel,nfs,history,
#                 services,env,users,containers,cloud,systemd,pam
#    -v  Modo verbose (muestra referencias y detalles extra)
#    -h  Ayuda
# =============================================================================

# NO usamos set -e porque un comando fallido mataría el script silenciosamente.
# Cada función maneja sus propios errores con || true o 2>/dev/null.
set -uo pipefail

# ─── Colores ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'; DIM='\033[2m'

# ─── Variables globales ───────────────────────────────────────────────────────
OUTPUT_FILE=""
JSON_FILE=""
VERBOSE=false
SELECTED_MODULES=""
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
TIMESTAMP_ISO=$(date -u '+%Y-%m-%dT%H:%M:%SZ')

# Integridad del propio script
SCRIPT_SHA256=$(sha256sum "$0" 2>/dev/null | awk '{print $1}' || echo "no-disponible")

# Arrays de hallazgos globales (para el resumen final)
FINDINGS=()
WARNINGS=()
INFOS=()

# Arrays de hallazgos por módulo (para JSON)
_MOD_FINDINGS=(); _MOD_WARNINGS=(); _MOD_INFOS=()
JSON_MODULES=()



# ─── Limpieza de temporales al salir ──────────────────────────────────────────
_TMP_FILES=()
_cleanup() {
  for f in "${_TMP_FILES[@]+"${_TMP_FILES[@]}"}"; do
    rm -f "$f" 2>/dev/null || true
  done
}
trap '_cleanup' EXIT

_tmp_file() {
  local f
  f=$(mktemp /tmp/_roothunter_XXXXXX 2>/dev/null || echo "/tmp/_roothunter_$$_${RANDOM}")
  _TMP_FILES+=("$f")
  echo "$f"
}

# ─── Argumentos ───────────────────────────────────────────────────────────────
usage() {
  echo ""
  echo -e "${BOLD}Uso:${RESET} $0 [-o archivo.txt] [-j archivo.json] [-m módulos] [-v] [-h]"
  echo ""
  echo "  -o  Guardar reporte en texto plano"
  echo "  -j  Exportar reporte en JSON"
  echo "  -v  Modo verbose (referencias GTFOBins / HackTricks)"
  echo "  -m  Ejecutar solo módulos específicos (separados por coma)"
  echo "  -h  Esta ayuda"
  echo ""
  echo -e "${BOLD}Módulos disponibles:${RESET}"
  echo "  sysinfo   → Información del sistema"
  echo "  suid      → Binarios SUID / SGID"
  echo "  sudo      → Configuración sudo"
  echo "  cron      → Tareas cron"
  echo "  files     → Archivos sensibles y permisos"
  echo "  caps      → Linux capabilities"
  echo "  kernel    → Kernel y CVEs"
  echo "  nfs       → NFS no_root_squash"
  echo "  history   → Historial bash"
  echo "  services  → Servicios y puertos"
  echo "  env       → Variables de entorno y PATH"
  echo "  users     → Usuarios y cuentas"
  echo "  containers→ Escape de contenedores (nuevo)"
  echo "  cloud     → Credenciales IMDS cloud (nuevo)"
  echo "  systemd   → Units systemd escribibles (nuevo)"
  echo "  pam       → PAM backdoors y authorized_keys (nuevo)"
  echo ""
  echo -e "${BOLD}Ejemplos:${RESET}"
  echo "  bash $0 -m suid,sudo,kernel"
  echo "  bash $0 -o reporte.txt -j reporte.json -v"
  echo ""
  exit 0
}

while getopts ":o:j:m:vh" opt; do
  case $opt in
    o) OUTPUT_FILE="$OPTARG" ;;
    j) JSON_FILE="$OPTARG" ;;
    m) SELECTED_MODULES="$OPTARG" ;;
    v) VERBOSE=true ;;
    h) usage ;;
    *) usage ;;
  esac
done

# ─── Helpers de módulos seleccionados ─────────────────────────────────────────
_module_enabled() {
  local name="$1"
  [[ -z "$SELECTED_MODULES" ]] && return 0
  echo "$SELECTED_MODULES" | tr ',' '\n' | grep -qx "$name"
}



# ─── Helpers de impresión ─────────────────────────────────────────────────────
print_header() {
  echo -e "\n${BOLD}${CYAN}══════════════════════════════════════════${RESET}"
  echo -e "${BOLD}${CYAN}  $1${RESET}"
  echo -e "${BOLD}${CYAN}══════════════════════════════════════════${RESET}"
}

print_verbose() { $VERBOSE && echo -e "       ${RESET}↳ $1" || true; }

# Helpers que imprimen Y acumulan en arrays global + módulo
mod_critical() {
  echo -e "  ${RED}[CRÍTICO]${RESET} $1"
  FINDINGS+=("$1")
  _MOD_FINDINGS+=("$1")
}
mod_warning() {
  echo -e "  ${YELLOW}[ADVERTENCIA]${RESET} $1"
  WARNINGS+=("$1")
  _MOD_WARNINGS+=("$1")
}
mod_info() {
  echo -e "  ${CYAN}[INFO]${RESET} $1"
  INFOS+=("$1")
  _MOD_INFOS+=("$1")
}
mod_ok() {
  echo -e "  ${GREEN}[OK]${RESET} $1"
  _MOD_INFOS+=("OK: $1")
}

# ─── Helper JSON ──────────────────────────────────────────────────────────────
json_escape() {
  local s="$1"
  s="${s//\\/\\\\}"; s="${s//\"/\\\"}"; s="${s//$'\n'/\\n}"; s="${s//$'\t'/\\t}"
  echo "$s"
}

flush_module_json() {
  local module_name="$1"
  local f_json="[" w_json="[" i_json="["
  local first=true

  for item in "${_MOD_FINDINGS[@]+"${_MOD_FINDINGS[@]}"}"; do
    $first || f_json+=","; f_json+="\"$(json_escape "$item")\""; first=false
  done; f_json+="]"; first=true

  for item in "${_MOD_WARNINGS[@]+"${_MOD_WARNINGS[@]}"}"; do
    $first || w_json+=","; w_json+="\"$(json_escape "$item")\""; first=false
  done; w_json+="]"; first=true

  for item in "${_MOD_INFOS[@]+"${_MOD_INFOS[@]}"}"; do
    $first || i_json+=","; i_json+="\"$(json_escape "$item")\""; first=false
  done; i_json+="]"

  JSON_MODULES+=("{\"module\":\"$(json_escape "$module_name")\",\"critical\":$f_json,\"warnings\":$w_json,\"info\":$i_json}")
  _MOD_FINDINGS=(); _MOD_WARNINGS=(); _MOD_INFOS=()
}

_run_module() {
  local fn="$1"
  local label="$2"
  local timeout_sec="${3:-60}"

  local _mod_start _mod_end _mod_elapsed
  _mod_start=$(date +%s 2>/dev/null || echo 0)

  "$fn"

  _mod_end=$(date +%s 2>/dev/null || echo 0)
  _mod_elapsed=$(( _mod_end - _mod_start ))
  if [[ $_mod_elapsed -gt $timeout_sec ]]; then
    echo -e "  ${YELLOW}[ADVERTENCIA]${RESET} Módulo '$label' tardó ${_mod_elapsed}s (límite sugerido: ${timeout_sec}s)"
    WARNINGS+=("Módulo '$label' tardó ${_mod_elapsed}s — considerar uso de -m para seleccionar módulos")
  fi
}

# ─── 1. Información del sistema ───────────────────────────────────────────────
check_system_info() {
  print_header "1. INFORMACIÓN DEL SISTEMA"
  _MOD_FINDINGS=(); _MOD_WARNINGS=(); _MOD_INFOS=()

  mod_info "Hostname    : $(hostname 2>/dev/null || echo '?')"
  mod_info "OS          : $(grep -oP '(?<=^PRETTY_NAME=").+(?=")' /etc/os-release 2>/dev/null || uname -s)"
  mod_info "Kernel      : $(uname -r)"
  mod_info "Arquitectura: $(uname -m)"
  mod_info "Fecha audit : $TIMESTAMP"
  mod_info "Usuario     : $(whoami) (UID=$(id -u), GID=$(id -g))"
  mod_info "Grupos      : $(id -Gn)"
  mod_info "SHA256 script: $SCRIPT_SHA256"

  # Detectar si estamos dentro de un contenedor (informativo aquí, detallado en módulo containers)
  if [[ -f /.dockerenv ]] || grep -qE 'docker|lxc|containerd' /proc/1/cgroup 2>/dev/null; then
    mod_warning "Entorno detectado: posiblemente DENTRO DE UN CONTENEDOR"
  fi

  flush_module_json "Sistema"
}

# ─── 2. Binarios SUID/SGID ────────────────────────────────────────────────────
check_suid_sgid() {
  print_header "2. BINARIOS SUID / SGID"
  _MOD_FINDINGS=(); _MOD_WARNINGS=(); _MOD_INFOS=()

  local dangerous_suid=(
    "nmap" "vim" "vi" "nano" "find" "bash" "sh" "dash" "less" "more"
    "awk" "gawk" "python" "python3" "perl" "ruby" "lua" "env" "tee"
    "cp" "mv" "chmod" "chown" "dd" "tar" "zip" "unzip" "curl" "wget"
    "nc" "netcat" "ncat" "socat" "tcpdump" "strace" "ltrace" "gdb"
    "node" "php" "man" "ftp" "tftp" "ssh" "scp" "rsync"
    "docker" "lxc" "runc" "kubectl" "git" "make" "gcc"
    "mysql" "sqlite3" "psql" "mongod" "redis-cli"
    "openssl" "pkexec" "su" "sudo" "passwd" "snap" "pip" "pip3"
    "ruby" "irb" "lua" "lua5.1" "lua5.2" "lua5.3" "expect"
    "ionice" "nice" "taskset" "time" "timeout" "watch"
  )

  mod_info "Buscando binarios SUID en sistemas de archivos locales (-xdev)..."
  local count=0 sgid_count=0

  # -xdev: no cruzar otros sistemas de archivos (evita /proc, /sys, NFS, etc.)
  # Reduce drásticamente el tiempo en sistemas grandes
  local suid_tmp
  suid_tmp=$(_tmp_file)
  find / -xdev -perm -4000 -type f 2>/dev/null | sort > "$suid_tmp"

  while IFS= read -r bin; do
    [[ -z "$bin" ]] && continue
    local name owner perms is_dangerous=false
    name=$(basename "$bin" 2>/dev/null) || continue
    owner=$(stat -c '%U' "$bin" 2>/dev/null || echo "?")
    perms=$(stat -c '%a' "$bin" 2>/dev/null || echo "?")
    count=$((count + 1))
    for d in "${dangerous_suid[@]}"; do
      [[ "$name" == "$d" ]] && is_dangerous=true && break
    done
    if $is_dangerous; then
      mod_critical "SUID peligroso: $bin (owner: $owner, perms: $perms)"
      print_verbose "GTFOBins: https://gtfobins.github.io/gtfobins/$name/"
    else
      mod_warning "SUID encontrado: $bin (owner: $owner)"
    fi
  done < "$suid_tmp"

  [[ $count -eq 0 ]] && mod_ok "No se encontraron binarios SUID"
  mod_info "Total SUID: $count"

  mod_info "Buscando binarios SGID..."
  local sgid_tmp
  sgid_tmp=$(_tmp_file)
  find / -xdev -perm -2000 -type f 2>/dev/null | sort > "$sgid_tmp"

  while IFS= read -r bin; do
    [[ -z "$bin" ]] && continue
    sgid_count=$((sgid_count + 1))
    mod_warning "SGID: $bin (owner: $(stat -c '%U:%G' "$bin" 2>/dev/null || echo '?'))"
  done < "$sgid_tmp"
  mod_info "Total SGID: $sgid_count"

  flush_module_json "SUID/SGID"
}

# ─── 3. Sudo ──────────────────────────────────────────────────────────────────
check_sudo() {
  print_header "3. CONFIGURACIÓN SUDO"
  _MOD_FINDINGS=(); _MOD_WARNINGS=(); _MOD_INFOS=()

  if ! command -v sudo &>/dev/null; then
    mod_info "sudo no instalado"; flush_module_json "Sudo"; return
  fi

  if sudo -n -l 2>/dev/null | grep -q "may run" 2>/dev/null; then
    mod_critical "El usuario puede ejecutar sudo SIN contraseña"
    while IFS= read -r line; do
      [[ -n "$line" && ! "$line" =~ ^(Matching|User|Defaults) ]] && mod_critical "  → $line"
    done < <(sudo -n -l 2>/dev/null || true)
  else
    mod_info "sudo requiere contraseña o no hay permisos configurados"
  fi

  id -nG 2>/dev/null | grep -qE '\bsudo\b|\bwheel\b|\badmin\b' && \
    mod_warning "Grupo privilegiado: $(id -nG 2>/dev/null | tr ' ' '\n' | grep -E 'sudo|wheel|admin' | tr '\n' ' ')" || true

  if [[ -r /etc/sudoers ]]; then
    while IFS= read -r line; do
      mod_critical "NOPASSWD en /etc/sudoers: $line"
    done < <(grep -i "NOPASSWD" /etc/sudoers 2>/dev/null | grep -v "^#" || true)
  fi

  if [[ -d /etc/sudoers.d ]]; then
    for f in /etc/sudoers.d/*; do
      [[ -r "$f" ]] || continue
      while IFS= read -r line; do
        mod_critical "NOPASSWD en $f: $line"
      done < <(grep -i "NOPASSWD" "$f" 2>/dev/null | grep -v "^#" || true)
    done
  fi

  flush_module_json "Sudo"
}

# ─── 4. Cron jobs ─────────────────────────────────────────────────────────────
check_cron() {
  print_header "4. TAREAS CRON"
  _MOD_FINDINGS=(); _MOD_WARNINGS=(); _MOD_INFOS=()

  local cron_paths=(
    /etc/crontab /etc/cron.d /etc/cron.daily
    /etc/cron.weekly /etc/cron.monthly
    /var/spool/cron /var/spool/cron/crontabs
  )

  for path in "${cron_paths[@]}"; do
    if [[ -f "$path" ]]; then
      mod_info "Cron: $path (owner: $(stat -c '%U' "$path" 2>/dev/null || echo '?'))"
      while IFS= read -r script; do
        [[ -f "$script" && -w "$script" ]] && mod_critical "Script cron ESCRIBIBLE: $script"
      done < <(grep -oP '(/[^\s]+)' "$path" 2>/dev/null || true)

    elif [[ -d "$path" ]]; then
      for f in "$path"/*; do
        [[ -f "$f" ]] || continue
        mod_info "Cron job: $f (owner: $(stat -c '%U' "$f" 2>/dev/null || echo '?'))"
        while IFS= read -r script; do
          [[ -f "$script" && -w "$script" ]] && mod_critical "Script cron ESCRIBIBLE: $script (en $f)"
        done < <(grep -oP '(/[^\s]+)' "$f" 2>/dev/null || true)
      done
    fi
  done

  local crontab_out
  crontab_out=$(crontab -l 2>/dev/null || true)
  if [[ -n "$crontab_out" ]]; then
    while IFS= read -r line; do
      [[ -n "$line" && ! "$line" =~ ^# ]] && mod_info "Crontab usuario: $line"
    done <<< "$crontab_out"
  fi

  flush_module_json "Cron"
}

# ─── 5. Archivos y permisos ───────────────────────────────────────────────────
check_file_permissions() {
  print_header "5. ARCHIVOS SENSIBLES Y PERMISOS"
  _MOD_FINDINGS=(); _MOD_WARNINGS=(); _MOD_INFOS=()

  [[ -w /etc/passwd ]] \
    && mod_critical "/etc/passwd ESCRIBIBLE — inyección de usuario root posible" \
    || mod_ok "/etc/passwd: solo lectura"

  [[ -r /etc/shadow ]] \
    && mod_critical "/etc/shadow LEGIBLE — hashes expuestos" \
    || mod_ok "/etc/shadow: no accesible"

  for dir in /root/.ssh /home/*/.ssh; do
    [[ -d "$dir" ]] || continue
    local perms; perms=$(stat -c '%a' "$dir" 2>/dev/null || echo "?")
    [[ "$perms" != "700" && "$perms" != "600" ]] && mod_warning "Permisos débiles en $dir ($perms)"
    for key in "$dir"/id_rsa "$dir"/id_ed25519 "$dir"/id_ecdsa "$dir"/id_dsa; do
      [[ -f "$key" && -r "$key" ]] && mod_critical "Clave SSH privada legible: $key"
    done
  done

  while IFS= read -r dir; do
    [[ -n "$dir" ]] && mod_critical "Directorio world-writable en ruta del sistema: $dir"
  done < <(find /etc /usr /bin /sbin /lib -maxdepth 2 -writable -type d 2>/dev/null || true)

  for f in /etc/mysql/my.cnf /var/www/html/wp-config.php ~/.aws/credentials ~/.docker/config.json; do
    [[ -f "$f" && -r "$f" ]] || continue
    mod_warning "Config legible: $f"
    while IFS= read -r line; do
      mod_critical "Posible credencial en $f: ${line:0:80}"
    done < <(grep -iE "(password|secret|token|key)\s*[=:]" "$f" 2>/dev/null | grep -v "^#" | head -3 || true)
  done

  flush_module_json "Permisos de archivos"
}

# ─── 6. Capabilities ──────────────────────────────────────────────────────────
check_capabilities() {
  print_header "6. LINUX CAPABILITIES"
  _MOD_FINDINGS=(); _MOD_WARNINGS=(); _MOD_INFOS=()

  if ! command -v getcap &>/dev/null; then
    mod_info "getcap no disponible — omitiendo"
    flush_module_json "Capabilities"; return
  fi

  local dangerous_caps=(
    "cap_setuid" "cap_setgid" "cap_sys_admin" "cap_sys_ptrace"
    "cap_dac_override" "cap_dac_read_search" "cap_sys_rawio"
    "cap_sys_module" "cap_net_raw"
  )

  local caps_list
  caps_list=$(getcap -r / 2>/dev/null || true)

  if [[ -z "$caps_list" ]]; then
    mod_ok "No se encontraron capabilities adicionales"
  else
    while IFS= read -r line; do
      [[ -z "$line" ]] && continue
      local cap is_dangerous=false
      cap=$(echo "$line" | awk '{print $2, $3}' 2>/dev/null || echo "")
      for dc in "${dangerous_caps[@]}"; do
        echo "$cap" | grep -qi "$dc" 2>/dev/null && is_dangerous=true && break
      done
      $is_dangerous && mod_critical "Capability peligrosa: $line" || mod_warning "Capability: $line"
    done <<< "$caps_list"
  fi

  flush_module_json "Capabilities"
}

# ─── 7. Kernel + CVEs via API ─────────────────────────────────────────────────
check_kernel() {
  print_header "7. KERNEL Y CVEs"
  _MOD_FINDINGS=(); _MOD_WARNINGS=(); _MOD_INFOS=()

  local kernel; kernel=$(uname -r 2>/dev/null || echo "desconocido")
  mod_info "Kernel: $kernel"

  # Protecciones del kernel
  if [[ -f /proc/sys/kernel/randomize_va_space ]]; then
    local aslr; aslr=$(cat /proc/sys/kernel/randomize_va_space 2>/dev/null || echo "?")
    case $aslr in
      2) mod_ok "ASLR: Completo (nivel 2)" ;;
      1) mod_warning "ASLR: Parcial (nivel 1)" ;;
      0) mod_critical "ASLR: DESHABILITADO" ;;
      *) mod_info "ASLR: valor desconocido ($aslr)" ;;
    esac
  fi

  if [[ -f /proc/sys/kernel/dmesg_restrict ]]; then
    local dmesg; dmesg=$(cat /proc/sys/kernel/dmesg_restrict 2>/dev/null || echo "?")
    [[ "$dmesg" == "0" ]] \
      && mod_warning "dmesg_restrict: deshabilitado" \
      || mod_ok "dmesg_restrict: habilitado ($dmesg)"
  fi

  if [[ -f /proc/sys/kernel/yama/ptrace_scope ]]; then
    local ptrace; ptrace=$(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null || echo "?")
    [[ "$ptrace" == "0" ]] \
      && mod_warning "ptrace_scope: 0 — procesos trazables por cualquier usuario" \
      || mod_ok "ptrace_scope: $ptrace (restringido)"
  fi

  # Protecciones adicionales
  if [[ -f /proc/sys/fs/protected_symlinks ]]; then
    local sl; sl=$(cat /proc/sys/fs/protected_symlinks 2>/dev/null || echo "?")
    [[ "$sl" == "0" ]] && mod_warning "protected_symlinks: deshabilitado — symlink races posibles"
  fi

  if [[ -f /proc/sys/kernel/kptr_restrict ]]; then
    local kr; kr=$(cat /proc/sys/kernel/kptr_restrict 2>/dev/null || echo "?")
    [[ "$kr" == "0" ]] && mod_warning "kptr_restrict: 0 — punteros del kernel expuestos en /proc"
  fi

  # ── Consulta CVEs a linuxkernelcves.com ───────────────────────────────────
  local kernel_base
  kernel_base=$(echo "$kernel" | grep -oE '^[0-9]+\.[0-9]+' 2>/dev/null || echo "")

  if [[ -z "$kernel_base" ]]; then
    mod_info "No se pudo extraer versión base del kernel para consulta CVE"
  else
    mod_info "Consultando CVEs para kernel $kernel_base (requiere internet)..."
  fi

  if [[ -n "$kernel_base" ]] && command -v curl &>/dev/null; then
    local api_url="https://www.linuxkernelcves.com/api/cves?kernel=${kernel_base}&limit=10"
    local http_code cve_tmp
    cve_tmp=$(_tmp_file)
    http_code=$(curl -s -o "$cve_tmp" -w "%{http_code}" \
      --max-time 10 -H "Accept: application/json" "$api_url" 2>/dev/null || echo "000")

    if [[ "$http_code" == "200" && -f "$cve_tmp" ]]; then
      if command -v python3 &>/dev/null; then
        local parsed
        parsed=$(python3 - "$cve_tmp" 2>/dev/null <<'PYEOF'
import json, sys
path = sys.argv[1]
try:
    with open(path) as f:
        raw = f.read().strip()
    if not raw:
        print("TOTAL:0"); sys.exit(0)
    data = json.loads(raw)
    cves = data if isinstance(data, list) else data.get("cves", data.get("results", []))
    for c in cves[:10]:
        cve_id  = c.get("cve_id", c.get("id", "N/A"))
        score   = str(c.get("cvss3_score", c.get("score", "0")) or "0")
        summary = c.get("summary", c.get("description", "Sin descripcion"))[:120]
        summary = summary.replace("|||", " ")
        try:
            sev = "CRITICAL" if float(score) >= 7.0 else "MEDIUM"
        except Exception:
            sev = "MEDIUM"
        # Usar un separador inequívoco: tabulador
        print(f"{sev}\t{cve_id}\tCVSS:{score}\t{summary}")
    print(f"TOTAL:{len(cves)}")
except Exception as e:
    print(f"ERROR:{e}")
PYEOF
        ) || parsed="ERROR:python3 falló"

        while IFS= read -r line; do
          [[ -z "$line" ]] && continue
          if [[ "$line" == TOTAL:* ]]; then
            mod_info "Total CVEs para kernel $kernel_base: ${line#TOTAL:}"
          elif [[ "$line" == ERROR:* ]]; then
            mod_info "No se pudieron parsear CVEs: ${line#ERROR:}"
          else
            # Campos separados por tabulador: sev  cve_id  score  summary
            local sev cve_id score summary
            IFS=$'\t' read -r sev cve_id score summary <<< "$line"
            [[ "$sev" == "CRITICAL" ]] \
              && mod_critical "CVE $cve_id [$score] — $summary" \
              || mod_warning  "CVE $cve_id [$score] — $summary"
          fi
        done <<< "$parsed"
      else
        local cve_count=0
        while IFS= read -r cve; do
          mod_warning "CVE detectado: $cve"
          cve_count=$((cve_count + 1))
        done < <(grep -oE '"cve_id"\s*:\s*"[^"]+"' "$cve_tmp" 2>/dev/null | grep -oE 'CVE-[0-9-]+' | head -10 || true)
        mod_info "CVEs encontrados: $cve_count (instala python3 para detalles de CVSS)"
      fi
    elif [[ "$http_code" == "000" ]]; then
      mod_info "Sin acceso a internet — verificar manualmente:"
      mod_info "  https://www.linuxkernelcves.com/cves?q=$kernel_base"
    else
      mod_warning "API CVE respondió HTTP $http_code — verificar manualmente"
    fi
  elif [[ -z "$kernel_base" ]]; then
    true
  else
    mod_info "curl no disponible — instalar con: apt install curl"
    mod_info "Verificar CVEs en: https://www.linuxkernelcves.com/cves"
  fi

  flush_module_json "Kernel y CVEs"
}

# ─── 8. NFS no_root_squash ────────────────────────────────────────────────────
check_nfs() {
  print_header "8. NFS — NO_ROOT_SQUASH"
  _MOD_FINDINGS=(); _MOD_WARNINGS=(); _MOD_INFOS=()

  if ! command -v showmount &>/dev/null && [[ ! -f /etc/exports ]]; then
    mod_info "NFS no parece estar instalado"
    flush_module_json "NFS"; return
  fi

  # Revisar /etc/exports (si somos servidor NFS)
  if [[ -f /etc/exports && -r /etc/exports ]]; then
    mod_info "Revisando /etc/exports..."
    while IFS= read -r line; do
      [[ "$line" =~ ^#.*$ || -z "$line" ]] && continue
      local share; share=$(echo "$line" | awk '{print $1}')

      if echo "$line" | grep -qi "no_root_squash"; then
        mod_critical "NFS share con no_root_squash: $share"
        mod_critical "  Config: $line"
        print_verbose "Exploit: mount -t nfs TARGET:$share /mnt && cp /bin/bash /mnt/ && chmod +s /mnt/bash"
      fi

      echo "$line" | grep -qi "no_all_squash" && \
        mod_warning "NFS con no_all_squash: $share — $line"

      echo "$line" | grep -q '\*' && \
        mod_warning "NFS expuesto a TODOS los hosts (*): $share" || true

      echo "$line" | grep -qiE '\brw\b' 2>/dev/null && echo "$line" | grep -q '\*' 2>/dev/null && \
        mod_critical "NFS con escritura abierta a todos (*rw): $share" || true

    done < /etc/exports
  else
    mod_info "/etc/exports no accesible o no existe"
  fi

  # Mounts NFS activos (como cliente)
  local nfs_mounts
  nfs_mounts=$(mount 2>/dev/null | grep -iE '\bnfs\b|\bnfs4\b' || true)
  if [[ -n "$nfs_mounts" ]]; then
    mod_info "Shares NFS montados:"
    while IFS= read -r mnt; do
      mod_info "  $mnt"
      echo "$mnt" | grep -qiE "nolock|no_root_squash|vers=2" 2>/dev/null && \
        mod_warning "Mount NFS con opciones inseguras: $mnt" || true
    done <<< "$nfs_mounts"
  else
    mod_ok "No hay shares NFS montados actualmente"
  fi

  # Listar exports locales con showmount
  if command -v showmount &>/dev/null; then
    local exports
    exports=$(showmount -e localhost 2>/dev/null || showmount -e 127.0.0.1 2>/dev/null || true)
    [[ -n "$exports" ]] && mod_info "Exports NFS expuestos:" && \
      while IFS= read -r line; do mod_info "  $line"; done <<< "$exports"
  fi

  flush_module_json "NFS"
}

# ─── 9. Historial Bash — contraseñas ─────────────────────────────────────────
check_bash_history() {
  print_header "9. HISTORIAL BASH — CONTRASEÑAS EXPUESTAS"
  _MOD_FINDINGS=(); _MOD_WARNINGS=(); _MOD_INFOS=()

  local pass_patterns=(
    '-p[[:space:]]+[^[:space:]]+'
    '--password[[:space:]=][^[:space:]]+'
    '--passwd[[:space:]=][^[:space:]]+'
    'PASS(WORD)?[[:space:]]*=[[:space:]]*\S+'
    'SECRET[[:space:]]*=[[:space:]]*\S+'
    'TOKEN[[:space:]]*=[[:space:]]*\S+'
    'API_KEY[[:space:]]*=[[:space:]]*\S+'
    'curl[[:space:]][^|]*(-u|--user)[[:space:]]+\S+'
    'sshpass[[:space:]]+-p[[:space:]]+\S+'
    '-passin[[:space:]]+pass:\S+'
    '-passout[[:space:]]+pass:\S+'
    'docker[[:space:]]+login[^|]*-p[[:space:]]+\S+'
    'aws[[:space:]]+configure[[:space:]]*.*--aws-secret'
    'PGPASSWORD=[^[:space:]]+'
    'MYSQL_PWD=[^[:space:]]+'
  )

  local history_files=()
  local current_hist="${HISTFILE:-$HOME/.bash_history}"
  [[ -f "$current_hist" ]] && history_files+=("$current_hist")

  for home_dir in /root /home/*; do
    for hist_file in \
      "$home_dir/.bash_history" \
      "$home_dir/.zsh_history" \
      "$home_dir/.sh_history" \
      "$home_dir/.fish/fish_history" \
      "$home_dir/.python_history" \
      "$home_dir/.mysql_history" \
      "$home_dir/.psql_history"; do
      local already=false
      for existing in "${history_files[@]+"${history_files[@]}"}"; do
        [[ "$existing" == "$hist_file" ]] && already=true && break
      done
      [[ -f "$hist_file" && -r "$hist_file" && "$already" == "false" ]] && \
        history_files+=("$hist_file")
    done
  done

  if [[ ${#history_files[@]} -eq 0 ]]; then
    mod_info "No se encontraron archivos de historial accesibles"
    flush_module_json "Historial Bash"; return
  fi

  local total_hits=0

  for hist_file in "${history_files[@]}"; do
    local file_hits=0
    mod_info "Revisando: $hist_file ($(wc -l < "$hist_file" 2>/dev/null || echo '?') líneas)"

    for pattern in "${pass_patterns[@]}"; do
      local matches
      matches=$(grep -iEo "$pattern" "$hist_file" 2>/dev/null | head -5 || true)
      if [[ -n "$matches" ]]; then
        while IFS= read -r match; do
          [[ -z "$match" ]] && continue
          # Redactar: conservar primeros 3 chars del valor, ocultar el resto
          local redacted
          redacted=$(echo "$match" | sed -E \
            's/([-=: ]+)([^[:space:]]{1,3})[^[:space:]]*/\1\2[REDACTED]/g')
          mod_critical "Posible credencial en $(basename "$hist_file"): $redacted"
          file_hits=$((file_hits + 1))
          total_hits=$((total_hits + 1))
        done <<< "$matches"
      fi
    done

    # Conteo de comandos sensibles adicionales
    for cmd_pattern in \
      "mysql[[:space:]].*-p" "mysqldump.*-p" "psql.*-[Ww]" \
      "sshpass" "net[[:space:]]use.*password" \
      "openssl.*-pass" "gpg.*--passphrase" \
      "ansible-vault" "vault[[:space:]]login"; do
      local hits
      hits=$(grep -icE "$cmd_pattern" "$hist_file" 2>/dev/null || echo "0")
      hits="${hits//[^0-9]/}"
      if [[ -n "$hits" && "$hits" -gt 0 ]]; then
        mod_warning "Comando sensible (${hits}x) en $(basename "$hist_file"): $cmd_pattern"
        file_hits=$((file_hits + hits))
        total_hits=$((total_hits + hits))
      fi
    done

    [[ $file_hits -eq 0 ]] && mod_ok "Sin hallazgos en $hist_file"
  done

  mod_info "Total de hallazgos en historiales: $total_hits"

  # Detectar intentos de ocultar el historial
  [[ "${HISTSIZE:-x}" == "0" || "${HISTFILESIZE:-x}" == "0" ]] && \
    mod_warning "HISTSIZE/HISTFILESIZE=0 — historial deshabilitado intencionalmente"

  [[ "${HISTFILE:-x}" == "/dev/null" ]] && \
    mod_warning "HISTFILE apunta a /dev/null — historial redirigido intencionalmente"

  flush_module_json "Historial Bash"
}

# ─── 10. Servicios y puertos ──────────────────────────────────────────────────
check_services() {
  print_header "10. SERVICIOS Y PUERTOS"
  _MOD_FINDINGS=(); _MOD_WARNINGS=(); _MOD_INFOS=()

  mod_info "Servicios escuchando localmente:"
  if command -v ss &>/dev/null; then
    while IFS= read -r line; do
      mod_info "  $line"
      # Detectar servicios escuchando en 0.0.0.0 (expuestos a toda la red)
      echo "$line" | grep -q "0\.0\.0\.0" && \
        mod_warning "Servicio expuesto a todas las interfaces: $line"
    done < <(ss -tlnp 2>/dev/null | tail -n +2 || true)
  elif command -v netstat &>/dev/null; then
    while IFS= read -r line; do
      mod_info "  $line"
    done < <(netstat -tlnp 2>/dev/null | grep -E "127\.0\.0\.1|0\.0\.0\.0" || true)
  else
    mod_info "ss y netstat no disponibles"
  fi

  if [[ -S /var/run/docker.sock ]]; then
    [[ -r /var/run/docker.sock || -w /var/run/docker.sock ]] \
      && mod_critical "Docker socket accesible — escalada a root posible vía contenedor" \
      || mod_warning "Docker socket existe pero no accesible"
  fi

  id -nG | grep -q "\bdocker\b" && \
    mod_critical "Usuario en grupo 'docker' — escalada a root posible"

  flush_module_json "Servicios"
}

# ─── 11. Variables de entorno y PATH ──────────────────────────────────────────
check_env() {
  print_header "11. VARIABLES DE ENTORNO Y PATH"
  _MOD_FINDINGS=(); _MOD_WARNINGS=(); _MOD_INFOS=()

  mod_info "PATH actual: $PATH"
  IFS=':' read -ra path_dirs <<< "$PATH"
  for dir in "${path_dirs[@]}"; do
    if [[ -d "$dir" && -w "$dir" ]]; then
      mod_critical "Directorio ESCRIBIBLE en PATH: $dir — PATH hijacking posible"
    elif [[ "$dir" == "." || -z "$dir" ]]; then
      mod_critical "PATH incluye '.' — PATH hijacking posible"
    fi
  done

  [[ -n "${LD_PRELOAD:-}" ]] \
    && mod_critical "LD_PRELOAD activo: $LD_PRELOAD" \
    || mod_ok "LD_PRELOAD no definido"

  [[ -n "${LD_LIBRARY_PATH:-}" ]] && mod_warning "LD_LIBRARY_PATH definido: $LD_LIBRARY_PATH"

  # Secrets en variables de entorno del proceso actual
  local env_secrets
  env_secrets=$(env 2>/dev/null | grep -iE \
    '(password|passwd|secret|token|api_key|private_key|aws_secret|db_pass)=' \
    | grep -v '^#' || true)
  if [[ -n "$env_secrets" ]]; then
    while IFS= read -r var; do
      local varname varval
      varname=$(echo "$var" | cut -d= -f1)
      varval=$(echo "$var" | cut -d= -f2-)
      # Mostrar solo primeros 4 chars del valor
      mod_critical "Secreto en entorno: ${varname}=${varval:0:4}[REDACTED]"
    done <<< "$env_secrets"
  else
    mod_ok "No se detectaron secretos obvios en variables de entorno"
  fi

  flush_module_json "Variables de entorno"
}

# ─── 12. Usuarios y cuentas ───────────────────────────────────────────────────
check_users() {
  print_header "12. USUARIOS Y CUENTAS"
  _MOD_FINDINGS=(); _MOD_WARNINGS=(); _MOD_INFOS=()

  local root_users root_count
  root_users=$(awk -F: '($3 == 0) {print $1}' /etc/passwd 2>/dev/null || true)
  root_count=$(echo "$root_users" | grep -c '[^[:space:]]' 2>/dev/null || echo "0")
  if [[ "$root_count" -gt 1 ]]; then
    mod_critical "Múltiples usuarios con UID 0: $root_users"
  else
    mod_ok "Un solo usuario con UID 0: root"
  fi

  if [[ -r /etc/shadow ]]; then
    local no_pass_users
    no_pass_users=$(awk -F: '($2 == "" || $2 == "!!" || $2 == "!") {print $1}' /etc/shadow 2>/dev/null || true)
    while IFS= read -r user; do
      [[ -n "$user" ]] && mod_critical "Usuario sin contraseña: $user"
    done <<< "$no_pass_users"
  else
    local no_pass_users
    no_pass_users=$(awk -F: '($2 == "") {print $1}' /etc/passwd 2>/dev/null || true)
    while IFS= read -r user; do
      [[ -n "$user" ]] && mod_warning "Posible usuario sin contraseña (según /etc/passwd): $user"
    done <<< "$no_pass_users"
  fi

  mod_info "Usuarios con shell interactiva:"
  while IFS= read -r line; do
    [[ -n "$line" ]] && mod_info "  $line"
  done < <(grep -vE "(/nologin|/false|/sync|/halt|/shutdown)$" /etc/passwd 2>/dev/null | \
    awk -F: '{print $1, "→ shell:", $7}' || true)

  flush_module_json "Usuarios"
}

# ─── 13. Escape de contenedores ───────────────────────────────────────────────
check_containers() {
  print_header "13. ESCAPE DE CONTENEDORES"
  _MOD_FINDINGS=(); _MOD_WARNINGS=(); _MOD_INFOS=()

  # ── Detectar si estamos dentro de un contenedor ──────────────────────────
  local in_container=false container_type="desconocido"

  if [[ -f /.dockerenv ]]; then
    in_container=true; container_type="Docker"
    mod_warning "Archivo /.dockerenv presente — ejecutando dentro de Docker"
  fi

  if grep -qE 'docker|lxc|containerd' /proc/1/cgroup 2>/dev/null; then
    in_container=true
    local cg_type
    cg_type=$(grep -oE 'docker|lxc|containerd' /proc/1/cgroup 2>/dev/null | head -1)
    container_type="${cg_type:-$container_type}"
    mod_warning "cgroup indica entorno de contenedor: $container_type"
  fi

  if [[ -f /proc/1/environ ]]; then
    grep -qz 'container=' /proc/1/environ 2>/dev/null && \
      mod_warning "Variable 'container=' detectada en PID 1 — posible contenedor systemd-nspawn"
  fi

  $in_container || mod_ok "No se detectaron indicadores de contenedor"

  # ── Contenedor privilegiado ───────────────────────────────────────────────
  if $in_container; then
    # --privileged: acceso completo a devices del host
    if [[ -d /dev && $(ls /dev/ 2>/dev/null | wc -l) -gt 50 ]]; then
      mod_critical "Gran cantidad de devices en /dev — posible contenedor --privileged"
      print_verbose "Exploit: montar disco del host vía /dev/sdX y acceder al FS"
    fi

    # cap_sys_admin dentro del contenedor
    if command -v capsh &>/dev/null; then
      capsh --print 2>/dev/null | grep -q "cap_sys_admin" && \
        mod_critical "cap_sys_admin activa dentro del contenedor — escape posible"
    fi

    # Namespace compartido con host (pid, network)
    local host_pid_ns container_pid_ns
    host_pid_ns=$(readlink /proc/1/ns/pid 2>/dev/null || echo "?")
    container_pid_ns=$(readlink /proc/$$/ns/pid 2>/dev/null || echo "?")
    [[ "$host_pid_ns" == "$container_pid_ns" && "$host_pid_ns" != "?" ]] && \
      mod_critical "Namespace PID compartido con el host — sin aislamiento de procesos"
  fi

  # ── Docker socket (dentro o fuera de contenedor) ───────────────────────────
  for sock in /var/run/docker.sock /run/docker.sock; do
    if [[ -S "$sock" ]]; then
      if [[ -w "$sock" ]]; then
        mod_critical "Docker socket escribible: $sock — escape a root posible"
        print_verbose "Exploit: docker run -v /:/host --rm -it alpine chroot /host"
      elif [[ -r "$sock" ]]; then
        mod_warning "Docker socket legible: $sock — enumeración de contenedores posible"
      fi
    fi
  done

  # ── Docker en el grupo del usuario ────────────────────────────────────────
  id -nG 2>/dev/null | grep -qw "docker" && \
    mod_critical "Usuario en grupo 'docker' — equivalente a root en el host"

  # ── Montajes peligrosos desde el host ─────────────────────────────────────
  if [[ -f /proc/mounts || -r /proc/mounts ]]; then
    while IFS= read -r mnt; do
      mod_critical "Sistema de archivos del host montado: $mnt"
    done < <(grep -E '^[^#].*\s/host' /proc/mounts 2>/dev/null || true)

    # /proc del host montado
    grep -q "proc /proc/host" /proc/mounts 2>/dev/null && \
      mod_critical "/proc del host montado — acceso a procesos del host"
  fi

  # ── Kubernetes: service account tokens ────────────────────────────────────
  local sa_token="/var/run/secrets/kubernetes.io/serviceaccount/token"
  if [[ -f "$sa_token" && -r "$sa_token" ]]; then
    mod_critical "Token de Kubernetes ServiceAccount legible: $sa_token"
    print_verbose "Usar: kubectl --token=\$(cat $sa_token) auth can-i --list"
    local sa_ns="/var/run/secrets/kubernetes.io/serviceaccount/namespace"
    [[ -f "$sa_ns" ]] && mod_info "Namespace K8s: $(cat "$sa_ns" 2>/dev/null)"
  fi

  # ── containerd / podman sockets ───────────────────────────────────────────
  for sock in /run/containerd/containerd.sock /run/podman/podman.sock; do
    [[ -S "$sock" && -w "$sock" ]] && \
      mod_critical "Socket de runtime escribible: $sock — escape posible"
  done

  flush_module_json "Contenedores"
}

# ─── 14. Credenciales IMDS de cloud ──────────────────────────────────────────
check_cloud_imds() {
  print_header "14. CREDENCIALES CLOUD — IMDS"
  _MOD_FINDINGS=(); _MOD_WARNINGS=(); _MOD_INFOS=()

  if ! command -v curl &>/dev/null; then
    mod_info "curl no disponible — omitiendo checks de IMDS"
    flush_module_json "Cloud IMDS"; return
  fi

  local curl_opts="-s --max-time 3 --connect-timeout 2"

  # ── AWS IMDS v1 / v2 ─────────────────────────────────────────────────────
  mod_info "Probando AWS IMDS (169.254.169.254)..."

  # IMDSv1 (sin token — inseguro)
  local aws_v1
  aws_v1=$(curl $curl_opts "http://169.254.169.254/latest/meta-data/" 2>/dev/null || true)
  if [[ -n "$aws_v1" ]]; then
    mod_critical "AWS IMDSv1 accesible SIN token (inseguro) — metadatos expuestos"
    # Intentar obtener credenciales del rol IAM
    local iam_role
    iam_role=$(curl $curl_opts \
      "http://169.254.169.254/latest/meta-data/iam/security-credentials/" 2>/dev/null || true)
    if [[ -n "$iam_role" ]]; then
      mod_critical "Rol IAM encontrado: $iam_role"
      local creds
      creds=$(curl $curl_opts \
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/${iam_role}" 2>/dev/null || true)
      if echo "$creds" | grep -q "AccessKeyId" 2>/dev/null; then
        mod_critical "Credenciales AWS IAM accesibles vía IMDS para rol: $iam_role"
        print_verbose "Credenciales temporales de AWS expuestas — pueden usarse para movimiento lateral"
      fi
    else
      mod_warning "AWS IMDSv1 accesible pero sin rol IAM configurado"
    fi
    local region
    region=$(curl $curl_opts \
      "http://169.254.169.254/latest/meta-data/placement/region" 2>/dev/null || true)
    [[ -n "$region" ]] && mod_info "Región AWS: $region"
  fi

  # IMDSv2 (con token — más seguro, pero aún informativo si está activo)
  local aws_token
  aws_token=$(curl $curl_opts -X PUT \
    -H "X-aws-ec2-metadata-token-ttl-seconds: 10" \
    "http://169.254.169.254/latest/api/token" 2>/dev/null || true)
  if [[ -n "$aws_token" && -z "$aws_v1" ]]; then
    mod_warning "AWS IMDSv2 activo (requiere token PUT) — más seguro que v1"
    mod_info "Para revisar manualmente: curl -H 'X-aws-ec2-metadata-token: \$TOKEN' http://169.254.169.254/latest/meta-data/"
  fi

  [[ -z "$aws_v1" && -z "$aws_token" ]] && mod_ok "AWS IMDS no accesible"

  # ── GCP Metadata Server ───────────────────────────────────────────────────
  mod_info "Probando GCP Metadata Server (metadata.google.internal)..."
  local gcp_meta
  gcp_meta=$(curl $curl_opts \
    -H "Metadata-Flavor: Google" \
    "http://metadata.google.internal/computeMetadata/v1/instance/" 2>/dev/null || true)
  if [[ -n "$gcp_meta" ]]; then
    mod_critical "GCP Metadata Server accesible — instancia en Google Cloud"
    local gcp_token
    gcp_token=$(curl $curl_opts \
      -H "Metadata-Flavor: Google" \
      "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" \
      2>/dev/null || true)
    if echo "$gcp_token" | grep -q "access_token" 2>/dev/null; then
      mod_critical "Token de servicio GCP accesible — credenciales de cuenta de servicio expuestas"
      print_verbose "Token puede usarse contra la API de Google Cloud"
    fi
    local gcp_email
    gcp_email=$(curl $curl_opts \
      -H "Metadata-Flavor: Google" \
      "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email" \
      2>/dev/null || true)
    [[ -n "$gcp_email" ]] && mod_info "Service account GCP: $gcp_email"
  else
    mod_ok "GCP Metadata Server no accesible"
  fi

  # ── Azure IMDS ────────────────────────────────────────────────────────────
  mod_info "Probando Azure IMDS (169.254.169.254/metadata/instance)..."
  local azure_meta
  azure_meta=$(curl $curl_opts \
    -H "Metadata: true" \
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01" 2>/dev/null || true)
  if [[ -n "$azure_meta" ]] && echo "$azure_meta" | grep -q "subscriptionId" 2>/dev/null; then
    mod_critical "Azure IMDS accesible — instancia en Microsoft Azure"
    local az_token
    az_token=$(curl $curl_opts \
      -H "Metadata: true" \
      "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" \
      2>/dev/null || true)
    if echo "$az_token" | grep -q "access_token" 2>/dev/null; then
      mod_critical "Token Managed Identity de Azure accesible — credenciales expuestas"
      print_verbose "Token puede usarse contra la API de Azure Resource Manager"
    fi
  else
    mod_ok "Azure IMDS no accesible"
  fi

  # ── Credenciales cloud en archivos locales ────────────────────────────────
  mod_info "Buscando credenciales cloud en archivos locales..."
  local cloud_files=(
    "$HOME/.aws/credentials"
    "$HOME/.aws/config"
    "$HOME/.config/gcloud/credentials.db"
    "$HOME/.config/gcloud/application_default_credentials.json"
    "$HOME/.azure/azureProfile.json"
    "$HOME/.azure/accessTokens.json"
    /etc/boto.cfg
    /etc/s3cfg
  )

  for cf in "${cloud_files[@]}"; do
    if [[ -f "$cf" && -r "$cf" ]]; then
      mod_critical "Archivo de credenciales cloud legible: $cf"
      # Buscar claves de acceso sin mostrar valores completos
      if grep -qiE "(access_key|secret_key|token|client_secret)" "$cf" 2>/dev/null; then
        mod_critical "  Contiene claves de acceso: $cf"
      fi
    fi
  done

  flush_module_json "Cloud IMDS"
}

# ─── 15. Systemd units escribibles ────────────────────────────────────────────
check_systemd() {
  print_header "15. SYSTEMD — UNITS Y TIMERS ESCRIBIBLES"
  _MOD_FINDINGS=(); _MOD_WARNINGS=(); _MOD_INFOS=()

  if ! command -v systemctl &>/dev/null; then
    mod_info "systemd no disponible en este sistema"
    flush_module_json "Systemd"; return
  fi

  local unit_dirs=(
    /etc/systemd/system
    /lib/systemd/system
    /usr/lib/systemd/system
    /run/systemd/system
    "$HOME/.config/systemd/user"
  )

  mod_info "Revisando units y timers de systemd..."

  for dir in "${unit_dirs[@]}"; do
    [[ -d "$dir" ]] || continue

    # Buscar units y timers escribibles
    while IFS= read -r unit_file; do
      [[ -z "$unit_file" ]] && continue
      mod_critical "Unit systemd ESCRIBIBLE: $unit_file"
      print_verbose "Modificar ExecStart= en $unit_file y recargar con: systemctl daemon-reload"

      # Buscar el binario que ejecuta el servicio
      local exec_start
      exec_start=$(grep -oP '(?<=ExecStart=)[^\s]+' "$unit_file" 2>/dev/null | head -1 || true)
      if [[ -n "$exec_start" && -f "$exec_start" && -w "$exec_start" ]]; then
        mod_critical "  Binario ejecutado también escribible: $exec_start"
      fi
    done < <(find "$dir" -maxdepth 2 -type f \( -name "*.service" -o -name "*.timer" \) \
      -writable 2>/dev/null || true)
  done

  # Binarios referenciados en units activos que sean escribibles
  mod_info "Revisando binarios de servicios activos..."
  local active_units
  active_units=$(systemctl list-units --type=service --state=running \
    --no-pager --plain 2>/dev/null | awk '{print $1}' | grep "\.service$" || true)

  local checked=0
  while IFS= read -r unit; do
    [[ -z "$unit" ]] && continue
    [[ $checked -ge 30 ]] && break  # limitar para no tardar demasiado
    local exec_path
    exec_path=$(systemctl show "$unit" --property=ExecStart 2>/dev/null | \
      grep -oP '(?<=path=)[^;]+' | head -1 || true)
    if [[ -n "$exec_path" && -f "$exec_path" && -w "$exec_path" ]]; then
      mod_critical "Binario de servicio activo ESCRIBIBLE: $exec_path (servicio: $unit)"
    fi
    checked=$((checked + 1))
  done <<< "$active_units"

  # Timers activos (equivalente a cron)
  mod_info "Timers systemd activos:"
  while IFS= read -r line; do
    [[ -n "$line" ]] && mod_info "  $line"
  done < <(systemctl list-timers --no-pager --plain 2>/dev/null | head -20 || true)

  # Polkit — reglas escribibles o inseguras
  if [[ -d /etc/polkit-1/rules.d ]]; then
    mod_info "Revisando reglas Polkit..."
    while IFS= read -r rule; do
      mod_critical "Regla Polkit ESCRIBIBLE: $rule"
    done < <(find /etc/polkit-1/rules.d -type f -writable 2>/dev/null || true)

    # Reglas que conceden acceso sin autenticación
    while IFS= read -r rule; do
      if grep -qiE '(return\s+polkit\.Result\.(YES|AUTH_ADMIN_KEEP))|allow_any.*yes' "$rule" 2>/dev/null; then
        mod_critical "Regla Polkit permisiva detectada: $rule"
        print_verbose "Revisar manualmente el contenido de: $rule"
      fi
    done < <(find /etc/polkit-1 -name "*.rules" 2>/dev/null || true)
  fi

  # pkexec versión (CVE-2021-4034 PwnKit)
  if command -v pkexec &>/dev/null; then
    local pkexec_ver
    pkexec_ver=$(pkexec --version 2>/dev/null | grep -oP '[\d.]+' | head -1 || echo "?")
    mod_info "pkexec versión: $pkexec_ver"
    # PwnKit afecta versiones < 0.120
    if [[ "$pkexec_ver" != "?" ]]; then
      local major minor
      major=$(echo "$pkexec_ver" | cut -d. -f1)
      minor=$(echo "$pkexec_ver" | cut -d. -f2 || echo "0")
      if [[ "$major" -eq 0 && "${minor:-0}" -lt 120 ]] 2>/dev/null; then
        mod_critical "pkexec < 0.120 — potencialmente vulnerable a CVE-2021-4034 (PwnKit)"
        print_verbose "https://blog.qualys.com/vulnerabilities-threat-research/2022/01/25/pwnkit"
      else
        mod_ok "pkexec versión $pkexec_ver (no vulnerable a PwnKit)"
      fi
    fi
  fi

  flush_module_json "Systemd"
}

# ─── 16. PAM backdoors y authorized_keys ─────────────────────────────────────
check_pam_and_ssh_keys() {
  print_header "16. PAM BACKDOORS Y AUTHORIZED_KEYS"
  _MOD_FINDINGS=(); _MOD_WARNINGS=(); _MOD_INFOS=()

  # ── Módulos PAM ────────────────────────────────────────────────────────────
  mod_info "Revisando configuración PAM..."

  if [[ -d /etc/pam.d ]]; then
    # Módulos PAM no estándar o sospechosos
    local known_pam_modules=(
      "pam_unix" "pam_ldap" "pam_sss" "pam_krb5" "pam_winbind"
      "pam_env" "pam_limits" "pam_nologin" "pam_securetty"
      "pam_rootok" "pam_deny" "pam_permit" "pam_warn"
      "pam_faillock" "pam_tally2" "pam_lastlog" "pam_motd"
      "pam_mail" "pam_umask" "pam_systemd" "pam_cap"
      "pam_google_authenticator" "pam_duo" "pam_radius"
      "pam_mkhomedir" "pam_access" "pam_time" "pam_succeed_if"
      "pam_listfile" "pam_group" "pam_pwquality" "pam_cracklib"
    )

    while IFS= read -r pam_file; do
      [[ -f "$pam_file" && -r "$pam_file" ]] || continue

      # Detectar "pam_permit" en servicios críticos (acceso sin contraseña)
      if grep -qE '^[^#]*auth[[:space:]]+sufficient[[:space:]]+pam_permit' "$pam_file" 2>/dev/null; then
        mod_critical "PAM BACKDOOR: pam_permit sufficient en auth — acceso sin contraseña en $pam_file"
      fi

      # Módulos custom (no en /lib/security ni /lib64/security)
      while IFS= read -r mod_line; do
        local pam_mod
        pam_mod=$(echo "$mod_line" | grep -oP '[a-z0-9_]+\.so' | head -1 || true)
        [[ -z "$pam_mod" ]] && continue
        local mod_name="${pam_mod%.so}"
        local is_known=false
        for km in "${known_pam_modules[@]}"; do
          [[ "$mod_name" == "$km" ]] && is_known=true && break
        done
        if ! $is_known; then
          # Buscar el .so en rutas no estándar
          local found_in
          found_in=$(find /lib /lib64 /usr/lib /usr/lib64 -name "$pam_mod" 2>/dev/null | head -1 || true)
          if [[ -z "$found_in" ]]; then
            mod_critical "Módulo PAM desconocido en $pam_file: $pam_mod (no encontrado en rutas estándar)"
          else
            mod_warning "Módulo PAM no estándar: $pam_mod en $pam_file"
          fi
        fi
      done < <(grep -vE '^\s*#' "$pam_file" 2>/dev/null | grep -E '\.so' || true)

    done < <(find /etc/pam.d -type f 2>/dev/null | sort)

    # Archivos PAM escribibles
    while IFS= read -r f; do
      mod_critical "Archivo PAM ESCRIBIBLE: $f — backdoor posible"
    done < <(find /etc/pam.d -type f -writable 2>/dev/null || true)

    # Módulos PAM .so escribibles
    for lib_dir in /lib/security /lib64/security /usr/lib/security /usr/lib64/security; do
      [[ -d "$lib_dir" ]] || continue
      while IFS= read -r so; do
        mod_critical "Módulo PAM .so ESCRIBIBLE: $so — puede reemplazarse para capturar contraseñas"
      done < <(find "$lib_dir" -name "*.so" -writable 2>/dev/null || true)
    done
  else
    mod_info "/etc/pam.d no encontrado"
  fi

  # ── authorized_keys ────────────────────────────────────────────────────────
  mod_info "Revisando authorized_keys de todos los usuarios..."

  local ssh_dirs=()
  for home_dir in /root /home/*; do
    [[ -d "$home_dir/.ssh" ]] && ssh_dirs+=("$home_dir/.ssh")
  done

  if [[ ${#ssh_dirs[@]} -eq 0 ]]; then
    mod_ok "No se encontraron directorios .ssh"
  else
    for ssh_dir in "${ssh_dirs[@]}"; do
      local auth_keys="$ssh_dir/authorized_keys"
      local auth_keys2="$ssh_dir/authorized_keys2"

      for ak_file in "$auth_keys" "$auth_keys2"; do
        [[ -f "$ak_file" && -r "$ak_file" ]] || continue

        local key_count
        key_count=$(grep -c '^ssh-\|^ecdsa-\|^sk-' "$ak_file" 2>/dev/null || echo "0")
        mod_info "$ak_file: $key_count clave(s)"

        # Claves con opciones peligrosas
        while IFS= read -r key_line; do
          [[ -z "$key_line" || "$key_line" =~ ^# ]] && continue

          if echo "$key_line" | grep -qiE '^(no-pty|command=|from=|tunnel=|permitopen=)' 2>/dev/null; then
            mod_warning "Clave con restricciones en $ak_file: ${key_line:0:80}"
          fi

          # command= forzado — puede ser backdoor si el comando es sospechoso
          if echo "$key_line" | grep -qiE '^command="' 2>/dev/null; then
            local forced_cmd
            forced_cmd=$(echo "$key_line" | grep -oP '(?<=command=")[^"]+')
            mod_warning "Clave con command forzado en $ak_file: $forced_cmd"
            echo "$forced_cmd" | grep -qiE '(sh|bash|nc|socat|python|perl|ruby|/tmp)' && \
              mod_critical "  Comando forzado potencialmente malicioso: $forced_cmd"
          fi
        done < "$ak_file"

        # Permisos del archivo authorized_keys
        local ak_perms
        ak_perms=$(stat -c '%a' "$ak_file" 2>/dev/null || echo "?")
        if [[ "$ak_perms" != "600" && "$ak_perms" != "644" ]]; then
          mod_warning "Permisos inusuales en $ak_file: $ak_perms (esperado: 600)"
        fi

        # Archivo escribible por otros
        [[ -w "$ak_file" ]] && ! [[ "$(stat -c '%U' "$ak_file")" == "$(whoami)" ]] && \
          mod_critical "$ak_file es ESCRIBIBLE — inyección de clave SSH posible"
      done

      # Permisos del directorio .ssh
      local ssh_perms
      ssh_perms=$(stat -c '%a' "$ssh_dir" 2>/dev/null || echo "?")
      if [[ "$ssh_perms" != "700" ]]; then
        mod_warning "Permisos débiles en $ssh_dir: $ssh_perms (esperado: 700)"
      fi
    done
  fi

  # Configuración sshd_allow insegura
  if [[ -f /etc/ssh/sshd_config && -r /etc/ssh/sshd_config ]]; then
    mod_info "Revisando sshd_config..."

    grep -iE '^\s*PermitRootLogin\s+yes' /etc/ssh/sshd_config 2>/dev/null && \
      mod_critical "sshd: PermitRootLogin yes — root puede acceder directamente por SSH"

    grep -iE '^\s*PermitEmptyPasswords\s+yes' /etc/ssh/sshd_config 2>/dev/null && \
      mod_critical "sshd: PermitEmptyPasswords yes — acceso sin contraseña permitido"

    grep -iE '^\s*PasswordAuthentication\s+yes' /etc/ssh/sshd_config 2>/dev/null && \
      mod_warning "sshd: PasswordAuthentication yes — ataques de fuerza bruta posibles"

    grep -iE '^\s*X11Forwarding\s+yes' /etc/ssh/sshd_config 2>/dev/null && \
      mod_warning "sshd: X11Forwarding yes — puede facilitar movimiento lateral"
  fi

  flush_module_json "PAM y authorized_keys"
}



# ─── Resumen final ────────────────────────────────────────────────────────────
print_summary() {
  echo ""
  echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════╗${RESET}"
  echo -e "${BOLD}${CYAN}║           RESUMEN DE AUDITORÍA           ║${RESET}"
  echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════╝${RESET}"
  echo ""
  echo -e "  ${RED}Hallazgos críticos  : ${#FINDINGS[@]}${RESET}"
  echo -e "  ${YELLOW}Advertencias        : ${#WARNINGS[@]}${RESET}"
  echo -e "  ${CYAN}Informacional       : ${#INFOS[@]}${RESET}"
  echo ""

  if [[ ${#FINDINGS[@]} -gt 0 ]]; then
    echo -e "${BOLD}${RED}── CRÍTICOS ──────────────────────────────${RESET}"
    for f in "${FINDINGS[@]}"; do echo -e "  ${RED}▶${RESET} $f"; done
    echo ""
  fi

  if [[ ${#WARNINGS[@]} -gt 0 ]]; then
    echo -e "${BOLD}${YELLOW}── ADVERTENCIAS ──────────────────────────${RESET}"
    for w in "${WARNINGS[@]}"; do echo -e "  ${YELLOW}▶${RESET} $w"; done
    echo ""
  fi

  echo -e "  ${DIM}SHA256 del script: $SCRIPT_SHA256${RESET}"
  echo ""
  echo -e "${BOLD}${GREEN}Auditoría completada: $TIMESTAMP${RESET}"
  echo -e "${CYAN}Referencias: https://gtfobins.github.io | https://book.hacktricks.xyz${RESET}"
  echo ""
}

# ─── Exportar JSON ────────────────────────────────────────────────────────────
export_json() {
  local json_path="$1"

  local modules_str="" first=true
  for mod in "${JSON_MODULES[@]}"; do
    $first || modules_str+=","
    modules_str+="$mod"
    first=false
  done

  cat > "$json_path" <<EOF
{
  "report": {
    "tool": "roothunter.sh",
    "version": "1.1.0",
    "timestamp": "$TIMESTAMP_ISO",
    "script_sha256": "$SCRIPT_SHA256",
    "target": {
      "hostname": "$(json_escape "$(hostname 2>/dev/null || echo '?')")",
      "kernel": "$(json_escape "$(uname -r)")",
      "os": "$(json_escape "$(grep -oP '(?<=^PRETTY_NAME=").+(?=")' /etc/os-release 2>/dev/null || uname -s)")",
      "user": "$(whoami)",
      "uid": $(id -u),
      "groups": "$(json_escape "$(id -Gn)")"
    },
    "summary": {
      "critical": ${#FINDINGS[@]},
      "warnings": ${#WARNINGS[@]},
      "info": ${#INFOS[@]}
    },
    "modules": [
      $modules_str
    ]
  }
}
EOF

  # Pretty-print si python3 está disponible
  if command -v python3 &>/dev/null; then
    python3 -c "
import json
with open('$json_path') as f: data = json.load(f)
with open('$json_path', 'w') as f: json.dump(data, f, indent=2, ensure_ascii=False)
" 2>/dev/null && echo -e "  ${GREEN}JSON validado y formateado${RESET}" || true
  fi

  echo -e "  ${GREEN}Reporte JSON guardado en: $json_path${RESET}"
}

# ─── Main ─────────────────────────────────────────────────────────────────────
main() {
  echo -e "${BOLD}${CYAN}"
  echo "  ██████╗  ██████╗  ██████╗ ████████╗██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ "
  echo "  ██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗"
  echo "  ██████╔╝██║   ██║██║   ██║   ██║   ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝"
  echo "  ██╔══██╗██║   ██║██║   ██║   ██║   ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗"
  echo "  ██║  ██║╚██████╔╝╚██████╔╝   ██║   ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║"
  echo "  ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝"
  echo -e "${RESET}"
  echo -e "${BOLD}  Script de Auditoría de Seguridad Linux v1.1.0${RESET}"
  echo -e "  ${YELLOW}⚠  Usar solo en sistemas con autorización explícita${RESET}"
  [[ -n "$SELECTED_MODULES" ]] && \
    echo -e "  ${CYAN}Módulos seleccionados: $SELECTED_MODULES${RESET}"
  echo ""

  # Definir lista de módulos a ejecutar
  declare -A ALL_MODULES=(
    [sysinfo]="check_system_info:Información del sistema:20"
    [suid]="check_suid_sgid:SUID/SGID:120"
    [sudo]="check_sudo:Sudo:15"
    [cron]="check_cron:Cron:15"
    [files]="check_file_permissions:Permisos de archivos:30"
    [caps]="check_capabilities:Capabilities:30"
    [kernel]="check_kernel:Kernel y CVEs:20"
    [nfs]="check_nfs:NFS:15"
    [history]="check_bash_history:Historial bash:20"
    [services]="check_services:Servicios:15"
    [env]="check_env:Variables de entorno:10"
    [users]="check_users:Usuarios:10"
    [containers]="check_containers:Contenedores:20"
    [cloud]="check_cloud_imds:Cloud IMDS:30"
    [systemd]="check_systemd:Systemd:30"
    [pam]="check_pam_and_ssh_keys:PAM y SSH keys:20"
  )

  local MODULE_ORDER=(
    sysinfo suid sudo cron files caps kernel nfs
    history services env users containers cloud systemd pam
  )

  # Ejecutar módulos
  for key in "${MODULE_ORDER[@]}"; do
    _module_enabled "$key" || continue
    local spec="${ALL_MODULES[$key]}"
    local fn="${spec%%:*}"
    local rest="${spec#*:}"
    local label="${rest%%:*}"
    local tmo="${rest##*:}"
    _run_module "$fn" "$label" "$tmo"
  done

  print_summary
}

# ─── Entry point ──────────────────────────────────────────────────────────────
if [[ -n "$OUTPUT_FILE" ]]; then
  main 2>&1 | tee >(sed 's/\x1b\[[0-9;]*m//g' > "$OUTPUT_FILE")
  echo -e "${GREEN}Reporte texto guardado en: $OUTPUT_FILE${RESET}"
else
  main
fi

# JSON siempre se exporta fuera del pipe para tener acceso a las variables globales
[[ -n "$JSON_FILE" ]] && export_json "$JSON_FILE"
