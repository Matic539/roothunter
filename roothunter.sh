#!/usr/bin/env bash
# =============================================================================
#  roothunter.sh — Script de Auditoría de Seguridad Linux v1.2.4
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

# Findings estructurados (nuevo schema v2). Cada elemento es un JSON-object string.
# Se acumulan globalmente y también por módulo para mantener compatibilidad.
STRUCTURED_FINDINGS=()
_MOD_STRUCTURED=()

# ─── Cache de identidad del usuario ───────────────────────────────────────────
# Estos valores no cambian durante la ejecución. Cachearlos evita decenas de
# forks de whoami/id en módulos que comparan owner de archivos.
CURRENT_USER=$(whoami 2>/dev/null || echo "?")
CURRENT_UID=$(id -u 2>/dev/null || echo "?")
CURRENT_GID=$(id -g 2>/dev/null || echo "?")
CURRENT_GROUPS=$(id -Gn 2>/dev/null || echo "?")

# ─── Lookup O(1) de SUID peligrosos ───────────────────────────────────────────
# Antes: loop O(n) por cada SUID detectado contra ~60 nombres → O(n*60) forks/comparaciones.
# Ahora: hash de bash, O(1) por SUID. En sistemas con 50 SUIDs son ~3000 → 50.
declare -gA DANGEROUS_SUID=(
  [nmap]=1 [vim]=1 [vi]=1 [nano]=1 [find]=1 [bash]=1 [sh]=1 [dash]=1
  [less]=1 [more]=1 [awk]=1 [gawk]=1 [python]=1 [python3]=1 [perl]=1
  [ruby]=1 [lua]=1 [env]=1 [tee]=1 [cp]=1 [mv]=1 [chmod]=1 [chown]=1
  [dd]=1 [tar]=1 [zip]=1 [unzip]=1 [curl]=1 [wget]=1 [nc]=1 [netcat]=1
  [ncat]=1 [socat]=1 [tcpdump]=1 [strace]=1 [ltrace]=1 [gdb]=1 [node]=1
  [php]=1 [man]=1 [ftp]=1 [tftp]=1 [ssh]=1 [scp]=1 [rsync]=1 [docker]=1
  [lxc]=1 [runc]=1 [kubectl]=1 [git]=1 [make]=1 [gcc]=1 [mysql]=1
  [sqlite3]=1 [psql]=1 [mongod]=1 [redis-cli]=1 [openssl]=1 [pkexec]=1
  [su]=1 [sudo]=1 [passwd]=1 [snap]=1 [pip]=1 [pip3]=1 [irb]=1
  [lua5.1]=1 [lua5.2]=1 [lua5.3]=1 [expect]=1 [ionice]=1 [nice]=1
  [taskset]=1 [time]=1 [timeout]=1 [watch]=1
)



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
  echo -e "${BOLD}Uso:${RESET} $0 [-o archivo.txt] [-j archivo.json] [-m módulos] [-v] [-V] [-h]"
  echo ""
  echo "  -o  Guardar reporte en texto plano"
  echo "  -j  Exportar reporte en JSON"
  echo "  -v  Modo verbose (referencias GTFOBins / HackTricks)"
  echo "  -V  Verificar vectores: ejecuta precondition+capability de"
  echo "      gtfobins.py para SUID/sudo/capabilities detectados, marcando"
  echo "      'verified=true' en el JSON cuando el vector es real (opt-in)."
  echo "      Alias largo: --verify-vectors"
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
  echo "  processes → Procesos root, sockets unix, configs shell (nuevo)"
  echo ""
  echo -e "${BOLD}Ejemplos:${RESET}"
  echo "  bash $0 -m suid,sudo,kernel"
  echo "  bash $0 -o reporte.txt -j reporte.json -v"
  echo ""
  echo -e "${BOLD}Ejemplos recomendados:${RESET}"
  echo "  bash $0 -V -j reporte.json"
  echo ""
  exit 0
}

# Variables globales (resto)
VERIFY_VECTORS=false

# Pre-procesamiento: convertir long options a short antes de getopts
# (bash getopts no soporta long options nativamente)
ARGS=()
for arg in "$@"; do
  case "$arg" in
    --verify-vectors) ARGS+=("-V") ;;
    --help)           ARGS+=("-h") ;;
    --verbose)        ARGS+=("-v") ;;
    *)                ARGS+=("$arg") ;;
  esac
done
set -- "${ARGS[@]}"

while getopts ":o:j:m:vVh" opt; do
  case $opt in
    o) OUTPUT_FILE="$OPTARG" ;;
    j) JSON_FILE="$OPTARG" ;;
    m) SELECTED_MODULES="$OPTARG" ;;
    v) VERBOSE=true ;;
    V) VERIFY_VECTORS=true ;;
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

# add_finding: registra un hallazgo estructurado.
# Uso:
#   add_finding <type> <severity> <message> [key1=value1] [key2=value2] ...
#
# severity: critical | warning | info
# El finding se acumula tanto en STRUCTURED_FINDINGS (global) como en
# _MOD_STRUCTURED (por módulo, para volcar al JSON del módulo en flush).
#
# Esta función NO imprime nada — la impresión sigue siendo responsabilidad
# de mod_critical/mod_warning/mod_info para mantener compatibilidad textual.
add_finding() {
  local type="$1"; shift
  local severity="$1"; shift
  local message="$1"; shift

  local data_json="{" first=true
  for kv in "$@"; do
    local k="${kv%%=*}" v="${kv#*=}"
    [[ "$k" == "$kv" ]] && continue  # no '=' en el arg, lo ignoramos
    $first || data_json+=","
    data_json+="\"$(json_escape "$k")\":\"$(json_escape "$v")\""
    first=false
  done
  data_json+="}"

  local finding_json
  finding_json="{\"type\":\"$(json_escape "$type")\",\"severity\":\"$(json_escape "$severity")\",\"message\":\"$(json_escape "$message")\",\"data\":$data_json}"

  STRUCTURED_FINDINGS+=("$finding_json")
  _MOD_STRUCTURED+=("$finding_json")
}

# ─── Verificación de vectores (opt-in, --verify-vectors) ──────────────────────
# Cuando -V está activo, ejecutamos los niveles 'precondition' y 'capability'
# de gtfobins.py para confirmar que el vector es real, no solo posible.
#
# Requisitos:
#   - python3 disponible en el host
#   - gtfobins.py presente en el mismo directorio que este script
#
# El resultado se devuelve como string serializable que se mete en data:
#   verified=true|false|unknown
#   verified_at_level=precondition|capability|none
#   verify_output=<primera línea del output del último chequeo>
#
# Si gtfobins.py no está accesible, devolvemos verified=unknown sin error.

# Path de gtfobins.py: mismo directorio que el script
_GTFOBINS_PATH=""
_init_gtfobins_path() {
  local script_dir
  script_dir=$(dirname "$(readlink -f "$0" 2>/dev/null || echo "$0")")
  if [[ -f "$script_dir/lib/gtfobins.py" ]]; then
    _GTFOBINS_PATH="$script_dir/lib/gtfobins.py"
  elif [[ -f "$script_dir/gtfobins.py" ]]; then
    # Fallback compat: gtfobins.py al lado del script (estructura antigua)
    _GTFOBINS_PATH="$script_dir/gtfobins.py"
  fi
}
_init_gtfobins_path

# _verify_vector — intenta verificar precondition y capability para
#   un vector dado. Argumentos:
#     $1 = kind ('suid' | 'sudo' | 'capability')
#     $2 = binary (nombre del binario, ej 'find', 'python3')
#     $3 = (opcional) capability name si kind=capability (ej 'cap_setuid')
#
# Imprime tres líneas en stdout:
#     verified=true|false|unknown
#     verified_at_level=precondition|capability|none
#     verify_output=<una línea>
#
# Lógica:
#   - precondition: el output debe matchear el patrón esperado
#     (para SUID: stat debe mostrar bit 4xxx, no 0755)
#   - capability: idem (debe ver CAPABILITY_OK o equivalente)
#   - Si precondition falla, vector NO viable → verified=false
#   - Si precondition pasa pero capability falla, viable parcial → verified=true (precondition)
#   - Si ambos pasan, vector confirmado → verified=true (capability)
_verify_vector() {
  local kind="$1"
  local binary="$2"
  local cap_name="${3:-}"

  if [[ -z "$_GTFOBINS_PATH" ]] || ! command -v python3 &>/dev/null; then
    echo "verified=unknown"
    echo "verified_at_level=none"
    echo "verify_output=gtfobins.py o python3 no disponible"
    return
  fi

  # Pedimos a python3 los comandos para los niveles precondition + capability,
  # más el patrón esperado de cada uno.
  local cmds_tmp
  cmds_tmp=$(_tmp_file)
  python3 - "$_GTFOBINS_PATH" "$kind" "$binary" "$cap_name" > "$cmds_tmp" 2>/dev/null <<'PYEOF'
import sys, importlib.util
gtf_path, kind, binary, cap_name = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
spec = importlib.util.spec_from_file_location('gtfobins', gtf_path)
g = importlib.util.module_from_spec(spec); spec.loader.exec_module(g)

if kind == 'suid':
    tech = g.SUID.get(binary)
elif kind == 'sudo':
    tech = g.SUDO.get(binary)
elif kind == 'capability':
    cap = g.CAPABILITIES.get(cap_name, {})
    tech = cap.get('exploits', {}).get(binary)
else:
    tech = None

if not tech:
    sys.exit(0)

# Imprimir cada nivel en formato "level<TAB>cmd<TAB>expected"
for level, cmd, expected in g.get_verify_levels(tech):
    if level in ('precondition', 'capability'):
        clean_cmd = cmd.replace('\t', ' ')
        clean_exp = (expected or '').replace('\t', ' ')
        print(f"{level}\t{clean_cmd}\t{clean_exp}")
PYEOF

  # Lógica de validación por nivel:
  # Para cada nivel evaluamos si el output indica un match real:
  #
  # - precondition para SUID/sudo: el comando es típicamente stat o sudo -nl
  #   con un grep. Output válido = línea NO vacía. Pero para SUID de stat,
  #   debemos chequear que el modo tenga bit '4' en el dígito SUID.
  #
  # - capability: sale "CAPABILITY_OK" u "OK" en stdout.
  #
  # Estrategia simple: extraemos un "expected_pattern" del campo expected
  # de gtfobins. Por ahora aplicamos heurísticas:
  #   * Si expected menciona "4xxx" → el output debe contener "4" en posición
  #     correcta del modo (stat output).
  #   * Si expected menciona "CAPABILITY_OK" → el output debe contenerlo.
  #   * Si expected menciona "NOPASSWD" → el output debe contenerlo.
  #   * En caso default, basta con output no vacío.
  local precond_pass=false cap_pass=false
  local last_level="none" last_output=""

  while IFS=$'\t' read -r level cmd expected; do
    [[ -z "$level" || -z "$cmd" ]] && continue
    local out
    out=$(timeout 5 bash -c "$cmd" 2>&1 | head -1 | head -c 200)
    [[ -z "$out" ]] && continue

    # Decidir si el output cumple lo esperado
    local matches=false
    if [[ "$expected" == *"4xxx"* ]]; then
      # Para SUID: stat -c "%U %a" debe mostrar usuario y modo con bit SUID activo.
      # El bit SUID está en el primer dígito del modo (4=SUID, 6=SUID+SGID, 7=todos).
      # Modos válidos: 4xxx, 6xxx, 7xxx (3 dígitos) o 04xxx, 06xxx, 07xxx (4 dígitos).
      # Modos sin SUID: 0xxx, 1xxx, 2xxx, 3xxx, o 0(0-3)xxx con 4 dígitos.
      if echo "$out" | grep -qE '^\S+ +([46-7]|0[46-7])[0-7]{3}$'; then
        matches=true
      fi
    elif [[ "$expected" == *"CAPABILITY_OK"* ]]; then
      echo "$out" | grep -q "CAPABILITY_OK" && matches=true
    elif [[ "$expected" == *"NOPASSWD"* ]]; then
      echo "$out" | grep -q "NOPASSWD" && matches=true
    elif [[ "$expected" == *"línea con cap_"* ]]; then
      # Capability check vía getcap: output debería contener cap_<algo>=
      echo "$out" | grep -qE 'cap_\w+(\+|=)' && matches=true
    elif [[ "$expected" == *"OK"* ]]; then
      # genérico: output contiene "OK"
      echo "$out" | grep -q "OK" && matches=true
    else
      # Si no hay heurística específica, ser conservadores: requerir que el
      # comando haya devuelto contenido NO vacío y NO sea un mensaje de error obvio.
      if ! echo "$out" | grep -qiE '^(error|permission denied|command not found|no such)'; then
        matches=true
      fi
    fi

    if $matches; then
      case "$level" in
        precondition) precond_pass=true ;;
        capability)   cap_pass=true ;;
      esac
      last_level="$level"
      last_output="$out"
    fi
  done < "$cmds_tmp"

  # Decisión final:
  #   - Sin precondition pasada → vector NO viable → verified=false
  #     (el binario detectado no tiene ya el SUID/sudo/capability esperado)
  #   - Con precondition pero sin capability → verified=true (parcial)
  #   - Ambas pasaron → verified=true (confirmado)
  local verified="false"
  if $precond_pass; then
    verified="true"
  fi

  echo "verified=$verified"
  echo "verified_at_level=$last_level"
  echo "verify_output=$last_output"
}

flush_module_json() {
  local module_name="$1"
  local f_json="[" w_json="[" i_json="[" s_json="["
  local first=true

  for item in "${_MOD_FINDINGS[@]+"${_MOD_FINDINGS[@]}"}"; do
    $first || f_json+=","; f_json+="\"$(json_escape "$item")\""; first=false
  done; f_json+="]"; first=true

  for item in "${_MOD_WARNINGS[@]+"${_MOD_WARNINGS[@]}"}"; do
    $first || w_json+=","; w_json+="\"$(json_escape "$item")\""; first=false
  done; w_json+="]"; first=true

  for item in "${_MOD_INFOS[@]+"${_MOD_INFOS[@]}"}"; do
    $first || i_json+=","; i_json+="\"$(json_escape "$item")\""; first=false
  done; i_json+="]"; first=true

  # Findings estructurados — ya son JSON object strings, no se escapan otra vez
  for item in "${_MOD_STRUCTURED[@]+"${_MOD_STRUCTURED[@]}"}"; do
    $first || s_json+=","; s_json+="$item"; first=false
  done; s_json+="]"

  JSON_MODULES+=("{\"module\":\"$(json_escape "$module_name")\",\"critical\":$f_json,\"warnings\":$w_json,\"info\":$i_json,\"findings\":$s_json}")
  _MOD_FINDINGS=(); _MOD_WARNINGS=(); _MOD_INFOS=(); _MOD_STRUCTURED=()
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
  mod_info "Usuario     : $CURRENT_USER (UID=$CURRENT_UID, GID=$CURRENT_GID)"
  mod_info "Grupos      : $CURRENT_GROUPS"
  mod_info "SHA256 script: $SCRIPT_SHA256"

  # Detectar versión de glibc — relevante para CVE-2023-4911 Looney Tunables
  local glibc_ver=""
  if command -v ldd &>/dev/null; then
    glibc_ver=$(ldd --version 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1 || echo "")
  fi
  if [[ -z "$glibc_ver" && -f /lib/x86_64-linux-gnu/libc.so.6 ]]; then
    glibc_ver=$(/lib/x86_64-linux-gnu/libc.so.6 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+' | head -1 || echo "")
  fi
  if [[ -n "$glibc_ver" ]]; then
    mod_info "glibc       : $glibc_ver"
    add_finding "glibc_version" "info" "glibc versión: $glibc_ver" "version=$glibc_ver"
  fi

  # Detectar si estamos dentro de un contenedor (informativo aquí, detallado en módulo containers)
  if [[ -f /.dockerenv ]] || grep -qE 'docker|lxc|containerd' /proc/1/cgroup 2>/dev/null; then
    mod_warning "Entorno detectado: posiblemente DENTRO DE UN CONTENEDOR"
    add_finding "container_detected" "warning" \
      "Entorno detectado: posiblemente DENTRO DE UN CONTENEDOR" \
      "indicator=cgroup_or_dockerenv"
  fi

  flush_module_json "Sistema"
}

# ─── 2. Binarios SUID/SGID ────────────────────────────────────────────────────
check_suid_sgid() {
  print_header "2. BINARIOS SUID / SGID"
  _MOD_FINDINGS=(); _MOD_WARNINGS=(); _MOD_INFOS=()

  mod_info "Buscando binarios SUID en sistemas de archivos locales (-xdev)..."
  local count=0 sgid_count=0

  # -xdev: no cruzar otros sistemas de archivos (evita /proc, /sys, NFS, etc.)
  # Reduce drásticamente el tiempo en sistemas grandes
  local suid_tmp
  suid_tmp=$(_tmp_file)
  find / -xdev -perm -4000 -type f 2>/dev/null | sort > "$suid_tmp"

  while IFS= read -r bin; do
    [[ -z "$bin" ]] && continue
    local name owner perms
    # basename inline (sin fork): expansión de parámetros
    name="${bin##*/}"
    # Una sola llamada a stat para owner+perms en vez de dos forks por SUID.
    # Si stat falla, ambos quedan en "?" — el formato es estable.
    IFS='|' read -r owner perms < <(stat -c '%U|%a' "$bin" 2>/dev/null || echo "?|?")
    [[ -z "$owner" ]] && owner="?"
    [[ -z "$perms" ]] && perms="?"
    count=$((count + 1))

    # Lookup O(1) contra el set declarado globalmente
    if [[ -n "${DANGEROUS_SUID[$name]:-}" ]]; then
      mod_critical "SUID peligroso: $bin (owner: $owner, perms: $perms)"
      print_verbose "GTFOBins: https://gtfobins.github.io/gtfobins/$name/"
      # Verificación opcional opt-in
      local verify_kv=()
      if $VERIFY_VECTORS; then
        local vout
        vout=$(_verify_vector "suid" "$name")
        while IFS= read -r vline; do
          [[ -n "$vline" ]] && verify_kv+=("$vline")
        done <<< "$vout"
        # Mostrar resultado en consola
        local vstatus="${vout#*verified=}"; vstatus="${vstatus%%$'\n'*}"
        case "$vstatus" in
          true)    print_verbose "✓ Verificado: vector confirmado en gtfobins.py" ;;
          false)   print_verbose "✗ No verificado: chequeos no concluyentes" ;;
          unknown) print_verbose "? Sin verificar: gtfobins.py o python3 no disponible" ;;
        esac
      fi
      add_finding "suid_dangerous" "critical" \
        "SUID peligroso: $bin (owner: $owner, perms: $perms)" \
        "binary=$name" "path=$bin" "owner=$owner" "perms=$perms" \
        "${verify_kv[@]+"${verify_kv[@]}"}"
    else
      mod_warning "SUID encontrado: $bin (owner: $owner)"
      add_finding "suid_unusual" "warning" \
        "SUID encontrado: $bin (owner: $owner)" \
        "binary=$name" "path=$bin" "owner=$owner" "perms=$perms"
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
    local sgid_name sgid_owner_group
    sgid_name="${bin##*/}"
    sgid_owner_group=$(stat -c '%U:%G' "$bin" 2>/dev/null || echo '?')
    mod_warning "SGID: $bin (owner: $sgid_owner_group)"
    add_finding "sgid_binary" "warning" \
      "SGID: $bin (owner: $sgid_owner_group)" \
      "binary=$sgid_name" "path=$bin" "owner_group=$sgid_owner_group"
  done < "$sgid_tmp"
  mod_info "Total SGID: $sgid_count"

  flush_module_json "SUID/SGID"
}

# ─── 3. Sudo ──────────────────────────────────────────────────────────────────
# Helper: parsea una línea de sudo -l y emite un finding por cada binario.
# Formato sudoers soportado:
#   (ALL : ALL) NOPASSWD: /usr/bin/find, /usr/bin/vim
#   (ALL : ALL) ALL                              ← cualquier comando
#   (root) NOPASSWD: ALL                         ← cualquier comando como root
#   (root) /usr/bin/less *                       ← comando con args/wildcard
#
# IMPORTANTE: La palabra literal 'ALL' como comando significa "cualquier
# comando" en sintaxis sudoers — es escalada total inmediata vía `sudo bash`.
_parse_sudo_line() {
  local line="$1" source="$2"
  local nopasswd_hint="${3:-false}"  # "true" si el caller ya sabe que es NOPASSWD

  # Strip leading whitespace para regex limpio
  local trimmed="${line#"${line%%[![:space:]]*}"}"

  # Regex única: (runas) [NOPASSWD:] comandos
  # Captura: 1=runas, 2=NOPASSWD opcional, 3=parte de comandos
  local runas="" nopasswd="false" cmds_part=""
  if [[ "$trimmed" =~ ^\(([^\)]+)\)[[:space:]]*(NOPASSWD:[[:space:]]*)?(.*)$ ]]; then
    runas="${BASH_REMATCH[1]}"
    [[ -n "${BASH_REMATCH[2]}" ]] && nopasswd="true"
    cmds_part="${BASH_REMATCH[3]}"
  else
    # Línea de sudoers sin runas explícito (ej: "user ALL=(ALL) NOPASSWD: ALL")
    # Fallback: solo detectar NOPASSWD y usar todo lo que sigue al último ':'
    [[ "$trimmed" =~ NOPASSWD ]] && nopasswd="true"
    if [[ "$trimmed" == *":"* ]]; then
      cmds_part="${trimmed##*:}"
    else
      cmds_part="$trimmed"
    fi
  fi

  [[ "$nopasswd_hint" == "true" ]] && nopasswd="true"
  # ltrim cmds_part
  cmds_part="${cmds_part#"${cmds_part%%[![:space:]]*}"}"

  if [[ "$cmds_part" == "ALL" ]] || [[ "$cmds_part" =~ ^ALL[[:space:]]*$ ]] \
     || [[ "$cmds_part" =~ ^ALL[[:space:]]*, ]] || [[ "$cmds_part" =~ ,[[:space:]]*ALL[[:space:]]*$ ]] \
     || [[ "$cmds_part" =~ ,[[:space:]]*ALL[[:space:]]*, ]]; then
    local sev="critical"
    local msg="Sudo: usuario puede ejecutar CUALQUIER comando"
    [[ "$nopasswd" == "true" ]] && msg+=" SIN contraseña (NOPASSWD)"
    msg+=" como '$runas'. Escalada: sudo /bin/bash"
    add_finding "sudo_all_commands" "$sev" "$msg" \
      "runas=$runas" "nopasswd=$nopasswd" "source=$source" \
      "exploit=sudo /bin/bash" "exploit_alt=sudo -i"
    # NO retornamos: si hay más comandos en la lista, los seguimos parseando
    # como findings individuales (defensivo, raramente ocurre con ALL).
  fi

  # Split por coma — cada item es un comando permitido
  local IFS_OLD="$IFS"; IFS=','
  local cmds_array=($cmds_part)
  IFS="$IFS_OLD"

  for cmd_full in "${cmds_array[@]}"; do
    # Limpiar espacios
    cmd_full="${cmd_full#"${cmd_full%%[![:space:]]*}"}"
    cmd_full="${cmd_full%"${cmd_full##*[![:space:]]}"}"
    [[ -z "$cmd_full" ]] && continue
    # Si el token es literalmente 'ALL' ya lo emitimos arriba; saltar.
    [[ "$cmd_full" == "ALL" ]] && continue

    # Extraer path del binario (primera "palabra" del comando)
    local bin_path bin_name args has_wildcard="false"
    bin_path="${cmd_full%% *}"
    bin_name="${bin_path##*/}"  # basename inline (sin fork)
    args="${cmd_full#"$bin_path"}"
    args="${args#"${args%%[![:space:]]*}"}"
    [[ "$cmd_full" == *"*"* ]] && has_wildcard="true"

    # Severidad: NOPASSWD eleva a crítico; con password queda warning informativo
    local sev="warning"
    [[ "$nopasswd" == "true" ]] && sev="critical"

    # Verificación opt-in (solo si NOPASSWD: con password no se puede chequear sin
    # interacción del usuario)
    local verify_kv=()
    if $VERIFY_VECTORS && [[ "$nopasswd" == "true" ]]; then
      local vout
      vout=$(_verify_vector "sudo" "$bin_name")
      while IFS= read -r vline; do
        [[ -n "$vline" ]] && verify_kv+=("$vline")
      done <<< "$vout"
    fi

    add_finding "sudo_rule" "$sev" \
      "Sudo: $cmd_full (NOPASSWD=$nopasswd, source=$source)" \
      "binary=$bin_name" "path=$bin_path" "args=$args" \
      "nopasswd=$nopasswd" "runas=$runas" \
      "wildcard=$has_wildcard" "source=$source" \
      "${verify_kv[@]+"${verify_kv[@]}"}"
  done
}

check_sudo() {
  print_header "3. CONFIGURACIÓN SUDO"
  _MOD_FINDINGS=(); _MOD_WARNINGS=(); _MOD_INFOS=()

  if ! command -v sudo &>/dev/null; then
    mod_info "sudo no instalado"; flush_module_json "Sudo"; return
  fi

  # Versión de sudo (importante para CVEs como Baron Samedit y CVE-2023-22809)
  local sudo_ver
  sudo_ver=$(sudo -V 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+(p[0-9]+)?' | head -1 || echo "")
  if [[ -n "$sudo_ver" ]]; then
    mod_info "sudo versión: $sudo_ver"
    add_finding "sudo_version" "info" "sudo versión: $sudo_ver" "version=$sudo_ver"
  fi

  if sudo -n -l 2>/dev/null | grep -q "may run" 2>/dev/null; then
    mod_critical "El usuario puede ejecutar sudo SIN contraseña"
    add_finding "sudo_nopasswd_available" "critical" \
      "El usuario puede ejecutar sudo SIN contraseña" \
      "user=$CURRENT_USER"
    while IFS= read -r line; do
      [[ -z "$line" || "$line" =~ ^(Matching|User|Defaults) ]] && continue
      mod_critical "  → $line"
      _parse_sudo_line "$line" "sudo -l" "true"
    done < <(sudo -n -l 2>/dev/null || true)
  else
    mod_info "sudo requiere contraseña o no hay permisos configurados"
  fi

  # Grupos privilegiados — distinguimos dos clases:
  #   sudo-equivalents:  permiten ejecutar sudo (warning, ya cubierto arriba)
  #   root-equivalents:  ESCALADA DIRECTA A ROOT sin sudo (critical)
  #
  # Los root-equivalents son grupos donde la membresía sola permite
  # comprometer el sistema, sin necesidad de password ni sudo:
  #   lxd/lxc      → crear container privilegiado montando / del host
  #   docker       → docker run -v /:/host alpine chroot /host
  #   disk         → leer/escribir devices del filesystem directamente
  #   shadow       → leer /etc/shadow (offline cracking)
  #   adm          → leer /var/log (puede contener secretos)
  #   video/kvm    → acceso a hardware sensible (menos directo)
  local sudo_groups="" root_groups=""
  for g in $CURRENT_GROUPS; do
    case "$g" in
      sudo|wheel|admin)
        sudo_groups+="${sudo_groups:+ }$g" ;;
      lxd|lxc|docker|disk|shadow|adm)
        root_groups+="${root_groups:+ }$g" ;;
    esac
  done

  if [[ -n "$sudo_groups" ]]; then
    mod_warning "Grupo privilegiado: $sudo_groups"
    add_finding "privileged_group_membership" "warning" \
      "Usuario en grupo privilegiado: $sudo_groups" \
      "groups=$sudo_groups"
  fi

  for g in $root_groups; do
    local exploit="" desc=""
    case "$g" in
      lxd|lxc)
        desc="Crear container privilegiado montando / del host"
        exploit="lxc init alpine c -c security.privileged=true; lxc config device add c disk source=/ path=/mnt recursive=true; lxc start c; lxc exec c sh" ;;
      docker)
        desc="Lanzar container con / del host montado"
        exploit="docker run -v /:/host --rm -it alpine chroot /host" ;;
      disk)
        desc="Acceso raw a devices — leer /etc/shadow o reescribir binarios"
        exploit="debugfs /dev/sda1  # o: dd if=/dev/sda | strings" ;;
      shadow)
        desc="Lectura de /etc/shadow — crackear hashes offline"
        exploit="cat /etc/shadow > /tmp/sh.txt; john /tmp/sh.txt" ;;
      adm)
        desc="Lectura de /var/log — puede contener secretos, sesiones, tokens"
        exploit="grep -riE 'password|token|secret' /var/log/ 2>/dev/null" ;;
    esac
    mod_critical "Grupo ROOT-EQUIVALENTE: $g — $desc"
    add_finding "root_equivalent_group" "critical" \
      "Usuario en grupo '$g' — escalada directa a root: $desc" \
      "group=$g" "user=$CURRENT_USER" "exploit=$exploit"
  done

  if [[ -r /etc/sudoers ]]; then
    # Las líneas que grep'eamos contienen "NOPASSWD" por construcción → hint=true
    while IFS= read -r line; do
      mod_critical "NOPASSWD en /etc/sudoers: $line"
      _parse_sudo_line "$line" "/etc/sudoers" "true"
    done < <(grep -i "NOPASSWD" /etc/sudoers 2>/dev/null | grep -v "^#" || true)
  fi

  if [[ -d /etc/sudoers.d ]]; then
    for f in /etc/sudoers.d/*; do
      [[ -r "$f" ]] || continue
      while IFS= read -r line; do
        mod_critical "NOPASSWD en $f: $line"
        _parse_sudo_line "$line" "$f" "true"
      done < <(grep -i "NOPASSWD" "$f" 2>/dev/null | grep -v "^#" || true)
    done
  fi

  flush_module_json "Sudo"
}

# ─── 4. Cron jobs ─────────────────────────────────────────────────────────────
# Helper: dado un path a un script, chequea recursivamente si es escribible
# o si referencia otros scripts/binarios escribibles (1 nivel de profundidad).
# Emite findings críticos por cada vector encontrado.
#
# Argumentos:
#   $1 = path al script referenciado
#   $2 = path al cron file que lo referencia (para attribution)
#   $3 = max_depth (default 1)
_cron_check_script() {
  local script="$1" cron_source="$2" depth="${3:-1}"
  [[ -f "$script" ]] || return 0

  local script_owner; script_owner=$(stat -c '%U' "$script" 2>/dev/null || echo '?')
  local cron_owner;   cron_owner=$(stat -c '%U' "$cron_source" 2>/dev/null || echo '?')

  # ─ Vector 1: el script en sí es escribible ────────────────────────────────
  if [[ -w "$script" ]]; then
    mod_critical "Script cron ESCRIBIBLE: $script (referenciado en $cron_source)"
    add_finding "cron_writable_script" "critical" \
      "Script cron ESCRIBIBLE: $script (referenciado en $cron_source)" \
      "script=$script" "cron_source=$cron_source" \
      "cron_owner=$cron_owner" "script_owner=$script_owner" \
      "depth=0"
    return 0  # ya es game over, no profundizamos
  fi

  # ─ Vector 2: directorio del script escribible (swap del archivo entero) ───
  local script_dir; script_dir=$(dirname "$script" 2>/dev/null || echo "")
  if [[ -n "$script_dir" && -w "$script_dir" ]]; then
    mod_critical "Directorio del script cron ESCRIBIBLE: $script_dir (script: $script)"
    add_finding "cron_writable_script_dir" "critical" \
      "Directorio del script cron ESCRIBIBLE: $script_dir (script: $script)" \
      "directory=$script_dir" "script=$script" "cron_source=$cron_source"
  fi

  # ─ Vector 3 (transitivo): el script referencia OTROS paths escribibles ────
  # Solo si el script es legible y aún tenemos profundidad
  [[ $depth -le 0 || ! -r "$script" ]] && return 0
  while IFS= read -r referenced; do
    # Solo paths absolutos a archivos existentes
    [[ -z "$referenced" || "$referenced" != /* || ! -e "$referenced" ]] && continue
    # Evitar bucles obvios
    [[ "$referenced" == "$script" ]] && continue
    if [[ -w "$referenced" ]]; then
      mod_critical "Script cron referencia path ESCRIBIBLE: $referenced (cadena: $cron_source → $script → $referenced)"
      add_finding "cron_writable_transitive" "critical" \
        "Script cron referencia path ESCRIBIBLE: $referenced (cadena: $cron_source → $script → $referenced)" \
        "writable_path=$referenced" "script=$script" "cron_source=$cron_source" \
        "depth=1"
    fi
  done < <(grep -oE '(/[A-Za-z0-9_./-]+)' "$script" 2>/dev/null \
           | sort -u | head -50 || true)
}

# Helper: chequea una línea de crontab por wildcards en argumentos
_cron_check_wildcard() {
  local line="$1" cron_source="$2"
  local wildcard_re='(tar|rsync|chown|chmod|7z|zip|find|scp|wget|cp|mv|cat)[[:space:]]+[^|]*[*?]'
  if [[ "$line" =~ $wildcard_re ]]; then
    mod_warning "Cron con wildcard en comando sensible: $line"
    add_finding "cron_wildcard_injection_candidate" "warning" \
      "Cron usa wildcard con comando sensible (posible wildcard injection): $line" \
      "cron_source=$cron_source" "line=${line:0:160}" \
      "hint=verificar cwd del comando — si es escribible, hay escalada"
  fi
}

check_cron() {
  print_header "4. TAREAS CRON"
  _MOD_FINDINGS=(); _MOD_WARNINGS=(); _MOD_INFOS=()

  local cron_paths=(
    /etc/crontab /etc/cron.d /etc/cron.daily
    /etc/cron.weekly /etc/cron.monthly /etc/cron.hourly
    /var/spool/cron /var/spool/cron/crontabs
  )

  for path in "${cron_paths[@]}"; do
    if [[ -f "$path" ]]; then
      local cron_owner; cron_owner=$(stat -c '%U' "$path" 2>/dev/null || echo '?')
      mod_info "Cron: $path (owner: $cron_owner)"
      add_finding "cron_file" "info" "Cron file: $path" \
        "path=$path" "owner=$cron_owner" "type=file"

      # ¿El crontab en sí es escribible? Vector directo a root.
      if [[ -w "$path" ]]; then
        mod_critical "Crontab ESCRIBIBLE: $path — agregar línea = ejecución como $cron_owner"
        add_finding "cron_file_writable" "critical" \
          "Crontab ESCRIBIBLE: $path — agregar línea = ejecución como $cron_owner" \
          "path=$path" "owner=$cron_owner"
      fi

      # PATH inyectable: si el crontab define PATH= con un dir escribible primero,
      # cualquier comando bare (no path absoluto) será hijacked.
      while IFS= read -r path_line; do
        local cron_path="${path_line#*=}"
        cron_path="${cron_path//\"/}"; cron_path="${cron_path//\'/}"
        local IFS_OLD="$IFS"; IFS=':'
        local dirs=($cron_path)
        IFS="$IFS_OLD"
        for d in "${dirs[@]}"; do
          [[ -z "$d" ]] && continue
          if [[ -d "$d" && -w "$d" ]]; then
            mod_critical "PATH de cron incluye directorio ESCRIBIBLE: $d (en $path)"
            add_finding "cron_path_writable" "critical" \
              "PATH de cron incluye directorio ESCRIBIBLE: $d (en $path)" \
              "directory=$d" "cron_source=$path" "cron_path=$cron_path"
          fi
        done
      done < <(grep -E '^[[:space:]]*PATH[[:space:]]*=' "$path" 2>/dev/null || true)

      # Por cada línea de cron, chequear scripts referenciados y wildcards
      while IFS= read -r line; do
        [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
        # Líneas de definición (PATH=, MAILTO=, SHELL=) no son comandos
        [[ "$line" =~ ^[[:space:]]*[A-Z_]+= ]] && continue
        _cron_check_wildcard "$line" "$path"
        # Extraer paths absolutos referenciados
        while IFS= read -r script; do
          _cron_check_script "$script" "$path" 1
        done < <(grep -oE '(/[A-Za-z0-9_./-]+)' <<< "$line" 2>/dev/null | sort -u || true)
      done < "$path"

    elif [[ -d "$path" ]]; then
      for f in "$path"/*; do
        [[ -f "$f" ]] || continue
        local cron_owner; cron_owner=$(stat -c '%U' "$f" 2>/dev/null || echo '?')
        mod_info "Cron job: $f (owner: $cron_owner)"
        add_finding "cron_file" "info" "Cron job: $f" \
          "path=$f" "owner=$cron_owner" "type=dir_entry"

        if [[ -w "$f" ]]; then
          mod_critical "Cron job ESCRIBIBLE: $f — ejecución como $cron_owner garantizada"
          add_finding "cron_file_writable" "critical" \
            "Cron job ESCRIBIBLE: $f — ejecución como $cron_owner garantizada" \
            "path=$f" "owner=$cron_owner"
        fi

        # Aplicar mismos checks que arriba: PATH= inyectable, wildcards, scripts
        while IFS= read -r path_line; do
          local cron_path="${path_line#*=}"
          cron_path="${cron_path//\"/}"; cron_path="${cron_path//\'/}"
          local IFS_OLD="$IFS"; IFS=':'
          local dirs=($cron_path)
          IFS="$IFS_OLD"
          for d in "${dirs[@]}"; do
            [[ -z "$d" ]] && continue
            if [[ -d "$d" && -w "$d" ]]; then
              mod_critical "PATH de cron incluye directorio ESCRIBIBLE: $d (en $f)"
              add_finding "cron_path_writable" "critical" \
                "PATH de cron incluye directorio ESCRIBIBLE: $d (en $f)" \
                "directory=$d" "cron_source=$f" "cron_path=$cron_path"
            fi
          done
        done < <(grep -E '^[[:space:]]*PATH[[:space:]]*=' "$f" 2>/dev/null || true)

        while IFS= read -r line; do
          [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
          [[ "$line" =~ ^[[:space:]]*[A-Z_]+= ]] && continue
          _cron_check_wildcard "$line" "$f"
          while IFS= read -r script; do
            _cron_check_script "$script" "$f" 1
          done < <(grep -oE '(/[A-Za-z0-9_./-]+)' <<< "$line" 2>/dev/null | sort -u || true)
        done < "$f"
      done
    fi
  done

  # Crontab del usuario actual
  local crontab_out
  crontab_out=$(crontab -l 2>/dev/null || true)
  if [[ -n "$crontab_out" ]]; then
    while IFS= read -r line; do
      [[ -n "$line" && ! "$line" =~ ^# ]] && mod_info "Crontab usuario: $line"
    done <<< "$crontab_out"
    add_finding "user_crontab_exists" "info" \
      "Crontab del usuario actual definido" \
      "user=$CURRENT_USER" "line_count=$(echo "$crontab_out" | grep -cvE '^#|^$')"
  fi

  # Crontabs de OTROS usuarios accesibles — en CTFs es común dejar
  # /var/spool/cron/crontabs/<user> con permisos relajados.
  for spool in /var/spool/cron/crontabs /var/spool/cron; do
    [[ -d "$spool" ]] || continue
    for f in "$spool"/*; do
      [[ -f "$f" && -r "$f" ]] || continue
      local ct_owner; ct_owner=$(stat -c '%U' "$f" 2>/dev/null || echo '?')
      [[ "$ct_owner" == "$CURRENT_USER" ]] && continue
      mod_warning "Crontab de otro usuario LEGIBLE: $f (owner=$ct_owner)"
      add_finding "other_user_crontab_readable" "warning" \
        "Crontab de otro usuario LEGIBLE: $f (owner=$ct_owner) — posible info leak" \
        "path=$f" "owner=$ct_owner"
    done
  done

  flush_module_json "Cron"
}

# ─── 5. Archivos y permisos ───────────────────────────────────────────────────
check_file_permissions() {
  print_header "5. ARCHIVOS SENSIBLES Y PERMISOS"
  _MOD_FINDINGS=(); _MOD_WARNINGS=(); _MOD_INFOS=()

  if [[ -w /etc/passwd ]]; then
    mod_critical "/etc/passwd ESCRIBIBLE — inyección de usuario root posible"
    add_finding "passwd_writable" "critical" \
      "/etc/passwd ESCRIBIBLE — inyección de usuario root posible" \
      "path=/etc/passwd"
  else
    mod_ok "/etc/passwd: solo lectura"
  fi

  if [[ -r /etc/shadow ]]; then
    mod_critical "/etc/shadow LEGIBLE — hashes expuestos"
    add_finding "shadow_readable" "critical" \
      "/etc/shadow LEGIBLE — hashes expuestos" \
      "path=/etc/shadow"
  else
    mod_ok "/etc/shadow: no accesible"
  fi

  for dir in /root/.ssh /home/*/.ssh; do
    [[ -d "$dir" ]] || continue
    local perms; perms=$(stat -c '%a' "$dir" 2>/dev/null || echo "?")
    if [[ "$perms" != "700" && "$perms" != "600" ]]; then
      mod_warning "Permisos débiles en $dir ($perms)"
      add_finding "ssh_dir_weak_perms" "warning" \
        "Permisos débiles en $dir ($perms)" \
        "path=$dir" "perms=$perms"
    fi
    for key in "$dir"/id_rsa "$dir"/id_ed25519 "$dir"/id_ecdsa "$dir"/id_dsa; do
      if [[ -f "$key" && -r "$key" ]]; then
        mod_critical "Clave SSH privada legible: $key"
        local key_owner; key_owner=$(stat -c '%U' "$key" 2>/dev/null || echo '?')
        local key_type="${key##*/}"  # basename inline
        add_finding "ssh_private_key_readable" "critical" \
          "Clave SSH privada legible: $key" \
          "path=$key" "owner=$key_owner" "key_type=$key_type"
      fi
    done
  done

  while IFS= read -r dir; do
    if [[ -n "$dir" ]]; then
      mod_critical "Directorio world-writable en ruta del sistema: $dir"
      add_finding "system_dir_writable" "critical" \
        "Directorio world-writable en ruta del sistema: $dir" \
        "path=$dir"
    fi
  done < <(find /etc /usr /bin /sbin /lib -maxdepth 2 -writable -type d 2>/dev/null || true)

  for f in /etc/mysql/my.cnf /var/www/html/wp-config.php ~/.aws/credentials ~/.docker/config.json; do
    [[ -f "$f" && -r "$f" ]] || continue
    mod_warning "Config legible: $f"
    add_finding "config_file_readable" "warning" \
      "Config legible: $f" "path=$f"
    while IFS= read -r line; do
      mod_critical "Posible credencial en $f: ${line:0:80}"
      add_finding "credential_in_config" "critical" \
        "Posible credencial en $f: ${line:0:80}" \
        "path=$f" "preview=${line:0:80}"
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
      # Formato típico: "/usr/bin/python3.10 cap_setuid,cap_setgid+ep"
      # o (más viejo):  "/usr/bin/python3.10 = cap_setuid+ep"
      local bin_path caps_field bin_name
      bin_path=$(echo "$line" | awk '{print $1}')
      caps_field=$(echo "$line" | awk '{for(i=2;i<=NF;i++) printf "%s%s", $i, (i<NF?" ":"")}')
      # Normalizar: quitar '=' opcional
      caps_field="${caps_field#= }"
      # Solo la parte antes del flag (+ep, +ei, etc.)
      local caps_only="${caps_field%%+*}"
      bin_name="${bin_path##*/}"  # basename inline (sin fork)

      # Lowercase para matching robusto contra dangerous_caps (que están en lowercase)
      local caps_only_lc="${caps_only,,}"
      local is_dangerous=false matched_cap=""
      for dc in "${dangerous_caps[@]}"; do
        if [[ "$caps_only_lc" == *"$dc"* ]]; then
          is_dangerous=true
          matched_cap="$dc"
          break
        fi
      done

      if $is_dangerous; then
        mod_critical "Capability peligrosa: $line"
        # Para capabilities, el matching del bin_name debe ser flexible:
        # python3.10 → python3 → python (ya implementado en rh-analyze).
        # Aquí solo probamos el nombre tal cual; el analyzer rebajará si falla.
        local verify_kv=()
        if $VERIFY_VECTORS; then
          local vout
          vout=$(_verify_vector "capability" "$bin_name" "$matched_cap")
          # Si el bin_name no matchea exacto (ej python3.10), probar simplificado
          local vstatus
          vstatus=$(echo "$vout" | grep '^verified=' | cut -d= -f2)
          if [[ "$vstatus" != "true" ]]; then
            local simplified="${bin_name//[0-9.]/}"
            if [[ "$simplified" != "$bin_name" && -n "$simplified" ]]; then
              vout=$(_verify_vector "capability" "$simplified" "$matched_cap")
            fi
          fi
          while IFS= read -r vline; do
            [[ -n "$vline" ]] && verify_kv+=("$vline")
          done <<< "$vout"
        fi
        add_finding "capability_dangerous" "critical" \
          "Capability peligrosa: $line" \
          "binary=$bin_name" "path=$bin_path" \
          "capability=$matched_cap" "caps_full=$caps_field" \
          "${verify_kv[@]+"${verify_kv[@]}"}"
      else
        mod_warning "Capability: $line"
        add_finding "capability_other" "warning" \
          "Capability: $line" \
          "binary=$bin_name" "path=$bin_path" \
          "caps_full=$caps_field"
      fi
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
  # Versión "limpia": 5.15.0-91-generic -> 5.15.0
  local kernel_clean
  kernel_clean=$(echo "$kernel" | grep -oE '^[0-9]+\.[0-9]+\.[0-9]+' || echo "$kernel")
  add_finding "kernel_version" "info" "Kernel: $kernel" \
    "version_full=$kernel" "version=$kernel_clean"

  # Protecciones del kernel
  if [[ -f /proc/sys/kernel/randomize_va_space ]]; then
    local aslr; aslr=$(cat /proc/sys/kernel/randomize_va_space 2>/dev/null || echo "?")
    case $aslr in
      2) mod_ok "ASLR: Completo (nivel 2)"
         add_finding "kernel_protection" "info" "ASLR completo (2)" "name=aslr" "value=2" "status=ok" ;;
      1) mod_warning "ASLR: Parcial (nivel 1)"
         add_finding "kernel_protection_weak" "warning" "ASLR parcial (1)" "name=aslr" "value=1" "status=partial" ;;
      0) mod_critical "ASLR: DESHABILITADO"
         add_finding "kernel_protection_weak" "critical" "ASLR deshabilitado" "name=aslr" "value=0" "status=disabled" ;;
      *) mod_info "ASLR: valor desconocido ($aslr)" ;;
    esac
  fi

  if [[ -f /proc/sys/kernel/dmesg_restrict ]]; then
    local dmesg; dmesg=$(cat /proc/sys/kernel/dmesg_restrict 2>/dev/null || echo "?")
    if [[ "$dmesg" == "0" ]]; then
      mod_warning "dmesg_restrict: deshabilitado"
      add_finding "kernel_protection_weak" "warning" "dmesg_restrict deshabilitado" \
        "name=dmesg_restrict" "value=0" "status=disabled"
    else
      mod_ok "dmesg_restrict: habilitado ($dmesg)"
    fi
  fi

  if [[ -f /proc/sys/kernel/yama/ptrace_scope ]]; then
    local ptrace; ptrace=$(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null || echo "?")
    if [[ "$ptrace" == "0" ]]; then
      mod_warning "ptrace_scope: 0 — procesos trazables por cualquier usuario"
      add_finding "kernel_protection_weak" "warning" "ptrace_scope=0" \
        "name=ptrace_scope" "value=0" "status=disabled"
    else
      mod_ok "ptrace_scope: $ptrace (restringido)"
    fi
  fi

  # Protecciones adicionales
  if [[ -f /proc/sys/fs/protected_symlinks ]]; then
    local sl; sl=$(cat /proc/sys/fs/protected_symlinks 2>/dev/null || echo "?")
    if [[ "$sl" == "0" ]]; then
      mod_warning "protected_symlinks: deshabilitado — symlink races posibles"
      add_finding "kernel_protection_weak" "warning" "protected_symlinks deshabilitado" \
        "name=protected_symlinks" "value=0" "status=disabled"
    fi
  fi

  if [[ -f /proc/sys/kernel/kptr_restrict ]]; then
    local kr; kr=$(cat /proc/sys/kernel/kptr_restrict 2>/dev/null || echo "?")
    if [[ "$kr" == "0" ]]; then
      mod_warning "kptr_restrict: 0 — punteros del kernel expuestos en /proc"
      add_finding "kernel_protection_weak" "warning" "kptr_restrict=0" \
        "name=kptr_restrict" "value=0" "status=disabled"
    fi
  fi

  # User namespaces sin restricción → habilita Dirty Pipe y otros exploits
  if [[ -f /proc/sys/kernel/unprivileged_userns_clone ]]; then
    local uns; uns=$(cat /proc/sys/kernel/unprivileged_userns_clone 2>/dev/null || echo "?")
    add_finding "kernel_protection" "info" "unprivileged_userns_clone=$uns" \
      "name=unprivileged_userns_clone" "value=$uns"
    [[ "$uns" == "1" ]] && mod_warning "unprivileged_userns_clone=1 — habilita varios exploits de kernel"
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
        add_finding "nfs_no_root_squash" "critical" \
          "NFS share con no_root_squash: $share" \
          "share=$share" "config=$line"
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
  local current_hist="${HISTFILE:-${HOME:-/root}/.bash_history}"
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
    local hist_basename="${hist_file##*/}"  # basename inline, una vez por archivo
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
          mod_critical "Posible credencial en $hist_basename: $redacted"
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
        mod_warning "Comando sensible (${hits}x) en $hist_basename: $cmd_pattern"
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
    if [[ -r /var/run/docker.sock || -w /var/run/docker.sock ]]; then
      mod_critical "Docker socket accesible — escalada a root posible vía contenedor"
      add_finding "docker_socket_accessible" "critical" \
        "Docker socket accesible — escalada a root posible vía contenedor" \
        "path=/var/run/docker.sock"
    else
      mod_warning "Docker socket existe pero no accesible"
    fi
  fi

  # Membresía en grupo docker — equivalente a root en el host
  if [[ " $CURRENT_GROUPS " == *" docker "* ]]; then
    mod_critical "Usuario en grupo 'docker' — escalada a root posible"
    add_finding "user_in_docker_group" "critical" \
      "Usuario en grupo 'docker' — escalada a root posible" \
      "user=$CURRENT_USER" "group=docker"
  fi

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
      add_finding "path_writable" "critical" \
        "Directorio ESCRIBIBLE en PATH: $dir — PATH hijacking posible" \
        "directory=$dir"
    elif [[ "$dir" == "." || -z "$dir" ]]; then
      mod_critical "PATH incluye '.' — PATH hijacking posible"
      add_finding "path_includes_cwd" "critical" \
        "PATH incluye '.' o entrada vacía — PATH hijacking posible" \
        "directory=${dir:-empty}"
    fi
  done

  if [[ -n "${LD_PRELOAD:-}" ]]; then
    mod_critical "LD_PRELOAD activo: $LD_PRELOAD"
    add_finding "ld_preload_active" "critical" \
      "LD_PRELOAD activo: $LD_PRELOAD" "value=$LD_PRELOAD"
  else
    mod_ok "LD_PRELOAD no definido"
  fi

  if [[ -n "${LD_LIBRARY_PATH:-}" ]]; then
    mod_warning "LD_LIBRARY_PATH definido: $LD_LIBRARY_PATH"
    add_finding "ld_library_path_set" "warning" \
      "LD_LIBRARY_PATH definido: $LD_LIBRARY_PATH" "value=$LD_LIBRARY_PATH"
  fi

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
      add_finding "env_secret" "critical" \
        "Secreto en entorno: ${varname}=${varval:0:4}[REDACTED]" \
        "var=$varname" "preview=${varval:0:4}"
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
        add_finding "docker_socket_writable" "critical" \
          "Docker socket escribible: $sock — escape a root posible" \
          "path=$sock"
      elif [[ -r "$sock" ]]; then
        mod_warning "Docker socket legible: $sock — enumeración de contenedores posible"
        add_finding "docker_socket_readable" "warning" \
          "Docker socket legible: $sock — enumeración de contenedores posible" \
          "path=$sock"
      fi
    fi
  done

  # ── Docker en el grupo del usuario ────────────────────────────────────────
  if [[ " $CURRENT_GROUPS " == *" docker "* ]]; then
    mod_critical "Usuario en grupo 'docker' — equivalente a root en el host"
    add_finding "user_in_docker_group" "critical" \
      "Usuario en grupo 'docker' — equivalente a root en el host" \
      "user=$CURRENT_USER" "group=docker"
  fi

  # ── Montajes peligrosos desde el host ─────────────────────────────────────
  if [[ -f /proc/mounts || -r /proc/mounts ]]; then
    while IFS= read -r mnt; do
      mod_critical "Sistema de archivos del host montado: $mnt"
      add_finding "host_filesystem_mounted" "critical" \
        "Sistema de archivos del host montado: $mnt" \
        "mount_line=$mnt"
    done < <(grep -E '^[^#].*\s/host' /proc/mounts 2>/dev/null || true)

    # /proc del host montado
    if grep -q "proc /proc/host" /proc/mounts 2>/dev/null; then
      mod_critical "/proc del host montado — acceso a procesos del host"
      add_finding "host_proc_mounted" "critical" \
        "/proc del host montado — acceso a procesos del host" \
        "path=/proc/host"
    fi
  fi

  # ── Kubernetes: service account tokens ────────────────────────────────────
  local sa_token="/var/run/secrets/kubernetes.io/serviceaccount/token"
  if [[ -f "$sa_token" && -r "$sa_token" ]]; then
    mod_critical "Token de Kubernetes ServiceAccount legible: $sa_token"
    print_verbose "Usar: kubectl --token=\$(cat $sa_token) auth can-i --list"
    local sa_ns="/var/run/secrets/kubernetes.io/serviceaccount/namespace"
    local namespace=""
    [[ -f "$sa_ns" ]] && namespace=$(cat "$sa_ns" 2>/dev/null || echo "")
    [[ -n "$namespace" ]] && mod_info "Namespace K8s: $namespace"
    add_finding "k8s_serviceaccount_token" "critical" \
      "Token de Kubernetes ServiceAccount legible: $sa_token" \
      "path=$sa_token" "namespace=$namespace"
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
    add_finding "aws_imdsv1_open" "critical" \
      "AWS IMDSv1 accesible SIN token (inseguro) — metadatos expuestos" \
      "endpoint=169.254.169.254" "version=v1"
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
        add_finding "aws_iam_credentials_exposed" "critical" \
          "Credenciales AWS IAM accesibles vía IMDS para rol: $iam_role" \
          "role=$iam_role" "cloud=aws"
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
    add_finding "aws_imdsv2_active" "warning" \
      "AWS IMDSv2 activo (más seguro que v1)" \
      "endpoint=169.254.169.254" "version=v2"
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
    add_finding "gcp_metadata_accessible" "critical" \
      "GCP Metadata Server accesible — instancia en Google Cloud" \
      "endpoint=metadata.google.internal" "cloud=gcp"
    local gcp_token
    gcp_token=$(curl $curl_opts \
      -H "Metadata-Flavor: Google" \
      "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" \
      2>/dev/null || true)
    if echo "$gcp_token" | grep -q "access_token" 2>/dev/null; then
      mod_critical "Token de servicio GCP accesible — credenciales de cuenta de servicio expuestas"
      print_verbose "Token puede usarse contra la API de Google Cloud"
      add_finding "gcp_service_token_exposed" "critical" \
        "Token de servicio GCP accesible — credenciales de cuenta de servicio expuestas" \
        "cloud=gcp"
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
    add_finding "azure_imds_accessible" "critical" \
      "Azure IMDS accesible — instancia en Microsoft Azure" \
      "endpoint=169.254.169.254" "cloud=azure"
    local az_token
    az_token=$(curl $curl_opts \
      -H "Metadata: true" \
      "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" \
      2>/dev/null || true)
    if echo "$az_token" | grep -q "access_token" 2>/dev/null; then
      mod_critical "Token Managed Identity de Azure accesible — credenciales expuestas"
      print_verbose "Token puede usarse contra la API de Azure Resource Manager"
      add_finding "azure_managed_identity_token" "critical" \
        "Token Managed Identity de Azure accesible — credenciales expuestas" \
        "cloud=azure"
    fi
  else
    mod_ok "Azure IMDS no accesible"
  fi

  # ── Credenciales cloud en archivos locales ────────────────────────────────
  mod_info "Buscando credenciales cloud en archivos locales..."
  local home_dir="${HOME:-/root}"
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
    add_finding "pkexec_version" "info" "pkexec versión: $pkexec_ver" "version=$pkexec_ver"
    # PwnKit afecta versiones < 0.120
    if [[ "$pkexec_ver" != "?" ]]; then
      local major minor
      major=$(echo "$pkexec_ver" | cut -d. -f1)
      minor=$(echo "$pkexec_ver" | cut -d. -f2 || echo "0")
      if [[ "$major" -eq 0 && "${minor:-0}" -lt 120 ]] 2>/dev/null; then
        mod_critical "pkexec < 0.120 — potencialmente vulnerable a CVE-2021-4034 (PwnKit)"
        print_verbose "https://blog.qualys.com/vulnerabilities-threat-research/2022/01/25/pwnkit"
        add_finding "cve_pwnkit" "critical" \
          "pkexec $pkexec_ver < 0.120 — vulnerable a CVE-2021-4034 (PwnKit)" \
          "cve=CVE-2021-4034" "version=$pkexec_ver" "fixed_in=0.120"
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

        # Archivo escribible por otros (cacheado: evita fork de whoami por archivo)
        if [[ -w "$ak_file" ]]; then
          local ak_owner; ak_owner=$(stat -c '%U' "$ak_file" 2>/dev/null || echo "?")
          [[ "$ak_owner" != "$CURRENT_USER" ]] && \
            mod_critical "$ak_file es ESCRIBIBLE — inyección de clave SSH posible"
        fi
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


# ─── 17. Procesos, sockets unix y configs de shell ───────────────────────────
# Vectores que un pentester revisa siempre:
#   - Procesos root con binarios o configs en directorios escribibles
#   - Tokens y secretos en /proc/*/environ y /proc/*/cmdline
#   - Sockets unix con permisos relajados (Redis, MySQL, daemon custom...)
#   - Configs de shell hijackeables (.bashrc/.zshrc/profile.d ajenos)

# Helper: ¿este path pertenece a un paquete del sistema?
# Si sí, lo consideramos "estándar" y no escribible normalmente.
# Devuelve 0 si pertenece a un paquete, 1 si no o si no podemos determinar.
_path_in_system_package() {
  local path="$1"
  [[ -z "$path" || ! -e "$path" ]] && return 1
  # Debian/Ubuntu
  if command -v dpkg &>/dev/null; then
    dpkg -S "$path" &>/dev/null && return 0
  fi
  # RHEL/Fedora/CentOS
  if command -v rpm &>/dev/null; then
    rpm -qf "$path" &>/dev/null && return 0
  fi
  # Arch
  if command -v pacman &>/dev/null; then
    pacman -Qo "$path" &>/dev/null && return 0
  fi
  return 1
}

# Helper: ¿es un binario/path "interesante" (no estándar)?
# Filtra paths típicos de paquetes del SO.
_path_is_suspicious() {
  local path="$1"
  [[ -z "$path" ]] && return 1
  # Paths obvios de paquetes — ni los chequeamos contra el package manager
  case "$path" in
    /usr/lib/*|/usr/libexec/*|/lib/*|/lib64/*) return 1 ;;
    /usr/bin/*|/usr/sbin/*|/bin/*|/sbin/*)
      # Solo confiamos si el package manager lo confirma
      _path_in_system_package "$path" && return 1
      return 0
      ;;
  esac
  # /opt, /home, /tmp, /var/lib/<custom>, /usr/local/* — interesantes
  return 0
}

check_processes() {
  print_header "17. PROCESOS, SOCKETS UNIX Y CONFIGS DE SHELL"
  _MOD_FINDINGS=(); _MOD_WARNINGS=(); _MOD_INFOS=()

  # Aliases locales hacia el caché global — evita 2 forks (whoami + id -u)
  # y mantiene el resto del módulo legible con nombres en lowercase.
  local current_user="$CURRENT_USER"
  local current_uid="$CURRENT_UID"

  # ── Procesos corriendo como root ──────────────────────────────────────────
  mod_info "Enumerando procesos como root..."

  # PIDs a ignorar: nuestro propio shell, su padre, y los hijos directos de awk/sed/grep
  # del pipe `ps | awk` que enumera. Calculamos el árbol del propio script.
  local self_pid="$$"
  local parent_pid; parent_pid=$(awk '/PPid:/ {print $2}' /proc/$$/status 2>/dev/null || echo "")
  local ignore_pids=" $self_pid $parent_pid "

  # Listamos PID y COMMAND completo — usamos -e -o para evitar truncado
  # Filtramos kthreadd y kernel threads (PPID 2 o brackets en cmd)
  local root_procs_tmp
  root_procs_tmp=$(_tmp_file)
  ps -eo pid,user,cmd 2>/dev/null \
    | awk '$2 == "root" && $3 !~ /^\[/ {pid=$1; $1=""; $2=""; print pid"|"$0}' \
    | sed 's/| */|/' > "$root_procs_tmp"

  local total_root_procs interesting_count=0
  total_root_procs=$(wc -l < "$root_procs_tmp" 2>/dev/null || echo 0)
  mod_info "Total procesos root: $total_root_procs (filtrando kthreads)"

  # Para cada proceso root, extraer el binario y chequear si es "interesante"
  local checked=0 max_check=200  # safety cap
  while IFS='|' read -r pid cmd; do
    [[ -z "$pid" || -z "$cmd" ]] && continue
    [[ $checked -ge $max_check ]] && break
    checked=$((checked + 1))

    # Ignorar nuestro árbol (script + parent + cualquier helper transitorio)
    [[ "$ignore_pids" == *" $pid "* ]] && continue
    # El proceso puede haber terminado entre ps y ahora
    [[ -e "/proc/$pid" ]] || continue
    # Si su PPid es nuestro PID, también lo ignoramos (es un hijo nuestro: awk/sed/etc.)
    local proc_ppid
    proc_ppid=$(awk '/PPid:/ {print $2}' "/proc/$pid/status" 2>/dev/null || echo "")
    [[ "$proc_ppid" == "$self_pid" ]] && continue

    # Resolver el binario real del proceso vía /proc/<pid>/exe (más fiable que parsear cmd)
    local exe_path=""
    if [[ -L "/proc/$pid/exe" ]]; then
      exe_path=$(readlink "/proc/$pid/exe" 2>/dev/null || echo "")
    fi
    # Si tiene " (deleted)" lo quitamos
    exe_path="${exe_path% (deleted)}"

    # Solo seguimos si tenemos un path absoluto. Si no, el proceso no es analizable
    # (kernel thread, exec efímero, o cmd parcial). Lo ignoramos en silencio.
    [[ "$exe_path" == /* ]] || continue

    # Filtro: solo seguimos analizando si el path es "sospechoso"
    _path_is_suspicious "$exe_path" || continue
    interesting_count=$((interesting_count + 1))

    local exe_perms exe_owner cwd
    exe_perms=$(stat -c '%a' "$exe_path" 2>/dev/null || echo "?")
    exe_owner=$(stat -c '%U' "$exe_path" 2>/dev/null || echo "?")
    cwd=$(readlink "/proc/$pid/cwd" 2>/dev/null || echo "?")

    mod_info "Proceso root no estándar: PID=$pid exe=$exe_path"

    # Binario escribible por el usuario actual = escalada inmediata
    if [[ -w "$exe_path" ]]; then
      mod_critical "Binario de proceso root ESCRIBIBLE: $exe_path (PID=$pid)"
      add_finding "process_root_writable_binary" "critical" \
        "Binario de proceso root ESCRIBIBLE: $exe_path (PID=$pid)" \
        "pid=$pid" "path=$exe_path" "owner=$exe_owner" "perms=$exe_perms" \
        "cmd=${cmd:0:120}"
      print_verbose "Reemplazar el binario y esperar reinicio del servicio = root"
    fi

    # Directorio del binario escribible = posible plant de librerías o swap del binario
    local exe_dir
    exe_dir=$(dirname "$exe_path" 2>/dev/null || echo "")
    if [[ -n "$exe_dir" && -w "$exe_dir" ]]; then
      mod_critical "Directorio del binario root ESCRIBIBLE: $exe_dir (PID=$pid)"
      add_finding "process_root_writable_dir" "critical" \
        "Directorio del binario root ESCRIBIBLE: $exe_dir (PID=$pid)" \
        "pid=$pid" "directory=$exe_dir" "binary=$exe_path"
    fi

    # CWD escribible: si el proceso hace dlopen relativo o lee archivos relativos,
    # podemos plantar contenido malicioso ahí
    if [[ "$cwd" != "?" && -w "$cwd" ]]; then
      mod_warning "CWD del proceso root ESCRIBIBLE: $cwd (PID=$pid, exe=$exe_path)"
      add_finding "process_root_writable_cwd" "warning" \
        "CWD del proceso root ESCRIBIBLE: $cwd (PID=$pid)" \
        "pid=$pid" "cwd=$cwd" "binary=$exe_path"
    fi
  done < "$root_procs_tmp"

  mod_info "Procesos root interesantes (no en paquetes del sistema): $interesting_count"

  # ── Tokens y secretos en /proc/*/environ y /proc/*/cmdline ────────────────
  mod_info "Buscando secretos en /proc/*/environ y /proc/*/cmdline (procesos ajenos)..."

  local env_hits=0 cmd_hits=0
  # Patrones (grep -i): nombres de variables / argumentos típicos
  local secret_pattern='(PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|APIKEY|PRIVATE_KEY|AWS_SECRET|DB_PASS|MYSQL_PWD|PGPASSWORD|GITHUB_TOKEN|GITLAB_TOKEN|SLACK_TOKEN|CREDENTIAL)='
  local cmd_secret_pattern='(-p[^[:space:]]+|--password=|sshpass|MYSQL_PWD=|PGPASSWORD=)'

  for proc_dir in /proc/[0-9]*; do
    [[ -d "$proc_dir" ]] || continue
    local pid; pid="${proc_dir##*/}"
    # Skip kernel threads en seco: no tienen /proc/<pid>/exe
    [[ -L "$proc_dir/exe" ]] || continue

    # Obtener UID del proceso desde /proc/<pid>/status (no fork de stat).
    # Línea: "Uid:\t<real>\t<eff>\t<saved>\t<fs>"  — nos basta con el real.
    local proc_uid="?"
    if [[ -r "$proc_dir/status" ]]; then
      while IFS= read -r sline; do
        if [[ "$sline" == Uid:* ]]; then
          # Tras 'Uid:' hay tabs y luego dígitos; nos quedamos con el primer entero
          proc_uid="${sline#Uid:*[$'\t ']}"; proc_uid="${proc_uid%%[$'\t ']*}"
          break
        fi
      done < "$proc_dir/status"
    fi
    # Evitar procesos del propio usuario (lo que vemos con env ya está cubierto)
    [[ "$proc_uid" == "$current_uid" ]] && continue

    # /proc/<pid>/environ — separado por NUL
    if [[ -r "$proc_dir/environ" ]]; then
      local env_owner; env_owner=$(stat -c '%U' "$proc_dir/environ" 2>/dev/null || echo "?")
      while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        local varname varval
        varname="${line%%=*}"
        varval="${line#*=}"
        mod_critical "Secreto en /proc/$pid/environ (owner=$env_owner): ${varname}=${varval:0:4}[REDACTED]"
        add_finding "process_env_secret" "critical" \
          "Secreto en /proc/$pid/environ (owner=$env_owner): ${varname}=${varval:0:4}[REDACTED]" \
          "pid=$pid" "owner=$env_owner" "var=$varname" "preview=${varval:0:4}"
        env_hits=$((env_hits + 1))
      done < <(tr '\0' '\n' < "$proc_dir/environ" 2>/dev/null \
                | grep -iE "^${secret_pattern}" | head -5 || true)
    fi

    # /proc/<pid>/cmdline — passwords como argumentos
    if [[ -r "$proc_dir/cmdline" ]]; then
      local cmdline
      cmdline=$(tr '\0' ' ' < "$proc_dir/cmdline" 2>/dev/null | head -c 500 || echo "")
      [[ -z "$cmdline" ]] && continue

      if [[ "$cmdline" =~ $cmd_secret_pattern ]]; then
        local cmd_owner; cmd_owner=$(stat -c '%U' "$proc_dir/cmdline" 2>/dev/null || echo "?")
        # Redactar el match preservando solo primeros 3 chars del valor
        local redacted
        redacted=$(echo "$cmdline" | sed -E \
          's/(-p|--password=|MYSQL_PWD=|PGPASSWORD=)([^[:space:]]{1,3})[^[:space:]]*/\1\2[REDACTED]/g')
        mod_critical "Password en /proc/$pid/cmdline (owner=$cmd_owner): ${redacted:0:120}"
        add_finding "process_cmdline_secret" "critical" \
          "Password en /proc/$pid/cmdline (owner=$cmd_owner): ${redacted:0:120}" \
          "pid=$pid" "owner=$cmd_owner" "preview=${redacted:0:120}"
        cmd_hits=$((cmd_hits + 1))
      fi
    fi
  done

  if [[ $env_hits -eq 0 ]]; then
    mod_ok "No se encontraron secretos en /proc/*/environ accesibles"
  else
    mod_info "Total secretos en environ: $env_hits"
  fi

  if [[ $cmd_hits -eq 0 ]]; then
    mod_ok "No se encontraron passwords en /proc/*/cmdline accesibles"
  else
    mod_info "Total passwords en cmdline: $cmd_hits"
  fi

  # ── Sockets unix con permisos relajados ───────────────────────────────────
  mod_info "Revisando sockets unix..."

  # Sockets de daemons del sistema esperados con permisos típicos relajados — los marcamos como info
  local socket_checked=0 socket_hits=0
  for sock_path in $(find /var/run /run /tmp -maxdepth 4 -type s 2>/dev/null | head -100); do
    [[ -S "$sock_path" ]] || continue
    socket_checked=$((socket_checked + 1))
    local sock_perms sock_owner sock_group
    sock_perms=$(stat -c '%a' "$sock_path" 2>/dev/null || echo "?")
    sock_owner=$(stat -c '%U' "$sock_path" 2>/dev/null || echo "?")
    sock_group=$(stat -c '%G' "$sock_path" 2>/dev/null || echo "?")

    # Skip ciertos sockets esperados (systemd internals con perms estándar)
    case "$sock_path" in
      /run/systemd/notify|/run/systemd/journal/*|/run/systemd/private*|/run/systemd/io.system.ManagedOOM)
        continue ;;
    esac

    # Detectar permisos relajados
    # World-writable (cualquier "?" en último dígito = otros) o group-writable a grupos amplios
    local world_writable=false world_readable=false
    case "${sock_perms: -1}" in
      2|3|6|7) world_writable=true ;;
      4|5)     world_readable=true ;;
    esac

    if [[ -w "$sock_path" && "$sock_owner" != "$current_user" ]]; then
      socket_hits=$((socket_hits + 1))
      # ¿de qué daemon es? buscar el proceso que lo abrió (lsof si está)
      local sock_proc=""
      if command -v lsof &>/dev/null; then
        sock_proc=$(lsof -t "$sock_path" 2>/dev/null | head -1 || echo "")
      fi
      mod_critical "Socket unix ESCRIBIBLE por nuestro user: $sock_path (owner=$sock_owner:$sock_group perms=$sock_perms)"
      add_finding "unix_socket_writable" "critical" \
        "Socket unix ESCRIBIBLE: $sock_path (owner=$sock_owner:$sock_group)" \
        "path=$sock_path" "owner=$sock_owner" "group=$sock_group" \
        "perms=$sock_perms" "pid=${sock_proc:-unknown}"
    elif $world_writable; then
      socket_hits=$((socket_hits + 1))
      mod_critical "Socket unix WORLD-WRITABLE: $sock_path (perms=$sock_perms, owner=$sock_owner)"
      add_finding "unix_socket_writable" "critical" \
        "Socket unix WORLD-WRITABLE: $sock_path (owner=$sock_owner, perms=$sock_perms)" \
        "path=$sock_path" "owner=$sock_owner" "perms=$sock_perms"
    elif $world_readable && [[ "$sock_owner" == "root" ]]; then
      mod_warning "Socket unix de root WORLD-READABLE: $sock_path (perms=$sock_perms)"
      add_finding "unix_socket_readable" "warning" \
        "Socket unix de root WORLD-READABLE: $sock_path (perms=$sock_perms)" \
        "path=$sock_path" "owner=$sock_owner" "perms=$sock_perms"
    fi
  done

  mod_info "Sockets unix revisados: $socket_checked, con permisos relajados: $socket_hits"

  # ── Configs de shell hijackeables ─────────────────────────────────────────
  mod_info "Revisando configs de shell de otros usuarios..."

  # /etc/profile.d/* — se ejecuta para todo login interactivo
  if [[ -d /etc/profile.d ]]; then
    while IFS= read -r f; do
      [[ -n "$f" ]] || continue
      mod_critical "Script de /etc/profile.d ESCRIBIBLE: $f"
      add_finding "profile_d_writable" "critical" \
        "Script de /etc/profile.d ESCRIBIBLE: $f — escalada al próximo login de cualquier usuario" \
        "path=$f"
    done < <(find /etc/profile.d -maxdepth 1 -type f -writable 2>/dev/null || true)
  fi

  # /etc/profile, /etc/bashrc, /etc/bash.bashrc, /etc/zsh/zshrc — globales
  for f in /etc/profile /etc/bashrc /etc/bash.bashrc /etc/zsh/zshrc /etc/zshrc; do
    [[ -f "$f" && -w "$f" ]] || continue
    mod_critical "Config global de shell ESCRIBIBLE: $f"
    add_finding "shell_rc_writable" "critical" \
      "Config global de shell ESCRIBIBLE: $f — escalada al próximo login" \
      "path=$f" "scope=global"
  done

  # .bashrc / .zshrc / .profile de OTROS usuarios (incluyendo root)
  for home_dir in /root /home/*; do
    [[ -d "$home_dir" ]] || continue
    local home_owner; home_owner=$(stat -c '%U' "$home_dir" 2>/dev/null || echo "?")
    [[ "$home_owner" == "$current_user" ]] && continue
    for rc_name in .bashrc .zshrc .profile .bash_profile .bash_login .bash_logout .zshenv .zlogin; do
      local rc="$home_dir/$rc_name"
      [[ -f "$rc" && -w "$rc" ]] || continue
      mod_critical "Config de shell de OTRO usuario ESCRIBIBLE: $rc (owner=$home_owner)"
      add_finding "shell_rc_writable" "critical" \
        "Config de shell de OTRO usuario ESCRIBIBLE: $rc (owner=$home_owner)" \
        "path=$rc" "owner=$home_owner" "scope=user"
    done
  done

  flush_module_json "Procesos y shell"
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

  # Findings estructurados (vista plana, todos los módulos juntos)
  local findings_str="" first_f=true
  for f in "${STRUCTURED_FINDINGS[@]+"${STRUCTURED_FINDINGS[@]}"}"; do
    $first_f || findings_str+=","
    findings_str+="$f"
    first_f=false
  done

  cat > "$json_path" <<EOF
{
  "report": {
    "tool": "roothunter.sh",
    "version": "1.2.4",
    "schema_version": "2",
    "timestamp": "$TIMESTAMP_ISO",
    "script_sha256": "$SCRIPT_SHA256",
    "target": {
      "hostname": "$(json_escape "$(hostname 2>/dev/null || echo '?')")",
      "kernel": "$(json_escape "$(uname -r)")",
      "os": "$(json_escape "$(grep -oP '(?<=^PRETTY_NAME=").+(?=")' /etc/os-release 2>/dev/null || uname -s)")",
      "user": "$CURRENT_USER",
      "uid": $CURRENT_UID,
      "groups": "$(json_escape "$CURRENT_GROUPS")"
    },
    "summary": {
      "critical": ${#FINDINGS[@]},
      "warnings": ${#WARNINGS[@]},
      "info": ${#INFOS[@]},
      "structured_findings": ${#STRUCTURED_FINDINGS[@]}
    },
    "findings": [
      $findings_str
    ],
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
  echo -e "${BOLD}  Script de Auditoría de Seguridad Linux v1.2.4${RESET}"
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
    [processes]="check_processes:Procesos y shell:60"
  )

  local MODULE_ORDER=(
    sysinfo suid sudo cron files caps kernel nfs
    history services env users containers cloud systemd pam processes
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
