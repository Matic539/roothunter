# =============================================================================
#  suid_whitelist.py — SUID binarios legítimos esperados por distro
#  Parte de la suite RootHunter (rh-analyze)
#
#  Propósito: reducir falsos positivos en el output de roothunter.sh.
#  Binarios como /usr/bin/sudo o /usr/bin/passwd son SUID por diseño en casi
#  toda distro Linux. Reportarlos como "crítico" satura el output y hace
#  más difícil ver los SUID realmente sospechosos.
#
#  El analyzer rebaja la severidad a "info" cuando el (path, distro) está en
#  la whitelist, y descuenta esos findings del score de riesgo.
#
#  Uso desde rh-analyze:
#    is_legitimate(path, os_name) -> (bool, reason)
#
#  Política: "whitelist por path completo, no por basename". Esto evita que
#  un atacante deje una copia de bash en /tmp/sudo y se cuele como legítima
#  solo porque el basename coincide.
# =============================================================================

# ─── SUIDs comunes a todas las distros Linux ──────────────────────────────────
# Estos paths existen en prácticamente cualquier instalación Linux estándar.
# Son SUID porque la funcionalidad lo requiere (cambio de contraseña, mount,
# elevación a root vía sudo, etc.).
COMMON = {
    '/usr/bin/sudo':            'sudo: necesita SUID para ejecutar como otro usuario',
    '/usr/bin/su':              'su: cambio de usuario requiere root',
    '/bin/su':                  'su (path tradicional)',
    '/usr/bin/passwd':          'passwd: actualiza /etc/shadow (root-only)',
    '/usr/bin/chsh':            'chsh: modifica shell del usuario',
    '/usr/bin/chfn':            'chfn: modifica info GECOS',
    '/usr/bin/gpasswd':         'gpasswd: gestión de grupos',
    '/usr/bin/newgrp':          'newgrp: cambio de grupo efectivo',
    '/usr/bin/mount':           'mount: necesita root para montar (en muchas distros)',
    '/bin/mount':               'mount (path tradicional)',
    '/usr/bin/umount':          'umount: contraparte de mount',
    '/bin/umount':              'umount (path tradicional)',
    '/usr/bin/pkexec':          'pkexec: PolicyKit (revisar versión por PwnKit)',
    '/usr/bin/fusermount':      'fusermount: monta filesystems FUSE',
    '/usr/bin/fusermount3':     'fusermount3: versión moderna',
    '/bin/fusermount':          'fusermount (path tradicional)',
    '/usr/lib/dbus-1.0/dbus-daemon-launch-helper': 'dbus-daemon-launch-helper',
    '/usr/lib/policykit-1/polkit-agent-helper-1':   'polkit agent helper',
    '/usr/lib/polkit-1/polkit-agent-helper-1':      'polkit agent helper (variante)',
    '/usr/libexec/polkit-agent-helper-1':           'polkit agent helper (libexec)',
    '/usr/lib/openssh/ssh-keysign':                  'ssh-keysign: autenticación host-based',
    '/usr/libexec/openssh/ssh-keysign':              'ssh-keysign (variante)',
}

# ─── Específicos de Debian/Ubuntu ─────────────────────────────────────────────
DEBIAN = {
    '/usr/bin/chage':                      'chage: cambio de info de contraseña',
    '/usr/bin/expiry':                     'expiry: chequeo de expiración',
    '/usr/sbin/pppd':                      'pppd: PPP daemon (raramente usado hoy)',
    '/usr/sbin/exim4':                     'exim4: MTA',
    '/usr/lib/eject/dmcrypt-get-device':   'dmcrypt-get-device',
    '/usr/lib/snapd/snap-confine':         'snap-confine: sandbox de snaps',
    '/usr/lib/x86_64-linux-gnu/utempter/utempter': 'utempter',
    '/usr/lib/xorg/Xorg.wrap':             'Xorg wrapper',
    '/usr/bin/at':                         'at: scheduler (puede no ser SUID en todas)',
    '/usr/bin/traceroute6.iputils':        'traceroute6 iputils',
    '/usr/bin/ntfs-3g':                    'ntfs-3g: filesystem driver',
    '/usr/bin/arping':                     'arping: requiere raw sockets',
    '/usr/sbin/mount.nfs':                 'mount.nfs',
    '/sbin/mount.nfs':                     'mount.nfs (path tradicional)',
    '/sbin/unix_chkpwd':                   'unix_chkpwd: verificación de password PAM',
    '/usr/sbin/unix_chkpwd':               'unix_chkpwd (path moderno)',
}

# ─── Específicos de RHEL / CentOS / Fedora / Rocky / Alma ────────────────────
RHEL = {
    '/usr/bin/chage':                'chage',
    '/usr/sbin/grub2-set-bootflag':  'grub2-set-bootflag',
    '/usr/libexec/dbus-1/dbus-daemon-launch-helper': 'dbus-daemon-launch-helper (libexec)',
    '/usr/bin/at':                   'at: job scheduler',
    '/usr/bin/crontab':              'crontab: edición de tabs (algunas distros)',
    '/usr/sbin/userhelper':          'userhelper: PAM helper RHEL',
    '/usr/sbin/usernetctl':          'usernetctl',
    '/usr/sbin/mount.nfs':           'mount.nfs',
    '/usr/lib/polkit-1/polkit-agent-helper-1': 'polkit agent helper RHEL',
    '/usr/libexec/utempter/utempter': 'utempter (libexec)',
    '/usr/libexec/Xorg.wrap':        'Xorg wrapper RHEL',
}

# ─── Específicos de Arch / Manjaro ────────────────────────────────────────────
ARCH = {
    '/usr/bin/chage':         'chage',
    '/usr/bin/crontab':       'crontab',
    '/usr/bin/at':            'at',
    '/usr/lib/polkit-1/polkit-agent-helper-1': 'polkit agent helper Arch',
    '/usr/lib/utempter/utempter': 'utempter',
}

# ─── Específicos de Alpine ────────────────────────────────────────────────────
ALPINE = {
    '/bin/busybox':           'busybox: SUID en algunas configuraciones de Alpine',
    '/usr/bin/su-exec':       'su-exec: variante de su minimalista',
}


# ─── Heurística para identificar la familia de distro ─────────────────────────
def detect_distro_family(os_name: str) -> str:
    """Devuelve una de: 'debian', 'rhel', 'arch', 'alpine', 'unknown'.

    Acepta strings tipo 'Ubuntu 22.04 LTS', 'Debian GNU/Linux 12 (bookworm)',
    'Rocky Linux 9.3', 'Arch Linux', 'Alpine Linux v3.19', etc.
    """
    if not os_name:
        return 'unknown'
    s = os_name.lower()
    if 'ubuntu' in s or 'debian' in s or 'mint' in s or 'kali' in s or 'parrot' in s:
        return 'debian'
    if any(x in s for x in ('red hat', 'redhat', 'rhel', 'centos', 'fedora',
                             'rocky', 'almalinux', 'alma linux', 'oracle linux',
                             'amazon linux')):
        return 'rhel'
    if 'arch' in s or 'manjaro' in s or 'endeavouros' in s:
        return 'arch'
    if 'alpine' in s:
        return 'alpine'
    return 'unknown'


def _whitelist_for_family(family: str) -> dict:
    """Construye el set efectivo: COMMON + específico de la familia."""
    merged = dict(COMMON)
    if family == 'debian':
        merged.update(DEBIAN)
    elif family == 'rhel':
        merged.update(RHEL)
    elif family == 'arch':
        merged.update(ARCH)
    elif family == 'alpine':
        merged.update(ALPINE)
    # 'unknown' usa solo COMMON — comportamiento conservador
    return merged


# ─── API pública ──────────────────────────────────────────────────────────────

def is_legitimate(path: str, os_name: str = '') -> tuple[bool, str]:
    """¿El binario SUID en `path` es legítimo para la distro `os_name`?

    Devuelve (es_legitimo, razon). Si es_legitimo=False, razon='' por convención.

    El matching es por path completo. NO se hace matching por basename, para
    no aceptar /tmp/passwd como legítimo solo porque exista /usr/bin/passwd
    legítimo en la distro.
    """
    family = detect_distro_family(os_name)
    wl = _whitelist_for_family(family)
    if path in wl:
        return True, wl[path]
    return False, ''


def whitelist_summary() -> dict:
    """Resumen de coverage para --list-techniques o tests."""
    return {
        'common_count': len(COMMON),
        'debian_count': len(DEBIAN),
        'rhel_count': len(RHEL),
        'arch_count': len(ARCH),
        'alpine_count': len(ALPINE),
        'total_unique_paths': len(set(COMMON) | set(DEBIAN) | set(RHEL)
                                  | set(ARCH) | set(ALPINE)),
    }


if __name__ == '__main__':
    import json
    print(json.dumps(whitelist_summary(), indent=2))
    # Pequeña demo
    print()
    for path, distro in [
        ('/usr/bin/sudo', 'Ubuntu 22.04'),
        ('/usr/bin/passwd', 'Rocky Linux 9'),
        ('/tmp/passwd', 'Ubuntu 22.04'),     # NO debe matchear
        ('/usr/bin/find', 'Debian 12'),      # NO está whitelisted
        ('/usr/bin/at', 'Ubuntu 22.04'),
    ]:
        ok, why = is_legitimate(path, distro)
        marker = '✓' if ok else '✗'
        print(f"  {marker} {path:30}  [{distro:20}] -> {why or '(no en whitelist)'}")
        