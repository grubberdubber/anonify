# Guía de Arquitectura, Seguridad y Uso Legal: anonify

## Misión

`anonify` es una herramienta CLI en Rust para **hardening de privacidad y anonimato de red temporal y reversible** en Linux. Su objetivo es reducir la identificabilidad de una máquina y de su tráfico frente a observadores de red (ISP, LAN, DPI, correlación de metadatos y fingerprinting), sin alterar la evidencia del sistema ni obstruir investigaciones.

La herramienta debe ser útil para privacidad personal, periodismo, investigación y evaluaciones de seguridad **autorizadas**. No es una herramienta de evasión de la ley, destrucción de evidencia ni anti-forense.

## Límites legales duros (no negociables)

Está **terminantemente prohibido** implementar, documentar o sugerir funcionalidades que:

- Borren, trunquen, roten, redirijan o alteren logs del sistema, `journald`, `auditd`, `dmesg`, logs de autenticación, logs de aplicaciones o cualquier registro sensible.
- Modifiquen timestamps de archivos o metadatos (`atime`, `mtime`, `ctime`, `touch`, `utime`, `debugfs`) para ocultar actividad.
- Borren o alteren historiales de shell, historiales de navegadores, cachés, portapapeles, archivos temporales del usuario o cualquier rastro de evidencia.
- Deshabiliten, silencien o manipulen auditoría del kernel, `auditd`, SELinux, AppArmor, firewalls del sistema, agentes de seguridad o herramientas forenses.
- Oculten procesos, archivos, conexiones, interfaces o usuarios.
- Destruyan, modifiquen o impidan preservar evidencia digital.
- Bloqueen el acceso de autoridades o peritos a sistemas, discos, redes o registros cuando exista una obligación legal de conservarlos.
- Faciliten la evasión de una investigación legal, el encubrimiento de delitos o el uso no autorizado de redes y sistemas.

Si una propuesta de módulo requiere cualquiera de esas acciones, **debe rechazarse** aunque el resto del diseño sea técnicamente brillante. La privacidad legítima se consigue minimizando los datos que genera la herramienta, no borrando los que genera el sistema.

## Modelo de amenaza

**Dentro del alcance:**

- Observación pasiva de red: ISP, operador Wi-Fi, LAN, vecinos, puntos de acceso.
- Fingerprinting de red: MAC, hostname, DNS, IPv6, timestamps TCP, ICMP, stack fingerprint.
- Fugas accidentales: DNS en claro, IPv6, ICMP, tráfico fuera del túnel, reconexiones de daemons.
- Correlación de metadatos de red y de sesión.
- Análisis de tráfico profundo (DPI) a nivel de red.

**Fuera del alcance:**

- Anonimato absoluto o garantizado.
- Compromiso del endpoint, malware, keyloggers, ataques físicos o DMA.
- Correlación global por adversarios con visibilidad simultánea de múltiples redes.
- Evasión de investigación legal o destrucción de evidencia.
- Protección de identidad en cuentas autenticadas, pagos o contenido que el usuario publique deliberadamente.

## Principios de diseño

1. **Reversibilidad y estado volátil.** El estado propio de `anonify` vive en `/run/anonify` (tmpfs) y en el kernel en tiempo de ejecución: tablas `nftables`, `sysctl`, interfaces, bind mounts. No se escriben secretos ni historiales en disco. La herramienta no debe prometer que programas de terceros (por ejemplo `wg-quick` o `NetworkManager`) no toquen estado del sistema; debe documentarlo y restaurarlo cuando sea posible.
2. **Fail-closed.** Si una capa de anonimato falla, la red se bloquea antes de permitir una fuga en claro. `tor` instala su propia política fail-closed antes del bootstrap; `vpn` advierte si se activa sin `killswitch`, porque el kill switch es parte de la arquitectura y no un extra opcional para uso anónimo.
3. **Minimización de datos.** `anonify` no registra actividad del usuario. Los mensajes van a `stderr`, y los logs técnicos imprescindibles (por ejemplo, el aviso de arranque de Tor) viven en tmpfs y desaparecen al reiniciar. No se tocan logs del sistema.
4. **Restauración verificable.** Cada cambio guarda el valor original y se verifica leyendo el estado real. Si una restauración falla, el estado original se conserva para reintentar; nunca se descarta silenciosamente.
5. **Mínimo privilegio.** Root solo cuando la operación lo exige. Se prefieren cambios runtime (`nmcli device modify`, `nft`, `sysctl`) frente a modificaciones persistentes de perfiles o archivos de configuración.
6. **Sin fugas por defecto.** No se hacen peticiones a Internet en claro durante `check` si no hay una capa de anonimato activa. No se resuelve DNS fuera del túnel cuando hay un túnel activo.
7. **Transparencia.** Cada módulo documenta qué cambia, cómo se revierte, qué riesgos tiene y qué no protege.

## Prohibiciones explícitas (veto de revisión)

- `logs`, `audit`, `journal`, `history`, `timestamps`, `wipe`, `shred`, `unlink` de registros del sistema o del usuario.
- Cualquier módulo llamado “anti-forense”, “limpieza de rastros”, “borrado seguro” o similar.
- Bloqueo de `auditd`, `systemd-journald`, `rsyslog`, `dmesg`, `kdump`, `pstore` o herramientas de respuesta a incidentes.
- Modificación de `/etc/machine-id`, `/etc/hostname` persistente, claves SSH, historiales o metadatos de archivos del usuario.
- “Spoofing” de reloj o zona horaria del sistema que altere timestamps de logs o archivos. Solo se permite aislar la zona horaria/locale de **aplicaciones lanzadas** por `launch`, sin tocar el reloj del sistema.
- Bloqueo de buses USB o periféricos para impedir análisis forense. El hardening de buses solo se acepta si es una política de seguridad del usuario y no una medida para ocultar evidencia.

## Módulos permitidos y roadmap

**Core actual:** `mac`, `hostname`, `sysctl`, `ipv6`, `dns`, `tor`, `vpn`, `killswitch`, `check`, `launch`.

**Expansión aceptada (con revisión legal y de seguridad):**

- `netns`/`bubblewrap`: aislamiento de aplicaciones en namespaces de red efímeros.
- `clock`/`timezone` para apps lanzadas: `TZ`, `LANG`, `LC_*` aislados en el proceso hijo.
- `memory`: `mlock`/`zeroize` para secretos del propio proceso, sin borrar memoria del sistema ni evidencia.
- `dns`: DoT/DoH local, resolución forzada por Tor, verificación de fugas.
- `check`: auditoría activa/pasiva de DNS, IPv6, MAC, hostname, rutas, Tor/VPN y kill switch.
- `mac`: listas OUI seguras y evasión de fingerprint OUI, siempre con MAC localmente administrada cuando sea posible.
- `launch`: perfiles efímeros de navegador en `/dev/shm`, sin persistencia.
- `scrub`: eliminación de metadatos EXIF/geo en **copias** que el usuario seleccione explícitamente, sin alterar originales ni timestamps sin consentimiento.

Cualquier módulo nuevo debe incluir: modelo de amenaza, mecanismo de reversión, pruebas, impacto legal y análisis de fugas.

## Reglas de desarrollo en Rust

1. **Rust idiomático y riguroso.** Edición 2021+, `clippy` en modo `pedantic`, errores explícitos con `thiserror`/`anyhow`. No usar `unwrap()` ni `expect()` en código de producción.
2. **Cero `unsafe` innecesario.** Priorizar crates seguros (`nix`, `rtnetlink`, `libc` solo para FFI imprescindible). Todo `unsafe` debe llevar un comentario `SAFETY` que justifique la invariante.
3. **Sin inyección de comandos.** Ejecutar programas con argumentos separados; nunca construir una shell con datos de usuario. Validar UIDs, IPs, puertos y nombres de interfaz antes de interpolarlos en reglas `nftables`.
4. **Estado atómico.** `state.json` se escribe con `temp + fsync + rename`, permisos `0600`, y un lock `flock`. Un estado corrupto debe producir un error claro, no un reinicio silencioso que pierda los valores originales.
5. **Pruebas.** Lógica pura con tests unitarios; operaciones de red en un namespace de usuario (`unshare -rn`) o en CI aislada. Nada de pruebas que toquen la red real del desarrollador.
6. **Commits.** Conventional Commits (`feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`, `security:`), atómicos y con el “por qué” en el cuerpo. No incluir secretos, claves ni configuraciones personales.

## Formato de salida esperado

1. Código Rust limpio, modular y listo para `src/modules/...`.
2. Explicación de los mecanismos de red y privacidad (nftables, sysctl, `unshare`, ioctls, NetworkManager runtime).
3. Evaluación crítica: si una propuesta toca logs, auditoría, timestamps o evidencia, debe rediseñarse antes de mostrarse. Si deja rastros persistentes innecesarios, debe justificarse y documentarse.
