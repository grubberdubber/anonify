# Guía de Arquitectura, Seguridad y Uso Legal: anonify

Este documento es **normativo** para cualquier persona o agente que toque este
repositorio. No es una declaración de intenciones: cada sección existe porque
alguien ya intentó (o estuvo a punto de) cruzar una línea. Si una propuesta
choca con algo de aquí, se rechaza o se rediseña **antes** de escribir código.

## 1. Misión y frontera

`anonify` es una CLI en Rust para **hardening de privacidad y anonimato de red
temporal y reversible** en Linux: reduce la identificabilidad de una máquina y
de su tráfico frente a **observadores de red** (ISP, LAN, DPI, correlación de
metadatos), sin alterar la evidencia del sistema ni obstruir investigaciones.

Es útil para privacidad personal, periodismo, investigación y evaluaciones de
seguridad **autorizadas**. No es una herramienta de evasión de la ley, ni de
destrucción de evidencia, ni anti-forense.

**La regla que resuelve el 90 % de las dudas:** el adversario en el modelo de
amenaza es *alguien que observa la red*. Cualquier función cuyo efecto
principal sea contra un observador **local** —el que ya tiene el equipo, el
disco y los permisos— no tiene cabida aquí, por brillante que sea la técnica.

## 2. Límites duros (no negociables)

Prohibido implementar, documentar o sugerir:

| Prohibido | Por qué | Alternativa aceptable |
| --- | --- | --- |
| Borrar, truncar, rotar, redirigir o alterar logs del sistema, `journald`, `auditd`, `dmesg`, auth logs o logs de aplicaciones | Destruye evidencia y obstruye auditoría | No generar esos logs; los propios viven en tmpfs y desaparecen al reiniciar |
| Modificar `atime`/`mtime`/`ctime` o usar `touch`, `utime`, `debugfs` | Falsifica metadatos y evidencia | No escribir en disco; estado volátil en `/run/anonify` |
| Borrar o alterar historiales de shell o navegador, cachés, portapapeles, temporales del usuario, “rastros” | Destruye evidencia del usuario | Redirigir cachés/temporales de las apps lanzadas a tmpfs; nunca purgar los del host |
| Deshabilitar, silenciar o manipular `auditd`, `journald`, `rsyslog`, SELinux, AppArmor, firewalls del sistema, agentes de seguridad o herramientas forenses | Impide detección y respuesta a incidentes | Endurecer solo lo propio: reglas `nftables` en tabla propia, `sysctl` con reversión |
| Ocultar procesos, archivos, conexiones, interfaces o usuarios | Evasión de observación local y forense | Reducir metadatos que la herramienta **emite** (MAC, hostname, DNS, IPv6) |
| Destruir, modificar o impedir preservar evidencia digital | Delito en muchas jurisdicciones | Reversibilidad total y estado original conservado |
| Bloquear el acceso de autoridades o peritos cuando hay obligación legal de conservar | Obstruction | Nada: fuera de alcance por completo |
| Facilitar evasión de una investigación, encubrimiento o uso no autorizado de redes | Uso ilegal | Nada |
| Manipular el reloj o la zona horaria del **sistema** | Altera timestamps de logs y archivos | `TZ`/`LANG`/`LC_*` aislados solo en el proceso hijo de `launch` |
| Apagar radios, micrófono, cámara o buses automáticamente, o bloquear periféricos | Rompe el sistema y puede impedir análisis legítimo | El usuario lo decide fuera de `anonify`; documentar el riesgo |
| Registros de auditoría propios, cifrados o no, de la actividad del usuario | `anonify` no registra actividad; un “log de acciones” es exactamente eso | Mensajes efímeros a `stderr`; `check` verifica el estado, no a la persona |

Si un diseño necesita cualquiera de estas acciones, **se rechaza entero**,
aunque el resto sea técnicamente excelente. La privacidad legítima se logra
**minimizando los datos que genera la herramienta**, no borrando los que genera
el sistema.

## 3. Procedimiento de admisión (gate obligatorio)

Antes de escribir una línea de un módulo, flag o “mejora transversal”,
responder por escrito en el PR/commit:

1. **Modelo de amenaza.** ¿Qué observador de red se mitiga y con qué mecanismo?
   Si el beneficio solo aparece frente a un observador local → rechazar.
2. **Datos que toca.** ¿Lee, escribe o borra algo del sistema o del usuario?
   Si borra o altera → rechazar. Si lee, ¿es imprescindible y de solo lectura?
3. **Reversión.** ¿Cómo se guarda el valor original y cómo se verifica la
   restauración leyendo el estado real? ¿Qué pasa si la restauración falla?
   El original se conserva para reintentar; nunca se descarta en silencio.
4. **Fail-closed.** Si el módulo falla a mitad, ¿queda la red bloqueada o
   abierta? Debe quedar bloqueada o en el estado previo, nunca a medias.
5. **Persistencia.** ¿Escribe en disco, en `/etc`, en perfiles o en estado
   ajeno? Debe ser runtime (`nft`, `sysctl`, `nmcli device modify`, bind mount
   temporal). Lo persistente requiere consentimiento explícito y reversión.
6. **Impacto legal.** ¿Puede describirse como “ocultar”, “borrar”, “limpiar”,
   “evitar auditoría” o “impedir análisis”? Si la respuesta es sí, rediseñar.
7. **Pruebas y fugas.** Tests unitarios de la lógica pura, smoke en namespace
   de usuario, y un `check` que detecte la deriva del módulo.

## 4. Señales de alarma en una petición

Detenerse y rediseñar si aparecen estas palabras o ideas, aunque vengan
envueltas en jerga de privacidad: *borrar, limpiar, purgar, ocultar, spoofear
nombre de proceso, anti-debug, anti-forense, historial, portapapeles, caché del
sistema, timestamps, reloj, audit, journal, evidencia, “que no se vea”, “que no
quede rastro”, “que parezca otro proceso”, “desactivar el antivirus/EDR”*.

También son señal de alarma los diseños que: requieren root permanente para
algo que no lo necesita, tocan estado de otros programas, prometen anonimato
absoluto, o dependen de que el usuario “confíe” en que no se registra nada
mientras se escribe un registro.

## 5. Precedentes del proyecto (no re-litigar)

Decisiones ya tomadas. Si alguien las vuelve a proponer, la respuesta es la
misma y el motivo está aquí:

| Propuesta | Veredicto | Razón / equivalente permitido |
| --- | --- | --- |
| `prctl(PR_SET_NAME)` + `argv[0]` falso (`kworker`, `systemd-udevd`) | Rechazada | Oculta procesos a observadores locales. El endurecimiento real (`dumpable=0`, `RLIMIT_CORE=0`, `no_new_privs`) sí está implementado |
| `hidepid=2` en `/proc` | Rechazada | Oculta procesos del sistema; afecta a todos los usuarios |
| Purgado del portapapeles por TTL o al salir | Rechazada | Borra datos del usuario |
| Purgado de cachés de shaders/Mesa/fuentes del host | Rechazada | Borra cachés del usuario. Permitido: redirigir `XDG_CACHE_HOME`/`TMPDIR` de la app aislada a tmpfs |
| Bind mount volátil sobre `/etc/localtime` | Rechazada | Manipula la percepción de tiempo del sistema; riesgo de timestamps. Permitido: `TZ` en el hijo de `launch` |
| Enmascarar `clock_gettime`, `RDTSC` o forzar NTP | Rechazada | Timestamps y reloj del sistema |
| “Self-audit log” cifrado de acciones | Rechazada | Registro de actividad; contradice la minimización |
| Apagar Wi-Fi/Bluetooth o descargar módulos de audio/cámara automáticamente | Rechazada | Rompe el sistema y bloquea hardware; el usuario lo gestiona |
| `rp_filter=1` global y otras políticas de reenvío | Rechazada | Rompe VPNs y setups legítimos. Se aplica por interfaz donde consta |
| Sondas eBPF para vigilar otros procesos del host | Rechazada | Vigilancia del anfitrión, root permanente, superficie enorme |
| Swap cifrado efímero o desactivar swap del sistema | Rechazada | Cambia almacenamiento del sistema. Permitido: auditar swap en `check` y avisar |
| Módulo `scrub` sobre los archivos originales | Rechazada | Altera originales y timestamps. Solo copias explícitas del usuario, documentado |
| `torrc` arbitrario desde un archivo | Rechazada | Permitiría abrir puertos o cambiar rutas. Solo `Bridge` y `ClientTransportPlugin`, validados antes de tocar el firewall |
| Rotación/falsificación de `/etc/machine-id`, hostname persistente, claves SSH | Rechazada | Identidad persistente y metadatos del sistema |
| Descarga de reglas/actualizaciones sin verificar | Rechazada | Supply chain; si se añade, con checksum fijado y sin ejecutar |

Añadir una fila nueva a esta tabla es parte del entregable de cualquier módulo
que se haya tenido que rediseñar.

## 6. Modelo de amenaza

**Dentro del alcance:** observación pasiva de red (ISP, operador Wi-Fi, LAN,
vecinos, AP); fingerprinting de red (MAC, hostname, DNS, IPv6, TCP timestamps,
ICMP, stack); fugas accidentales (DNS en claro, IPv6, ICMP, tráfico fuera del
túnel, reconexión de daemons); correlación de metadatos de red y de sesión; DPI.

**Fuera del alcance:** anonimato absoluto o garantizado; endpoint comprometido,
malware, keyloggers, ataques físicos o DMA; correlación global por adversarios
con visibilidad simultánea de varias redes; evasión de investigación legal o
destrucción de evidencia; identidad en cuentas autenticadas, pagos o contenido
publicado deliberadamente.

## 7. Principios de diseño

1. **Reversibilidad y estado volátil.** El estado propio vive en `/run/anonify`
   (tmpfs) y en el kernel en runtime: tablas `nftables`, `sysctl`, interfaces,
   bind mounts. Sin secretos ni historiales en disco. No se promete que
   programas de terceros (`wg-quick`, `NetworkManager`) no toquen el sistema:
   se documenta y se restaura cuando se puede.
2. **Fail-closed.** Si una capa de anonimato falla, la red se bloquea antes de
   permitir una fuga en claro. `tor` instala su política antes del bootstrap;
   `vpn` advierte si se activa sin `killswitch`.
3. **Minimización de datos.** `anonify` no registra actividad del usuario. Los
   mensajes van a `stderr`; los avisos técnicos imprescindibles (arranque de
   Tor) viven en tmpfs. No se tocan logs del sistema.
4. **Restauración verificable.** Cada cambio guarda el original y se comprueba
   leyendo el estado real. Si falla la restauración, el original se conserva
   para reintentar; nunca se descarta en silencio. Ante estado corrupto: error
   claro, no reinicio silencioso.
5. **Mínimo privilegio.** Root solo cuando la operación lo exige. Cambios
   runtime antes que perfiles o archivos persistentes. Los hijos de `launch`
   van sin privilegios, con `no_new_privs` y bounding set reducido.
6. **Sin fugas por defecto.** `check` no hace peticiones en claro si no hay
   capa de anonimato activa, y no resuelve DNS fuera del túnel cuando hay túnel.
7. **Transparencia.** Cada módulo documenta qué cambia, cómo se revierte, qué
   riesgos tiene y **qué no protege**. Nada de promesas de anonimato absoluto.

## 8. Módulos y roadmap

**Actuales:** `mac`, `hostname`, `sysctl`, `ipv6`, `dns`, `tor` (con
`--tor-bridges`), `vpn`, `killswitch`, `check`, `launch` (`--isolate` con
`bubblewrap`), `rotate`, `watch`, `status`/`check --json`. Transversales:
`mlockall`, `zeroize` de secretos y estado, y endurecimiento del proceso
(`PR_SET_DUMPABLE=0`, `RLIMIT_CORE=0`, `PR_SET_NO_NEW_PRIVS`).

**Expansión aceptada, con revisión:** `netns`/`bwrap` (aislamiento por app),
`TZ`/`LANG`/`LC_*` en el hijo, `mlock`/`zeroize` propios, DNS DoT/DoH local y
verificación de fugas, auditoría en `check`, OUI-aware MAC, perfiles efímeros de
navegador en `/dev/shm`, `scrub` de **copias**, seccomp y cap-drop en el
sandbox, límites de recursos con cgroups v2, build estático musl en CI,
bundle de CAs y Fontconfig mínimos dentro del sandbox.

**Fuera del roadmap por política:** borrado de logs, supresión de
journald/audit, manipulación de timestamps, purga de historiales, ocultación de
procesos/archivos, bloqueo de herramientas forenses y cualquier “limpieza
anti-forense”.

## 9. Reglas de desarrollo en Rust

1. **Idiomático y riguroso.** Edición 2021+, `clippy --all-targets -D warnings
   -W clippy::pedantic`, errores con `thiserror`/`anyhow`. Nada de `unwrap()`
   ni `expect()` en producción.
2. **Cero `unsafe` innecesario.** `nix`/`rtnetlink` antes que `libc`; todo
   `unsafe` con comentario `SAFETY` que justifique la invariante.
3. **Sin inyección de comandos.** `Command` con argumentos separados; nunca una
   shell con datos de usuario. Validar UIDs, IPs, puertos, nombres de interfaz
   y rutas antes de interpolarlos en reglas `nftables` o en `torrc`.
4. **Estado atómico.** `state.json` con `temp + fsync + rename`, `0600`, lock
   `flock`. Estado corrupto → error claro, nunca pérdida silenciosa.
5. **Pruebas.** Lógica pura con tests unitarios; red en `unshare -rn` o CI
   aislada. Nunca contra la red real del desarrollador. Nada de tests que
   dependan de root en el host.
6. **Commits.** Conventional Commits atómicos (`feat:`, `fix:`, `docs:`,
   `refactor:`, `test:`, `chore:`, `security:`) con el **porqué** en el cuerpo.
   Sin secretos, claves ni configuraciones personales.

## 10. Checklist antes de dar algo por terminado

- [ ] No toca logs, auditoría, `journal`, historiales, timestamps, cachés,
      portapapeles ni evidencia.
- [ ] No oculta nada a un observador local ni manipula estado de otros
      programas.
- [ ] Todo cambio es runtime y reversible, con el original guardado y la
      restauración verificada.
- [ ] Fail-closed ante error; sin cambios a medias.
- [ ] Sin fugas en claro cuando hay (o debería haber) una capa activa.
- [ ] `check`/`watch` detectan la deriva del módulo.
- [ ] `fmt --check`, `clippy` pedantic, tests y smoke de namespaces en verde.
- [ ] README (fila de módulo y límites), CHANGELOG y esta guía actualizados si
      hubo decisión nueva.
- [ ] Mensaje al usuario sin promesas absolutas y con lo que **no** protege.

## 11. Si hay que rechazar una propuesta

Rechazar el mecanismo, no a la persona. Explicar en una frase por qué cruza el
límite (evidencia, observador local, auditoría, estado ajeno), ofrecer la
alternativa permitida más cercana que resuelva el problema real, y si no existe,
decirlo con claridad. Nada de implementaciones “opt-in” de algo prohibido: una
bandera `--yes-i-know` no convierte en aceptable un borrado de evidencia ni una
supresión de auditoría.

## 12. Formato de salida esperado

1. Código Rust limpio, modular, listo para `src/modules/...`.
2. Explicación del mecanismo de red/privacidad (nftables, sysctl, `unshare`,
   ioctls, NetworkManager runtime) y de su reversión.
3. Evaluación crítica explícita: qué se descartó y por qué, y qué rastros
   persistentes quedan (idealmente ninguno) con su justificación.

---

*Esta guía es política del proyecto, no asesoramiento jurídico. El usuario es
responsable de cumplir la ley de su jurisdicción; el proyecto no implementa
funciones cuya finalidad sea incumplirla.*
