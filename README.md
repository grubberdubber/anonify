# 🕶️ anonify

```text
 █████╗ ███╗   ██╗ ██████╗ ███╗   ██╗██╗███████╗██╗   ██╗
██╔══██╗████╗  ██║██╔═══██╗████╗  ██║██║██╔════╝╚██╗ ██╔╝
███████║██╔██╗ ██║██║   ██║██╔██╗ ██║██║█████╗   ╚████╔╝ 
██╔══██║██║╚██╗██║██║   ██║██║╚██╗██║██║██╔══╝    ╚██╔╝  
██║  ██║██║ ╚████║╚██████╔╝██║ ╚████║██║██║        ██║   
╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝╚═╝        ╚═╝   
```

[![Language: Rust](https://img.shields.io/badge/Language-Rust_100%25-orange.svg?style=flat-square&logo=rust)](https://www.rust-lang.org/)
[![Platform: Arch Linux](https://img.shields.io/badge/Platform-Arch_Linux-blue.svg?style=flat-square&logo=arch-linux)](https://archlinux.org/)
[![License: GPL-3.0](https://img.shields.io/badge/License-GPL--3.0-green.svg?style=flat-square&logo=gnu)](https://www.gnu.org/licenses/gpl-3.0)
[![Memory: Volatile RAM-only](https://img.shields.io/badge/State-/run_RAM--only-critical.svg?style=flat-square)](#)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)](#)

> **Hardening de anonimato temporal, paranoico y 100% reversible para Arch Linux.**  
> Todos los cambios viven en RAM (`/run/anonify`, `sysctl`, `nftables`, bind-mounts). Al reiniciar o ejecutar `restore`, tu máquina vuelve exactamente al estado original. Sin residuos, sin historias.

---

### ⭐ ¡Reventad el botón de laik shavales!
Si te gusta el proyecto o te ha servido para que las telemetrías y los rastreadores no te huelan la tostada, **dale una estrellita ⭐ arriba a la derecha** que no cuesta nada y alimenta el ego del desarrollador.

> *Nota: Próxima actualización in english :3* 🌐

---

## 🧐 El contexto: ¿Por qué existe anonify?

Hay 200 scripts en bash por ahí que prometen "anonimato nivel Matrix", pero:
1. Te modifican `/etc/resolv.conf` y al cerrar te dejan sin internet hasta que reinicias NetworkManager llorando.
2. Tienen fugas (*leaks*) gigantescas por IPv6 o peticiones UDP DNS de fondo.
3. Si el script peta a mitad, se queda tu firewall roto y tu tarjeta en un estado esquizofrénico.

**anonify está programado 100% en Rust**, con control de errores real, rollback automático y persistencia en memoria volátil (`tmpfs`).

> ### 🛑 Aclaración seria
> Aunque el README tenga toques de humor y memes, **este proyecto me lo tomo totalmente en serio**. El código está diseñado con rigor militar: comprobaciones de drift cada pocos segundos (por si NetworkManager intenta devolverte tu hostname o tu MAC), tablas aisladas de `nftables` que no interfieren con tus reglas previas, y comprobaciones directas contra `/proc` y `/sys`.

---

## ⚡ Características Principales

| Módulo | Acción técnica en el sistema | Cómo se revierte |
|---|---|---|
| **`mac`** | Spoofing de MAC aleatoria en todas las interfaces de red físicas. | Restaura la MAC original guardada mediante `ip link`. |
| **`hostname`** | Cambia el hostname a uno efímero aleatorio (`host-xxxxxxxx`). | Restaura el hostname original de la máquina. |
| **`sysctl`** | Hardening del kernel: ignora ICMP echo (ping), desactiva TCP timestamps, bloquea redirecciones ICMP y restringe `kptr`/`bpf`. | Restaura exactamente los valores numéricos anteriores de cada clave. |
| **`ipv6`** | Deshabilita IPv6 en todas las interfaces para erradicar fugas de IP real. | Reactiva IPv6 con su valor previo. |
| **`dns`** | Bind mount temporal en RAM sobre `/etc/resolv.conf` redirigido a `127.0.0.1:5353`. | Hace `umount /etc/resolv.conf` al instante. |
| **`tor`** | Instancia aislada de Tor + tabla `nftables` dedicada (`inet anonify_tor`) redirigiendo todo el tráfico TCP y DNS. | Destruye la tabla `nftables` y envía `SIGTERM` al proceso Tor. |
| **`vpn`** | Levanta túnel WireGuard/Proton mediante `wg-quick` de forma controlada. | Ejecuta `wg-quick down`. |
| **`killswitch`** | Regla estricta en firewall: solo permite loopback, interfaces VPN (`wg*`, `tun*`, `proton*`) y tráfico del demonio Tor. Si el túnel cae, cero fuga. | Borra la tabla `inet anonify_ks`. |

---

## 📦 Requisitos e Instalación

Para que todo funcione fetén en tu distribución (Arch Linux btw):

```bash
# 1. Dependencias del sistema
sudo pacman -S --needed rust tor nftables wireguard-tools iproute2 curl

# 2. Clonar y compilar en release
git clone https://github.com/<TU_USUARIO>/anonify.git
cd anonify
cargo build --release

# 3. Instalar binario en el PATH
sudo install -m755 target/release/anonify /usr/local/bin/
```

---

## 🎮 Modo de Uso

### 1. Activar el escudo completo (Modo Paranoico)
```bash
# Activa mac, hostname, sysctl, ipv6, dns y tor de un plumazo:
sudo anonify enable --all
```

### 2. Activar solo lo que te interese
```bash
# Solo falsear MAC y levantar Tor:
sudo anonify enable mac tor

# Conectar VPN con Kill Switch estricto:
sudo anonify enable vpn killswitch --vpn-conf ~/mis_vpn/mullvad-es.conf
```

### 3. Ver estado y detectar trampas del sistema
```bash
sudo anonify status
```
*Si NetworkManager o algún demonio cabrón intentó restaurar tu MAC o hostname en segundo plano, `anonify` te alertará con un estado `[ON!]` indicando **drift** de configuración.*

### 4. Testear fugas (Check de Tor)
```bash
sudo anonify check
```

### 5. Lanzar aplicaciones aisladas (sin ser root)
Si necesitas abrir una VM de Whonix en VirtualBox o tu cliente VPN sin dejar rastros:
```bash
# Iniciar VirtualBox / Whonix:
anonify launch vbox Whonix-Workstation

# Ejecutar cualquier comando con tu usuario no-root:
anonify launch exec -- firefox
```

### 6. Volver a la normalidad (Restauración Total)
```bash
# Limpia iptables/nftables, restaura MACs, monta resolv.conf original y todo como nuevo:
sudo anonify restore
```
*(O si te da pereza, simplemente reinicia la máquina: recuerda que nada toca tu disco duro).*

---

## 🗺️ Próximas Actualizaciones / Roadmap (Anonimato Extremo)

Aquí las ideas en desarrollo y mejoras planificadas para las siguientes versiones:

- [ ] 🚨 **`anonify panic` (Botón del pánico / Anti-forense)**: Un comando que tumba instantáneamente todas las interfaces de red, mata sockets, hace un `shred` de la memoria en `/run/anonify`, vacía buffers de swap y, opcionalmente, apaga el equipo al segundo.
- [ ] 📦 **Aislamiento por Network Namespaces (NetNS / Bubblewrap)**: En lugar de obligar a todo el sistema a pasar por Tor, crear contenedores de red efímeros (`anonify run-in-sandbox -- firefox`) para aislar solo apps concretas con su propia interfaz virtual.
- [ ] 🏷️ **OUI Spoofing Inteligente (MACs creíbles)**: Generar direcciones MAC con prefijos de fabricantes comunes (Apple, Intel, Samsung) para que los portales cautivos y routers empresariales no bloqueen la interfaz por detectar MACs puramente aleatorias.
- [ ] 🕒 **Timezone & Locale Masking**: Bind-mount volátil sobre `/etc/localtime` (fijando `UTC`) y sanitización de variables de entorno de localización para impedir fingerprinting de huso horario por scripts locales.
- [ ] 🧼 **Metadata Sanitizer Pipeline**: Comando `anonify scrub <archivo>` integrado para pasar archivos por una limpieza de metadatos (EXIF, marcas de tiempo, datos de geolocalización) antes de compartirlos.
- [ ] 🧅 **Soporte Multi-Red (I2P & Lokinet)**: Capacidad de enrutar tráfico no solo a través de la red Tor, sino también a través de redes descentralizadas alternativas como I2P.
- [ ] 🦊 **Ephemeral RAM Browser Profile**: Script de lanzamiento de perfiles limpios de LibreWolf / Mullvad Browser montados directamente sobre `/dev/shm` que se autodestruyen automáticamente al cerrar la pestaña.

---

## 💬 Feedback, Sugerencias y los "Iuses" (Issues) de GitHub

¿Tienes una idea loca para llevar el anonimato aún más lejos? ¿Has encontrado un bug o una incompatibilidad con tu configuración de red?

Por favor, **no te cortes y abre un [Issue](../../issues) aquí en GitHub**.  
Los *Issues* son la vía directa para debatir mejoras, proponer módulos nuevos y pulir detalles. Se aprecian Pull Requests bien estructuradas, limpias y respetando la filosofía del proyecto.

---

## ⚠️ Descargo de Responsabilidad (Léelo con cabeza)

- **No existe el anonimato absoluto al 100%.** Si inicias sesión en tu cuenta de Google con Tor puesto, te estás identificando tú solito.
- Esta herramienta mitiga identificadores de hardware (MAC), del sistema operativo (hostname, sysctl), y fuga de paquetes (IPv6, DNS leaks, kill switch), pero no te salva de malware, ataques de correlación temporal de tráfico avanzada ni de la huella (*browser fingerprinting*) del navegador. Usa navegadores endurecidos (Tor Browser, LibreWolf) o sistemas dedicados como Tails / Whonix para tareas críticas.
- Cambiar la MAC desconecta la tarjeta de red un microsegundo (algo natural al bajar y subir la interfaz).

---

## 🐧 Filosofía Linuxera & Licencia

Este proyecto abraza la **auténtica filosofía del Software Libre**. La privacidad y la seguridad no pueden ser una caja negra corporativa; deben pertenecer a la comunidad.

Distribuido bajo la licencia **GNU General Public License v3.0 (GPLv3)**.  
Cualquiera puede usarlo, auditarlo, modificarlo y redistribuirlo libremente, siempre y cuando cualquier trabajo derivado permanezca con esta misma licencia libre y el código fuente esté disponible para todos. ¡Copyleft siempre! ✊

Consulta el archivo [LICENSE](LICENSE) para más detalles.
