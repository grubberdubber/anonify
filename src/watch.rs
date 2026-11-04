//! Vigilancia de deriva: comprueba periódicamente que los módulos que figuran
//! activos siguen aplicados en el sistema real y avisa (o restaura) si algo
//! externo los revirtió —`NetworkManager`, `systemd-resolved`, un
//! `wg-quick down` manual o un `nft flush ruleset`—.
//!
//! No escribe logs ni estado: solo lee `state.json` y el kernel, e imprime
//! avisos a stderr. Corre en primer plano para que quede claro quién vigila;
//! si quieres un servicio, envuélvelo con
//! `systemd-run --unit=anonify-watch anonify watch --restore`.
//!
//! Con `--restore`, la primera deriva detectada ejecuta una restauración
//! completa y termina: nunca se queda reintentando cambios sobre un sistema
//! que otra herramienta está reconfigurando.
use crate::{
    i18n::{tr, Lang},
    modules::Module,
    state::State,
};
use anyhow::{bail, Result};
use std::time::Duration;

pub struct Options {
    /// Segundos entre comprobaciones (mínimo 1).
    pub interval: u64,
    /// Restaurar todo y salir en la primera deriva detectada.
    pub restore: bool,
    /// Comprobar una sola vez y salir (código 1 si hay deriva).
    pub once: bool,
}

fn name(m: Module) -> String {
    format!("{m:?}").to_lowercase()
}

/// Módulos activos que el sistema ya no mantiene.
fn drifted(st: &State) -> Vec<Module> {
    Module::ALL
        .iter()
        .copied()
        .filter(|m| st.active.contains(m) && !m.holds(st))
        .collect()
}

/// Módulos con cambios parciales pendientes de deshacer.
fn pending(st: &State) -> Vec<Module> {
    Module::ALL
        .iter()
        .copied()
        .filter(|m| st.pending.contains(m))
        .collect()
}

fn report(lang: Lang, lost: &[Module], pend: &[Module]) {
    for m in lost {
        eprintln!(
            "[!] {} {}: {}",
            tr(lang, "drift:", "deriva:"),
            name(*m),
            tr(
                lang,
                "listed as active but the system no longer has it applied",
                "figura activo pero el sistema ya NO lo tiene aplicado"
            )
        );
    }
    for m in pend {
        eprintln!(
            "[!] {} {}: {}",
            tr(lang, "pending cleanup:", "limpieza pendiente:"),
            name(*m),
            tr(
                lang,
                "a previous change could not be reverted",
                "un cambio anterior no se pudo deshacer"
            )
        );
    }
}

pub fn run(lang: Lang, opts: &Options, mut restore: impl FnMut() -> Result<()>) -> Result<()> {
    if opts.interval == 0 {
        bail!(
            "{}",
            tr(
                lang,
                "--interval must be at least 1 second",
                "--interval debe ser de al menos 1 segundo"
            )
        );
    }
    if !opts.once {
        println!(
            "[*] {} {}s",
            tr(lang, "watching for drift every", "vigilando deriva cada"),
            opts.interval
        );
    }

    // Firma de la última anomalía para no repetir el mismo aviso cada ciclo.
    let mut last_alert: Option<(Vec<Module>, Vec<Module>)> = None;
    let mut announced_empty = false;

    loop {
        let st = State::load()?;
        let lost = drifted(&st);
        let pend = pending(&st);

        if lost.is_empty() && pend.is_empty() {
            if opts.once {
                println!(
                    "[\u{2713}] {}",
                    tr(lang, "no drift detected", "no se detectó deriva")
                );
                return Ok(());
            }
            if last_alert.take().is_some() {
                println!(
                    "[\u{2713}] {}",
                    tr(
                        lang,
                        "configuration is stable again",
                        "la configuración volvió a estar estable"
                    )
                );
            }
            if !announced_empty && st.active.is_empty() {
                println!(
                    "[*] {}",
                    tr(
                        lang,
                        "no modules active yet; waiting",
                        "aún no hay módulos activos; esperando"
                    )
                );
                announced_empty = true;
            }
            std::thread::sleep(Duration::from_secs(opts.interval));
            continue;
        }

        let signature = (lost.clone(), pend.clone());
        if last_alert.as_ref() != Some(&signature) {
            report(lang, &lost, &pend);
        }
        last_alert = Some(signature);

        if opts.restore {
            eprintln!(
                "[!] {}",
                tr(
                    lang,
                    "drift detected: running a full restore",
                    "deriva detectada: ejecutando un restore completo"
                )
            );
            restore()?;
            println!(
                "[\u{2713}] {}",
                tr(
                    lang,
                    "restore complete, leaving watch mode",
                    "restore completo, saliendo del modo vigilancia"
                )
            );
            return Ok(());
        }
        if opts.once {
            bail!("{}", tr(lang, "drift detected", "deriva detectada"));
        }
        std::thread::sleep(Duration::from_secs(opts.interval));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_interval_is_rejected() {
        let err = run(
            Lang::En,
            &Options {
                interval: 0,
                restore: false,
                once: true,
            },
            || Ok(()),
        )
        .expect_err("intervalo 0 debe fallar");
        assert!(format!("{err:#}").contains("interval"));
    }
}
