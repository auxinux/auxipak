//! Progression affichée sur la sortie d'erreur : barre de téléchargement et
//! indicateur d'étape (temps écoulé) pour les opérations longues.
//!
//! Rien n'est animé si la sortie d'erreur n'est pas un terminal (journaux,
//! CI, sortie JSON) ou si `AUXIPAK_NO_PROGRESS` est défini : seules les lignes
//! de début et de fin d'étape sont alors écrites.

use std::io::{IsTerminal, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const REFRESH: Duration = Duration::from_millis(100);
const BAR: usize = 24;

fn animated() -> bool {
    std::env::var_os("AUXIPAK_NO_PROGRESS").is_none() && std::io::stderr().is_terminal()
}

/// Taille lisible : « 58,3 Mo ».
pub fn human(bytes: u64) -> String {
    const U: [&str; 5] = ["o", "Ko", "Mo", "Go", "To"];
    let mut v = bytes as f64;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    let s = if i == 0 {
        format!("{bytes} o")
    } else {
        format!("{v:.1} {}", U[i])
    };
    s.replace('.', ",")
}

fn duration(d: Duration) -> String {
    let s = d.as_secs();
    if s >= 3600 {
        format!("{} h {:02} min", s / 3600, (s % 3600) / 60)
    } else if s >= 60 {
        format!("{} min {:02} s", s / 60, s % 60)
    } else {
        format!("{s} s")
    }
}

/// Ligne de progression d'un téléchargement (pure, testable).
fn render(label: &str, done: u64, total: Option<u64>, elapsed: Duration) -> String {
    let secs = elapsed.as_secs_f64().max(0.001);
    let rate = done as f64 / secs;
    match total.filter(|t| *t > 0) {
        Some(t) => {
            let ratio = (done as f64 / t as f64).clamp(0.0, 1.0);
            let full = (ratio * BAR as f64).round() as usize;
            let eta = if rate > 0.0 && done < t {
                format!("  reste {}", duration(Duration::from_secs_f64((t - done) as f64 / rate)))
            } else {
                String::new()
            };
            format!(
                "  {label}  [{}{}] {:>3} %  {}/{}  {}/s{eta}",
                "█".repeat(full),
                "░".repeat(BAR - full),
                (ratio * 100.0).floor() as u64,
                human(done),
                human(t),
                human(rate as u64),
            )
        }
        None => format!("  {label}  {}  {}/s", human(done), human(rate as u64)),
    }
}

/// Barre de progression d'un téléchargement.
pub struct Download {
    label: String,
    total: Option<u64>,
    start: Instant,
    last: Option<Instant>,
    done: u64,
    animated: bool,
    width: usize,
}

impl Download {
    pub fn new(label: &str, total: Option<u64>) -> Download {
        Download {
            label: label.to_string(),
            total,
            start: Instant::now(),
            last: None,
            done: 0,
            animated: animated(),
            width: 0,
        }
    }

    pub fn set_total(&mut self, total: Option<u64>) {
        if total.is_some() {
            self.total = total;
        }
    }

    /// Position courante (octets reçus, reprise comprise).
    pub fn set(&mut self, done: u64) {
        self.done = done;
        if !self.animated || self.last.map(|l| l.elapsed() < REFRESH).unwrap_or(false) {
            return;
        }
        self.last = Some(Instant::now());
        self.draw();
    }

    fn draw(&mut self) {
        let line = render(&self.label, self.done, self.total, self.start.elapsed());
        let n = line.chars().count();
        let pad = self.width.saturating_sub(n);
        self.width = n;
        let mut e = std::io::stderr().lock();
        let _ = write!(e, "\r{line}{}", " ".repeat(pad));
        let _ = e.flush();
    }

    /// Termine la ligne (succès).
    pub fn finish(mut self) {
        let el = self.start.elapsed();
        let line = format!(
            "  ✓ {}  {} en {} ({}/s)",
            self.label,
            human(self.done),
            duration(el),
            human((self.done as f64 / el.as_secs_f64().max(0.001)) as u64)
        );
        self.clear();
        eprintln!("{line}");
    }

    /// Efface la ligne animée (échec : le message d'erreur suit).
    pub fn abandon(mut self) {
        self.clear();
    }

    fn clear(&mut self) {
        if self.animated && self.width > 0 {
            eprint!("\r{}\r", " ".repeat(self.width));
            self.width = 0;
        }
    }
}

/// Indicateur d'étape : « ⠋ copie de Firefox.app (3 s) », puis « ✓ … (5 s) ».
pub struct Step {
    label: String,
    start: Instant,
    stop: Arc<AtomicBool>,
    task: Option<std::thread::JoinHandle<()>>,
    ended: bool,
}

impl Step {
    pub fn start(label: impl Into<String>) -> Step {
        let label = label.into();
        let stop = Arc::new(AtomicBool::new(false));
        let start = Instant::now();
        let task = if animated() {
            let (l, s) = (label.clone(), stop.clone());
            Some(std::thread::spawn(move || {
                const FRAMES: [char; 10] = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
                let mut i = 0;
                while !s.load(Ordering::Relaxed) {
                    let mut e = std::io::stderr().lock();
                    let _ = write!(e, "\r  {} {l} ({})  ", FRAMES[i % FRAMES.len()], duration(start.elapsed()));
                    let _ = e.flush();
                    drop(e);
                    i += 1;
                    std::thread::sleep(REFRESH);
                }
            }))
        } else {
            eprintln!("  {label}…");
            None
        };
        Step {
            label,
            start,
            stop,
            task,
            ended: false,
        }
    }

    fn end(&mut self, mark: &str) {
        if self.ended {
            return;
        }
        self.ended = true;
        self.stop.store(true, Ordering::Relaxed);
        if let Some(t) = self.task.take() {
            let _ = t.join();
            eprint!("\r{}\r", " ".repeat(self.label.chars().count() + 24));
        }
        eprintln!("  {mark} {} ({})", self.label, duration(self.start.elapsed()));
    }

    pub fn finish(mut self) {
        self.end("✓");
    }
}

impl Drop for Step {
    fn drop(&mut self) {
        // Échec ou abandon : la ligne est terminée, l'erreur s'affiche ensuite.
        self.end("✗");
    }
}

/// Exécute `fut` en affichant une étape.
pub async fn step<T, E>(label: impl Into<String>, fut: impl std::future::Future<Output = Result<T, E>>) -> Result<T, E> {
    let s = Step::start(label);
    let r = fut.await;
    if r.is_ok() {
        s.finish();
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tailles() {
        assert_eq!(human(512), "512 o");
        assert_eq!(human(1536), "1,5 Ko");
        assert_eq!(human(140 * 1024 * 1024), "140,0 Mo");
    }

    #[test]
    fn ligne_de_progression() {
        let l = render(
            "Firefox.dmg",
            50 * 1024 * 1024,
            Some(100 * 1024 * 1024),
            Duration::from_secs(5),
        );
        assert!(l.contains("50 %"), "{l}");
        assert!(l.contains("50,0 Mo/100,0 Mo"), "{l}");
        assert!(l.contains("10,0 Mo/s"), "{l}");
        assert!(l.contains("reste 5 s"), "{l}");
        assert_eq!(l.matches('█').count() + l.matches('░').count(), BAR);
        let u = render("x", 2048, None, Duration::from_secs(1));
        assert!(u.contains("2,0 Ko") && !u.contains('%'), "{u}");
        assert_eq!(duration(Duration::from_secs(125)), "2 min 05 s");
    }
}
