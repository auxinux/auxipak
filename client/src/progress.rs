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

fn fr() -> bool {
    auxipak_core::i18n::is_fr()
}

/// Taille lisible : « 58,3 Mo » (français) ou « 58.3 MB » (anglais).
pub fn human(bytes: u64) -> String {
    human_in(bytes, fr())
}

fn human_in(bytes: u64, fr: bool) -> String {
    let units: [&str; 5] = if fr {
        ["o", "Ko", "Mo", "Go", "To"]
    } else {
        ["B", "KB", "MB", "GB", "TB"]
    };
    let mut v = bytes as f64;
    let mut i = 0;
    while v >= 1024.0 && i < units.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    let s = if i == 0 {
        format!("{bytes} {}", units[0])
    } else {
        format!("{v:.1} {}", units[i])
    };
    if fr {
        s.replace('.', ",")
    } else {
        s
    }
}

fn duration(d: Duration) -> String {
    duration_in(d, fr())
}

fn duration_in(d: Duration, _fr: bool) -> String {
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
    render_in(label, done, total, elapsed, fr())
}

fn render_in(label: &str, done: u64, total: Option<u64>, elapsed: Duration, fr: bool) -> String {
    let human = |b: u64| human_in(b, fr);
    let secs = elapsed.as_secs_f64().max(0.001);
    let rate = done as f64 / secs;
    match total.filter(|t| *t > 0) {
        Some(t) => {
            let ratio = (done as f64 / t as f64).clamp(0.0, 1.0);
            let full = (ratio * BAR as f64).round() as usize;
            let eta = if rate > 0.0 && done < t {
                let left = duration_in(Duration::from_secs_f64((t - done) as f64 / rate), fr);
                if fr {
                    format!("  reste {left}")
                } else {
                    format!("  {left} left")
                }
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
        let line = auxipak_core::tr!(
            "  ✓ {}  {} en {} ({}/s)",
            "  ✓ {}  {} in {} ({}/s)",
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
        assert_eq!(human_in(512, true), "512 o");
        assert_eq!(human_in(1536, true), "1,5 Ko");
        assert_eq!(human_in(140 * 1024 * 1024, true), "140,0 Mo");
        assert_eq!(human_in(512, false), "512 B");
        assert_eq!(human_in(1536, false), "1.5 KB");
        assert_eq!(human_in(140 * 1024 * 1024, false), "140.0 MB");
    }

    #[test]
    fn ligne_de_progression() {
        let l = render_in(
            "Firefox.dmg",
            50 * 1024 * 1024,
            Some(100 * 1024 * 1024),
            Duration::from_secs(5),
            true,
        );
        assert!(l.contains("50 %"), "{l}");
        assert!(l.contains("50,0 Mo/100,0 Mo"), "{l}");
        assert!(l.contains("10,0 Mo/s"), "{l}");
        assert!(l.contains("reste 5 s"), "{l}");
        assert_eq!(l.matches('█').count() + l.matches('░').count(), BAR);
        let u = render_in("x", 2048, None, Duration::from_secs(1), true);
        assert!(u.contains("2,0 Ko") && !u.contains('%'), "{u}");
        assert_eq!(duration_in(Duration::from_secs(125), true), "2 min 05 s");
        let e = render_in(
            "Firefox.dmg",
            50 * 1024 * 1024,
            Some(100 * 1024 * 1024),
            Duration::from_secs(5),
            false,
        );
        assert!(
            e.contains("50.0 MB/100.0 MB") && e.contains("10.0 MB/s") && e.contains("5 s left"),
            "{e}"
        );
    }
}
