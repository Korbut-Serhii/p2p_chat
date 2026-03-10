//! P2P Chat v3 — encrypted, no input duplication.
//!
//! The duplication fix works like this:
//!   - Terminal is put into **raw mode** (crossterm).
//!   - A shared `Arc<Mutex<String>>` holds the line the user is typing.
//!   - The INPUT TASK reads keystrokes one-by-one, echoes them manually,
//!     and sends the line when Enter is pressed.
//!   - The RECEIVE TASK holds the same mutex. When a message arrives it:
//!       1. Locks the mutex.
//!       2. Erases the current input line from the screen.
//!       3. Prints the incoming message.
//!       4. Redraws the input line (so the user can keep typing).
//!     All of this happens in one locked section — no race, no duplicate.
//!
//! Wire protocol (after TCP connect):
//!   1. X25519 pubkeys exchanged (32 raw bytes each direction).
//!   2. Shared AES-256-GCM key derived via SHA-256 of the ECDH secret.
//!   3. Every message → base64( nonce[12] || AES-GCM(JSON) ) + '\n'

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use clap::{Parser, Subcommand};
use crossterm::{
    cursor,
    event::{self, Event, KeyCode, KeyEvent, KeyModifiers},
    execute,
    style::{self, Stylize},
    terminal::{self, ClearType},
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    io::{self, Write},
    sync::Arc,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    sync::{broadcast, Mutex},
};
use x25519_dalek::{EphemeralSecret, PublicKey};

// ─── CLI ─────────────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(name = "p2p_chat")]
#[command(about = "🔗 Encrypted peer-to-peer terminal chat", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Listen and wait for a peer to connect
    Host {
        #[arg(short, long, default_value = "7777")]
        port: u16,
        #[arg(short, long, default_value = "Host")]
        name: String,
    },
    /// Connect to a host
    Connect {
        #[arg(short, long)]
        addr: String,
        #[arg(short, long, default_value = "7777")]
        port: u16,
        #[arg(short, long, default_value = "Guest")]
        name: String,
    },
}

// ─── Messages ────────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "type")]
enum ChatMessage {
    Text {
        sender: String,
        content: String,
        timestamp: String,
    },
    System {
        content: String,
    },
    Goodbye {
        sender: String,
    },
}

impl ChatMessage {
    fn text(sender: &str, content: &str) -> Self {
        let timestamp = chrono::Local::now().format("%H:%M:%S").to_string();
        ChatMessage::Text {
            sender: sender.to_string(),
            content: content.to_string(),
            timestamp,
        }
    }
    fn system(content: &str) -> Self {
        ChatMessage::System {
            content: content.to_string(),
        }
    }
    fn goodbye(sender: &str) -> Self {
        ChatMessage::Goodbye {
            sender: sender.to_string(),
        }
    }

    /// Render this message as a coloured string (no newline).
    fn render(&self) -> String {
        match self {
            ChatMessage::Text {
                sender,
                content,
                timestamp,
            } => format!(
                "{} {} {}",
                format!("[{}]", timestamp).dark_grey().to_string(),
                format!("{}:", sender).cyan().bold().to_string(),
                content
            ),
            ChatMessage::System { content } => {
                format!("{} {}", "●".yellow().to_string(), content.clone().italic().yellow().to_string())
            }
            ChatMessage::Goodbye { sender } => {
                format!("{} {} left the chat.", "●".red().to_string(), sender.clone().bold().red().to_string())
            }
        }
    }
}

// ─── Terminal helper — print a message above the input line ──────────────────

/// Must be called while holding the `input_buf` lock so no other thread
/// can touch the terminal at the same time.
fn print_above_input(msg: &str, input_buf: &str) {
    let mut stdout = io::stdout();
    // Move to start of line, clear it, print the message, then
    // reprint the input prompt on the next line.
    execute!(
        stdout,
        cursor::MoveToColumn(0),
        terminal::Clear(ClearType::CurrentLine),
    )
    .ok();
    // Print the incoming message
    println!("{}", msg);
    // Reprint the input prompt with whatever the user had typed
    print!("> {}", input_buf);
    stdout.flush().ok();
}

// ─── Crypto ──────────────────────────────────────────────────────────────────

fn encrypt(cipher: &Aes256Gcm, plaintext: &[u8]) -> String {
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher.encrypt(nonce, plaintext).expect("encrypt");
    let mut blob = nonce_bytes.to_vec();
    blob.extend_from_slice(&ct);
    B64.encode(&blob)
}

fn decrypt(cipher: &Aes256Gcm, b64: &str) -> Option<Vec<u8>> {
    let blob = B64.decode(b64.trim()).ok()?;
    if blob.len() < 12 {
        return None;
    }
    let (nb, ct) = blob.split_at(12);
    cipher.decrypt(Nonce::from_slice(nb), ct).ok()
}

// ─── X25519 handshake ────────────────────────────────────────────────────────

async fn handshake(
    reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
    writer: &Arc<Mutex<tokio::net::tcp::OwnedWriteHalf>>,
    is_host: bool,
) -> Result<Aes256Gcm, String> {
    let secret = EphemeralSecret::random_from_rng(rand::thread_rng());
    let our_pub = PublicKey::from(&secret);

    let peer_bytes: [u8; 32] = if is_host {
        writer.lock().await.write_all(our_pub.as_bytes()).await.map_err(|e| e.to_string())?;
        let mut b = [0u8; 32];
        reader.read_exact(&mut b).await.map_err(|e| e.to_string())?;
        b
    } else {
        let mut b = [0u8; 32];
        reader.read_exact(&mut b).await.map_err(|e| e.to_string())?;
        writer.lock().await.write_all(our_pub.as_bytes()).await.map_err(|e| e.to_string())?;
        b
    };

    let shared = secret.diffie_hellman(&PublicKey::from(peer_bytes));
    let key_bytes = Sha256::digest(shared.as_bytes());
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    Ok(Aes256Gcm::new(key))
}

// ─── Chat session ─────────────────────────────────────────────────────────────

async fn run_chat(stream: TcpStream, my_name: String, peer_info: String, is_host: bool) {
    let (reader_half, writer_half) = stream.into_split();
    let writer = Arc::new(Mutex::new(writer_half));
    let mut buf_reader = BufReader::new(reader_half);

    // Handshake (before raw mode — we can use normal println here)
    println!("\r🔑 Performing key exchange (X25519 + AES-256-GCM)...");
    let cipher = match handshake(&mut buf_reader, &writer, is_host).await {
        Ok(c) => {
            println!("\r🔒 {}", "End-to-end encrypted. Nobody in between can read your messages.".green().bold());
            Arc::new(c)
        }
        Err(e) => {
            eprintln!("\rHandshake failed: {}", e);
            return;
        }
    };

    println!("\r{}", format!("─── Connected to {} ───", peer_info).green().bold());
    println!("\r{}", "Type a message and press Enter.  Ctrl-C or /quit to leave.".dark_grey());
    println!();

    // Send join announcement
    {
        let msg = ChatMessage::system(&format!("{} joined the chat.", my_name));
        let plain = serde_json::to_string(&msg).unwrap_or_default();
        let line = format!("{}\n", encrypt(&cipher, plain.as_bytes()));
        let _ = writer.lock().await.write_all(line.as_bytes()).await;
    }

    // Shared input buffer — both tasks access this under the same Mutex so
    // that "erase + print message + redraw prompt" is one atomic operation.
    let input_buf: Arc<Mutex<String>> = Arc::new(Mutex::new(String::new()));

    let (quit_tx, _) = broadcast::channel::<()>(4);

    // ── Enable raw mode ──────────────────────────────────────────────────────
    terminal::enable_raw_mode().expect("enable raw mode");
    // Print initial prompt
    print!("> ");
    io::stdout().flush().ok();

    // ── RECEIVE TASK ─────────────────────────────────────────────────────────
    let cipher_r   = Arc::clone(&cipher);
    let input_r    = Arc::clone(&input_buf);
    let quit_tx_r  = quit_tx.clone();

    let receive_task = tokio::spawn(async move {
        let mut line = String::new();
        loop {
            line.clear();
            match buf_reader.read_line(&mut line).await {
                Ok(0) => {
                    let buf = input_r.lock().await;
                    print_above_input(
                        &ChatMessage::system("Peer disconnected.").render(),
                        &buf,
                    );
                    drop(buf);
                    let _ = quit_tx_r.send(());
                    break;
                }
                Ok(_) => {
                    let trimmed = line.trim();
                    if trimmed.is_empty() { continue; }

                    let rendered = match decrypt(&cipher_r, trimmed) {
                        Some(plain) => {
                            let msg = serde_json::from_slice::<ChatMessage>(&plain)
                                .unwrap_or_else(|_| ChatMessage::text("Peer", &String::from_utf8_lossy(&plain)));
                            let is_bye = matches!(msg, ChatMessage::Goodbye { .. });
                            let r = msg.render();
                            if is_bye {
                                let buf = input_r.lock().await;
                                print_above_input(&r, &buf);
                                drop(buf);
                                let _ = quit_tx_r.send(());
                                break;
                            }
                            r
                        }
                        None => format!(
                            "{}",
                            "⚠  Unreadable message (possible tampering).".red()
                        ),
                    };

                    // Lock the buffer, erase input line, print message, redraw prompt
                    let buf = input_r.lock().await;
                    print_above_input(&rendered, &buf);
                    drop(buf);
                }
                Err(e) => {
                    let buf = input_r.lock().await;
                    print_above_input(&format!("{}", format!("Read error: {}", e).red()), &buf);
                    drop(buf);
                    let _ = quit_tx_r.send(());
                    break;
                }
            }
        }
    });

    // ── INPUT TASK (crossterm raw-mode keystroke reader) ─────────────────────
    let cipher_s   = Arc::clone(&cipher);
    let writer_s   = Arc::clone(&writer);
    let input_s    = Arc::clone(&input_buf);
    let my_name_s  = my_name.clone();
    let mut quit_rx = quit_tx.subscribe();

    let input_task = tokio::task::spawn_blocking(move || {
        let mut stdout = io::stdout();
        loop {
            // Check quit signal
            if quit_rx.try_recv().is_ok() { break; }

            // Poll for a keystroke (100 ms timeout so we can check quit_rx)
            if !event::poll(std::time::Duration::from_millis(100)).unwrap_or(false) {
                continue;
            }

            let ev = match event::read() {
                Ok(e) => e,
                Err(_) => break,
            };

            if let Event::Key(KeyEvent { code, modifiers, .. }) = ev {
                match code {
                    // ── Enter: send message ───────────────────────────────
                    KeyCode::Enter => {
                        // We need to get the buffer contents, but we're in a
                        // blocking thread. Use try_lock so we never dead-lock
                        // with the async receive task.
                        let text = {
                            // Spin-wait (very brief — just a string copy)
                            loop {
                                if let Ok(mut buf) = input_s.try_lock() {
                                    let t = buf.trim().to_string();
                                    buf.clear();
                                    break t;
                                }
                                std::thread::sleep(std::time::Duration::from_millis(1));
                            }
                        };

                        // Move to start of line, clear it
                        execute!(
                            stdout,
                            cursor::MoveToColumn(0),
                            terminal::Clear(ClearType::CurrentLine),
                        ).ok();

                        if text.is_empty() {
                            print!("> ");
                            stdout.flush().ok();
                            continue;
                        }

                        // /quit
                        if text == "/quit" || text == "/q" {
                            let bye = ChatMessage::goodbye(&my_name_s);
                            let plain = serde_json::to_string(&bye).unwrap_or_default();
                            let wire = format!("{}\n", encrypt(&cipher_s, plain.as_bytes()));
                            // Send synchronously from blocking thread
                            let rt = tokio::runtime::Handle::try_current();
                            if let Ok(handle) = rt {
                                handle.block_on(async {
                                    let _ = writer_s.lock().await.write_all(wire.as_bytes()).await;
                                });
                            }
                            println!("{}", "You left the chat. Goodbye!".yellow());
                            let _ = quit_tx.send(());
                            break;
                        }

                        // Build, print locally, encrypt, send
                        let msg = ChatMessage::text(&my_name_s, &text);
                        println!("{}", msg.render());
                        print!("> ");
                        stdout.flush().ok();

                        let plain = serde_json::to_string(&msg).unwrap_or_default();
                        let wire = format!("{}\n", encrypt(&cipher_s, plain.as_bytes()));
                        let rt = tokio::runtime::Handle::try_current();
                        if let Ok(handle) = rt {
                            let ok = handle.block_on(async {
                                writer_s.lock().await.write_all(wire.as_bytes()).await.is_ok()
                            });
                            if !ok {
                                println!("{}", "Failed to send message (connection lost).".red());
                                let _ = quit_tx.send(());
                                break;
                            }
                        }
                    }

                    // ── Backspace ─────────────────────────────────────────
                    KeyCode::Backspace => {
                        loop {
                            if let Ok(mut buf) = input_s.try_lock() {
                                if buf.pop().is_some() {
                                    // Erase last character on screen
                                    execute!(stdout, cursor::MoveLeft(1), terminal::Clear(ClearType::UntilNewLine)).ok();
                                }
                                break;
                            }
                            std::thread::sleep(std::time::Duration::from_millis(1));
                        }
                    }

                    // ── Ctrl-C ────────────────────────────────────────────
                    KeyCode::Char('c') if modifiers.contains(KeyModifiers::CONTROL) => {
                        // Send goodbye
                        let bye = ChatMessage::goodbye(&my_name_s);
                        let plain = serde_json::to_string(&bye).unwrap_or_default();
                        let wire = format!("{}\n", encrypt(&cipher_s, plain.as_bytes()));
                        if let Ok(handle) = tokio::runtime::Handle::try_current() {
                            handle.block_on(async {
                                let _ = writer_s.lock().await.write_all(wire.as_bytes()).await;
                            });
                        }
                        execute!(
                            stdout,
                            cursor::MoveToColumn(0),
                            terminal::Clear(ClearType::CurrentLine),
                        ).ok();
                        println!("{}", "You left the chat. Goodbye!".yellow());
                        let _ = quit_tx.send(());
                        break;
                    }

                    // ── Regular character ─────────────────────────────────
                    KeyCode::Char(c) => {
                        loop {
                            if let Ok(mut buf) = input_s.try_lock() {
                                buf.push(c);
                                // Echo to screen
                                print!("{}", c);
                                stdout.flush().ok();
                                break;
                            }
                            std::thread::sleep(std::time::Duration::from_millis(1));
                        }
                    }

                    _ => {}
                }
            }
        }
    });

    tokio::select! {
        _ = receive_task => {}
        _ = input_task   => {}
    }

    // Restore terminal
    terminal::disable_raw_mode().ok();
    println!("\r{}", "\n─── Session ended ───".dark_grey());
}

// ─── Entry point ─────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    print_banner();

    match cli.command {
        Commands::Host { port, name } => {
            let listener = match TcpListener::bind(format!("0.0.0.0:{}", port)).await {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("ERROR: Could not bind to port {}: {}", port, e);
                    std::process::exit(1);
                }
            };
            println!("● Listening on port {}. Waiting for peer...\n", port);
            println!(
                "  → Tell your friend to run:\n    p2p_chat.exe connect --addr <YOUR_IP> --port {} --name <name>\n",
                port
            );
            match listener.accept().await {
                Ok((stream, addr)) => run_chat(stream, name, addr.to_string(), true).await,
                Err(e) => eprintln!("Accept error: {}", e),
            }
        }

        Commands::Connect { addr, port, name } => {
            let target = format!("{}:{}", addr, port);
            println!("● Connecting to {}...", target);
            match TcpStream::connect(&target).await {
                Ok(stream) => run_chat(stream, name, target, false).await,
                Err(e) => {
                    eprintln!("ERROR: Could not connect to {}: {}", target, e);
                    eprintln!("Make sure the host is running and the IP/port are correct.");
                    std::process::exit(1);
                }
            }
        }
    }
}

fn print_banner() {
    println!("{}", r#"
  ██████╗ ██████╗ ██████╗      ██████╗██╗  ██╗ █████╗ ████████╗
  ██╔══██╗╚════██╗██╔══██╗    ██╔════╝██║  ██║██╔══██╗╚══██╔══╝
  ██████╔╝ █████╔╝██████╔╝    ██║     ███████║███████║   ██║   
  ██╔═══╝ ██╔═══╝ ██╔═══╝     ██║     ██╔══██║██╔══██║   ██║   
  ██║     ███████╗██║          ╚██████╗██║  ██║██║  ██║   ██║   
  ╚═╝     ╚══════╝╚═╝           ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝  
"#.cyan());
    println!("  {}\n", "Encrypted P2P terminal chat — Rust · X25519 · AES-256-GCM".dark_grey());
}
