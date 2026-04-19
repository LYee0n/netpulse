//! Interactive TUI mode powered by Ratatui + Crossterm.
//!
//! Layout
//! ──────
//!   ┌─ Header ────────────────────────────────────────────────────┐
//!   │  NetPulse  │ [1] Active  [2] History  │  [/] filter  ...   │
//!   ├─ Tab content ───────────────────────────────────────────────┤
//!   │  PID  COMM  REMOTE ADDR  STATE  PROTO  TX  RX              │
//!   │  …                                                          │
//!   ├─ Status bar ────────────────────────────────────────────────┤
//!   │  tracking N  │  sort: TX↓  │  filter: <text>               │
//!   └─────────────────────────────────────────────────────────────┘
//!
//! Tabs:
//!   1 – Active connections   (records seen in the last 60 s)
//!   2 – History / Summary    (all records since monitoring start)
//!
//! Key bindings:
//!   1/2    – switch tab
//!   s/S    – toggle sort TX↓ / RX↓
//!   r/R    – reset byte counters (delta baseline)
//!   /      – enter filter mode; <Esc> or <Enter> to leave
//!   ↑↓/jk  – scroll
//!   q/Q    – quit

use std::{io, time::Duration};

use anyhow::Result;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Frame, Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, Tabs},
};

use crate::model::{ConnectionRecord, GlobalStore, Protocol, TcpState, format_bytes};

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

pub async fn run(store: GlobalStore, filter_comm: Option<String>) -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let result = event_loop(&mut terminal, store, filter_comm).await;

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    result
}

// ---------------------------------------------------------------------------
// App state
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tab {
    Active,
    History,
}

impl Tab {
    fn title(self) -> &'static str {
        match self {
            Tab::Active => "Active (60s)",
            Tab::History => "History (all)",
        }
    }
    fn index(self) -> usize {
        match self {
            Tab::Active => 0,
            Tab::History => 1,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InputMode {
    Normal,
    Filter,
}

struct AppState {
    tab: Tab,
    sort_by_tx: bool,
    /// Persistent filter set via CLI `--filter-comm`.
    cli_filter: Option<String>,
    /// Interactive filter typed with `/`.
    tui_filter: String,
    input_mode: InputMode,
    scroll: usize,
}

impl AppState {
    fn effective_filter(&self) -> Option<&str> {
        if !self.tui_filter.is_empty() {
            Some(&self.tui_filter)
        } else {
            self.cli_filter.as_deref()
        }
    }
}

// ---------------------------------------------------------------------------
// Event loop
// ---------------------------------------------------------------------------

async fn event_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    store: GlobalStore,
    filter_comm: Option<String>,
) -> Result<()> {
    let mut state = AppState {
        tab: Tab::Active,
        sort_by_tx: true,
        cli_filter: filter_comm,
        tui_filter: String::new(),
        input_mode: InputMode::Normal,
        scroll: 0,
    };

    loop {
        terminal.draw(|f| draw(f, &store, &state))?;

        if event::poll(Duration::from_millis(200))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    match state.input_mode {
                        InputMode::Filter => match key.code {
                            KeyCode::Esc | KeyCode::Enter => {
                                state.input_mode = InputMode::Normal;
                            }
                            KeyCode::Backspace => {
                                state.tui_filter.pop();
                            }
                            KeyCode::Char(c) => {
                                state.tui_filter.push(c);
                                state.scroll = 0;
                            }
                            _ => {}
                        },
                        InputMode::Normal => match key.code {
                            KeyCode::Char('q') | KeyCode::Char('Q') => break,
                            KeyCode::Char('s') | KeyCode::Char('S') => {
                                state.sort_by_tx = !state.sort_by_tx;
                                state.scroll = 0;
                            }
                            KeyCode::Char('r') | KeyCode::Char('R') => {
                                store.reset();
                            }
                            KeyCode::Char('/') => {
                                state.input_mode = InputMode::Filter;
                                state.tui_filter.clear();
                                state.scroll = 0;
                            }
                            KeyCode::Char('1') => {
                                state.tab = Tab::Active;
                                state.scroll = 0;
                            }
                            KeyCode::Char('2') => {
                                state.tab = Tab::History;
                                state.scroll = 0;
                            }
                            KeyCode::Down | KeyCode::Char('j') => {
                                state.scroll = state.scroll.saturating_add(1);
                            }
                            KeyCode::Up | KeyCode::Char('k') => {
                                state.scroll = state.scroll.saturating_sub(1);
                            }
                            _ => {}
                        },
                    }
                }
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

fn draw(f: &mut Frame, store: &GlobalStore, state: &AppState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // header + tabs
            Constraint::Min(5),    // table
            Constraint::Length(1), // status bar
        ])
        .split(f.area());

    draw_header(f, chunks[0], state);
    draw_table(f, chunks[1], store, state);
    draw_status(f, chunks[2], store, state);
}

fn draw_header(f: &mut Frame, area: ratatui::layout::Rect, state: &AppState) {
    // Split header area: left = brand, right = tabs
    let hchunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(20), Constraint::Min(10)])
        .split(area);

    // Brand / keybind hint
    let brand = Paragraph::new(Line::from(vec![
        Span::styled(
            " NetPulse ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled("[/]", Style::default().fg(Color::Yellow)),
        Span::raw("filter "),
        Span::styled("[r]", Style::default().fg(Color::Yellow)),
        Span::raw("eset "),
        Span::styled("[q]", Style::default().fg(Color::Yellow)),
        Span::raw("uit"),
    ]))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Blue)),
    );
    f.render_widget(brand, hchunks[0]);

    // Tabs
    let titles: Vec<Line> = [Tab::Active, Tab::History]
        .iter()
        .enumerate()
        .map(|(i, t)| {
            Line::from(vec![
                Span::styled(format!("[{}] ", i + 1), Style::default().fg(Color::Yellow)),
                Span::raw(t.title()),
            ])
        })
        .collect();

    let tabs = Tabs::new(titles)
        .select(state.tab.index())
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Blue)),
        )
        .highlight_style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
        )
        .divider(" │ ");
    f.render_widget(tabs, hchunks[1]);
}

// Column layout:  PID | COMM | CMDLINE | REMOTE ADDR | PORT | PROTO | STATE | TX | RX
const COL_WIDTHS: [Constraint; 9] = [
    Constraint::Length(7),  // PID
    Constraint::Length(12), // COMM
    Constraint::Min(18),    // CMDLINE (flexible)
    Constraint::Length(15), // REMOTE IP
    Constraint::Length(6),  // PORT
    Constraint::Length(5),  // PROTO
    Constraint::Length(11), // STATE
    Constraint::Length(11), // TX
    Constraint::Length(11), // RX
];

fn draw_table(f: &mut Frame, area: ratatui::layout::Rect, store: &GlobalStore, state: &AppState) {
    let header_cells = [
        "PID",
        "COMM",
        "CMDLINE",
        "REMOTE IP",
        "PORT",
        "PROTO",
        "STATE",
        "TX",
        "RX",
    ]
    .map(|h| {
        Cell::from(h).style(
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )
    });
    let header = Row::new(header_cells)
        .style(Style::default().bg(Color::DarkGray))
        .height(1);

    // Fetch records based on tab.
    let records: Vec<ConnectionRecord> = match state.tab {
        Tab::Active => store.snapshot_window(state.sort_by_tx, 60),
        Tab::History => store.snapshot(state.sort_by_tx),
    };

    // Apply filter.
    let filtered: Vec<_> = if let Some(filter) = state.effective_filter() {
        let f = filter.to_lowercase();
        records
            .into_iter()
            .filter(|r| {
                r.comm.to_lowercase().contains(&f)
                    || r.cmdline.to_lowercase().contains(&f)
                    || r.remote_ip.to_string().contains(&f)
            })
            .collect()
    } else {
        records
    };

    let rows: Vec<Row> = filtered
        .iter()
        .skip(state.scroll)
        .map(|r| {
            let state_str = match r.proto {
                Protocol::Tcp => r.tcp_state.map(|s| s.as_str()).unwrap_or("?"),
                _ => "-",
            };
            let state_style = match r.tcp_state {
                Some(TcpState::Established) => Style::default().fg(Color::Green),
                Some(TcpState::TimeWait) | Some(TcpState::FinWait1) | Some(TcpState::FinWait2) => {
                    Style::default().fg(Color::Yellow)
                }
                Some(TcpState::Close) | Some(TcpState::CloseWait) | Some(TcpState::LastAck) => {
                    Style::default().fg(Color::Red)
                }
                _ => Style::default().fg(Color::DarkGray),
            };

            // Truncate cmdline for display.
            let cmdline_display = if r.cmdline.len() > 40 {
                format!("{}…", &r.cmdline[..39])
            } else {
                r.cmdline.clone()
            };

            Row::new([
                Cell::from(r.pid.to_string()),
                Cell::from(r.comm.clone()),
                Cell::from(cmdline_display),
                Cell::from(r.remote_ip.to_string()),
                Cell::from(r.remote_port.to_string()),
                Cell::from(r.proto.as_str()),
                Cell::from(state_str).style(state_style),
                Cell::from(format_bytes(r.tx_bytes)).style(Style::default().fg(Color::Green)),
                Cell::from(format_bytes(r.rx_bytes)).style(Style::default().fg(Color::Cyan)),
            ])
            .height(1)
        })
        .collect();

    let sort_label = if state.sort_by_tx { "TX↓" } else { "RX↓" };
    let title = match state.tab {
        Tab::Active => format!(" Active connections (last 60 s) — sort {sort_label} "),
        Tab::History => format!(" All connections since start — sort {sort_label} "),
    };

    let table = Table::new(rows, COL_WIDTHS)
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(title)
                .border_style(Style::default().fg(Color::Blue)),
        )
        .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED));

    f.render_widget(table, area);
}

fn draw_status(f: &mut Frame, area: ratatui::layout::Rect, store: &GlobalStore, state: &AppState) {
    let count = store.len();
    let sort = if state.sort_by_tx { "TX ↓" } else { "RX ↓" };

    let filter_part = match state.input_mode {
        InputMode::Filter => format!(
            "  │  filter: {}_", // trailing underscore = cursor
            state.tui_filter
        ),
        InputMode::Normal => state
            .effective_filter()
            .map(|f| format!("  │  filter: {f}"))
            .unwrap_or_default(),
    };

    let text = format!(" tracking {count}  │  sort: {sort}{filter_part}");
    let style = if state.input_mode == InputMode::Filter {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default().fg(Color::DarkGray)
    };
    f.render_widget(Paragraph::new(text).style(style), area);
}
