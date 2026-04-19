//! Interactive TUI mode powered by Ratatui + Crossterm.
//!
//! Layout
//! ──────
//!   ┌─ Header ──────────────────────────────────────┐
//!   │ NetPulse  v0.1.0   [r]eset  [s]ort  [q]uit   │
//!   ├─ Active connections ──────────────────────────┤
//!   │  PID   COMM       REMOTE ADDR       TX      RX│
//!   │  …                                            │
//!   ├─ Status bar ──────────────────────────────────┤
//!   │ tracking N connections  |  sort: TX ↓        │
//!   └───────────────────────────────────────────────┘

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
    widgets::{Block, Borders, Cell, Paragraph, Row, Table},
};

use crate::model::{GlobalStore, format_bytes};

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

pub async fn run(store: GlobalStore, filter_comm: Option<String>) -> Result<()> {
    // Set up terminal.
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let result = event_loop(&mut terminal, store, filter_comm).await;

    // Restore terminal.
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    result
}

// ---------------------------------------------------------------------------
// Event loop
// ---------------------------------------------------------------------------

struct AppState {
    sort_by_tx: bool,
    filter_comm: Option<String>,
    scroll: usize,
}

async fn event_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    store: GlobalStore,
    filter_comm: Option<String>,
) -> Result<()> {
    let mut state = AppState {
        sort_by_tx: true,
        filter_comm,
        scroll: 0,
    };

    loop {
        // Render.
        terminal.draw(|f| draw(f, &store, &state))?;

        // Poll for input (non-blocking, 200 ms timeout).
        if event::poll(Duration::from_millis(200))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Char('Q') => break,
                        KeyCode::Char('s') | KeyCode::Char('S') => {
                            state.sort_by_tx = !state.sort_by_tx;
                            state.scroll = 0;
                        }
                        KeyCode::Char('r') | KeyCode::Char('R') => {
                            store.reset();
                        }
                        KeyCode::Down | KeyCode::Char('j') => {
                            state.scroll = state.scroll.saturating_add(1);
                        }
                        KeyCode::Up | KeyCode::Char('k') => {
                            state.scroll = state.scroll.saturating_sub(1);
                        }
                        _ => {}
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
            Constraint::Length(3), // header
            Constraint::Min(5),    // table
            Constraint::Length(1), // status bar
        ])
        .split(f.area());

    draw_header(f, chunks[0]);
    draw_table(f, chunks[1], store, state);
    draw_status(f, chunks[2], store, state);
}

fn draw_header(f: &mut Frame, area: ratatui::layout::Rect) {
    let text = Line::from(vec![
        Span::styled(
            " NetPulse ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("│ eBPF per-process network monitor │ "),
        Span::styled("[s]", Style::default().fg(Color::Yellow)),
        Span::raw("ort  "),
        Span::styled("[r]", Style::default().fg(Color::Yellow)),
        Span::raw("eset  "),
        Span::styled("[q]", Style::default().fg(Color::Yellow)),
        Span::raw("uit  ↑↓ scroll"),
    ]);
    let p = Paragraph::new(text).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Blue)),
    );
    f.render_widget(p, area);
}

const COL_WIDTHS: [Constraint; 7] = [
    Constraint::Length(7),  // PID
    Constraint::Length(16), // COMM
    Constraint::Length(21), // REMOTE ADDR
    Constraint::Length(6),  // PORT
    Constraint::Length(5),  // PROTO
    Constraint::Length(12), // TX
    Constraint::Length(12), // RX
];

fn draw_table(f: &mut Frame, area: ratatui::layout::Rect, store: &GlobalStore, state: &AppState) {
    let header_cells = ["PID", "COMM", "REMOTE IP", "PORT", "PROTO", "TX", "RX"].map(|h| {
        Cell::from(h).style(
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )
    });
    let header = Row::new(header_cells)
        .style(Style::default().bg(Color::DarkGray))
        .height(1)
        .bottom_margin(0);

    let records = store.snapshot(state.sort_by_tx);
    let filtered: Vec<_> = if let Some(ref filter) = state.filter_comm {
        let f = filter.to_lowercase();
        records
            .iter()
            .filter(|r| r.comm.to_lowercase().contains(&f))
            .cloned()
            .collect()
    } else {
        records
    };

    let rows: Vec<Row> = filtered
        .iter()
        .skip(state.scroll)
        .map(|r| {
            Row::new([
                Cell::from(r.pid.to_string()),
                Cell::from(r.comm.clone()),
                Cell::from(r.remote_ip.to_string()),
                Cell::from(r.remote_port.to_string()),
                Cell::from(r.proto.as_str()),
                Cell::from(format_bytes(r.tx_bytes)).style(Style::default().fg(Color::Green)),
                Cell::from(format_bytes(r.rx_bytes)).style(Style::default().fg(Color::Cyan)),
            ])
            .height(1)
        })
        .collect();

    let sort_label = if state.sort_by_tx {
        "sort: TX↓"
    } else {
        "sort: RX↓"
    };
    let table = Table::new(rows, COL_WIDTHS)
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(" Connections ({sort_label}) "))
                .border_style(Style::default().fg(Color::Blue)),
        )
        .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED));

    f.render_widget(table, area);
}

fn draw_status(f: &mut Frame, area: ratatui::layout::Rect, store: &GlobalStore, state: &AppState) {
    let count = store.0.read().records.len();
    let sort = if state.sort_by_tx { "TX ↓" } else { "RX ↓" };
    let filter = state
        .filter_comm
        .as_deref()
        .map(|f| format!("  filter: {f}"))
        .unwrap_or_default();
    let text = format!(" tracking {count} connections  │  sort: {sort}{filter}");
    let p = Paragraph::new(text).style(Style::default().fg(Color::DarkGray));
    f.render_widget(p, area);
}
