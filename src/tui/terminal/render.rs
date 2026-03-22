use alacritty_terminal::grid::Dimensions;
use alacritty_terminal::term::cell::Flags;
use alacritty_terminal::vte::ansi::{Color as VteColor, CursorShape, CursorStyle, NamedColor};
use ratatui::style::{Color as TuiColor, Modifier, Style};
use ratatui::text::{Line, Span};

use super::{TerminalSelection, TerminalSession, TerminalView};

#[derive(Clone, Copy, Default)]
struct CellRender {
    ch: char,
    style: Style,
}

pub(crate) fn render_terminal_view(
    session: &TerminalSession,
    blink_on: bool,
    selection: Option<TerminalSelection>,
) -> TerminalView {
    let content = session.term.renderable_content();
    let rows = session.term.screen_lines();
    let cols = session.term.columns();
    if rows == 0 || cols == 0 {
        return TerminalView {
            lines: Vec::new(),
            cursor: None,
        };
    }

    let mut grid = vec![vec![CellRender::default(); cols]; rows];
    for item in content.display_iter {
        let line = item.point.line.0;
        if line < 0 {
            continue;
        }
        let row = line as usize;
        if row >= rows {
            continue;
        }
        let col = item.point.column.0 as usize;
        if col >= cols {
            continue;
        }
        let cell = item.cell;
        if cell
            .flags
            .contains(Flags::WIDE_CHAR_SPACER | Flags::LEADING_WIDE_CHAR_SPACER)
        {
            continue;
        }
        let mut style = style_from_cell(cell);
        if cell.flags.contains(Flags::INVERSE) {
            style = style.add_modifier(Modifier::REVERSED);
        }
        grid[row][col] = CellRender { ch: cell.c, style };
    }

    if let Some(sel) = selection {
        let (sx, sy) = sel.start;
        let (ex, ey) = sel.end;
        let (min_y, max_y) = if sy <= ey { (sy, ey) } else { (ey, sy) };
        let (min_x, max_x) = if sx <= ex { (sx, ex) } else { (ex, sx) };
        for y in min_y as usize..=max_y as usize {
            if y >= rows {
                continue;
            }
            let start_x = if y as u16 == min_y { min_x } else { 0 };
            let end_x = if y as u16 == max_y {
                max_x
            } else {
                (cols.saturating_sub(1)) as u16
            };
            for x in start_x as usize..=end_x as usize {
                if x >= cols {
                    continue;
                }
                grid[y][x].style = grid[y][x].style.add_modifier(Modifier::REVERSED);
            }
        }
    }

    let mut cursor = None;
    let cursor_style: CursorStyle = session.term.cursor_style();
    let cursor_shape = cursor_style.shape;
    let cursor_visible =
        content.cursor.shape != CursorShape::Hidden && (!cursor_style.blinking || blink_on);
    if cursor_visible {
        let line = content.cursor.point.line.0;
        let col = content.cursor.point.column.0;
        if line >= 0 {
            let row = line as usize;
            let col = col as usize;
            if row < rows && col < cols {
                let cell = &mut grid[row][col];
                match cursor_shape {
                    CursorShape::Block => {
                        cell.style = cell.style.add_modifier(Modifier::REVERSED);
                    }
                    CursorShape::HollowBlock => {
                        cell.style = cell.style.add_modifier(Modifier::REVERSED | Modifier::DIM);
                    }
                    CursorShape::Underline => {
                        cell.style = cell.style.add_modifier(Modifier::UNDERLINED);
                    }
                    CursorShape::Beam => {
                        cell.style = cell
                            .style
                            .add_modifier(Modifier::DIM | Modifier::UNDERLINED);
                    }
                    CursorShape::Hidden => {}
                }
                cursor = Some((col as u16, row as u16));
            }
        }
    }

    let mut lines = Vec::with_capacity(rows);
    for row in grid {
        let mut spans = Vec::new();
        let mut cur_style: Option<Style> = None;
        let mut buf = String::new();
        for cell in row {
            if cur_style.is_none() {
                cur_style = Some(cell.style);
            }
            if Some(cell.style) != cur_style {
                push_span(&mut spans, &mut buf, cur_style.unwrap());
                cur_style = Some(cell.style);
            }
            buf.push(cell.ch);
        }
        if let Some(style) = cur_style {
            push_span(&mut spans, &mut buf, style);
        }
        if spans.is_empty() {
            spans.push(Span::raw(""));
        }
        lines.push(Line::from(spans));
    }

    TerminalView { lines, cursor }
}

fn push_span(spans: &mut Vec<Span<'static>>, buf: &mut String, style: Style) {
    spans.push(Span::styled(buf.trim_end_matches(' ').to_string(), style));
    buf.clear();
}

fn style_from_cell(cell: &alacritty_terminal::term::cell::Cell) -> Style {
    let mut style = Style::default();
    style = style.fg(map_color(cell.fg)).bg(map_color(cell.bg));
    if cell.flags.contains(Flags::BOLD) {
        style = style.add_modifier(Modifier::BOLD);
    }
    if cell
        .flags
        .contains(Flags::UNDERLINE | Flags::DOUBLE_UNDERLINE | Flags::UNDERCURL)
    {
        style = style.add_modifier(Modifier::UNDERLINED);
    }
    if cell.flags.contains(Flags::ITALIC) {
        style = style.add_modifier(Modifier::ITALIC);
    }
    if cell.flags.contains(Flags::DIM) {
        style = style.add_modifier(Modifier::DIM);
    }
    if cell.flags.contains(Flags::STRIKEOUT) {
        style = style.add_modifier(Modifier::CROSSED_OUT);
    }
    if cell.flags.contains(Flags::HIDDEN) {
        style = style.add_modifier(Modifier::DIM);
    }
    style
}

fn map_color(color: VteColor) -> TuiColor {
    match color {
        VteColor::Named(named) => match named {
            NamedColor::Black => TuiColor::Black,
            NamedColor::Red => TuiColor::Red,
            NamedColor::Green => TuiColor::Green,
            NamedColor::Yellow => TuiColor::Yellow,
            NamedColor::Blue => TuiColor::Blue,
            NamedColor::Magenta => TuiColor::Magenta,
            NamedColor::Cyan => TuiColor::Cyan,
            NamedColor::White => TuiColor::White,
            NamedColor::BrightBlack => TuiColor::DarkGray,
            NamedColor::BrightRed => TuiColor::LightRed,
            NamedColor::BrightGreen => TuiColor::LightGreen,
            NamedColor::BrightYellow => TuiColor::LightYellow,
            NamedColor::BrightBlue => TuiColor::LightBlue,
            NamedColor::BrightMagenta => TuiColor::LightMagenta,
            NamedColor::BrightCyan => TuiColor::LightCyan,
            NamedColor::BrightWhite => TuiColor::Gray,
            NamedColor::Foreground => TuiColor::Reset,
            NamedColor::Background => TuiColor::Reset,
            NamedColor::Cursor => TuiColor::White,
            NamedColor::DimBlack => TuiColor::Black,
            NamedColor::DimRed => TuiColor::Red,
            NamedColor::DimGreen => TuiColor::Green,
            NamedColor::DimYellow => TuiColor::Yellow,
            NamedColor::DimBlue => TuiColor::Blue,
            NamedColor::DimMagenta => TuiColor::Magenta,
            NamedColor::DimCyan => TuiColor::Cyan,
            NamedColor::DimWhite => TuiColor::Gray,
            NamedColor::BrightForeground | NamedColor::DimForeground => TuiColor::Reset,
        },
        VteColor::Indexed(idx) => match idx as u8 {
            0 => TuiColor::Black,
            1 => TuiColor::Red,
            2 => TuiColor::Green,
            3 => TuiColor::Yellow,
            4 => TuiColor::Blue,
            5 => TuiColor::Magenta,
            6 => TuiColor::Cyan,
            7 => TuiColor::White,
            8 => TuiColor::DarkGray,
            9 => TuiColor::LightRed,
            10 => TuiColor::LightGreen,
            11 => TuiColor::LightYellow,
            12 => TuiColor::LightBlue,
            13 => TuiColor::LightMagenta,
            14 => TuiColor::LightCyan,
            15 => TuiColor::Gray,
            other => TuiColor::Indexed(other),
        },
        VteColor::Spec(rgb) => TuiColor::Rgb(rgb.r, rgb.g, rgb.b),
    }
}
