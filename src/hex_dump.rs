use bytes::Bytes;
use std::io;

use hexyl::{BorderStyle, Printer};

pub fn print_buf(buf: Bytes) {
    let stdout = io::stdout();
    let mut handle = stdout.lock();

    let show_color = true;
    let show_char_panel = true;
    let show_position_panel = true;
    let use_squeezing = false;
    let border_style = BorderStyle::Unicode;

    let mut printer = Printer::new(
        &mut handle,
        show_color,
        show_char_panel,
        show_position_panel,
        border_style,
        use_squeezing,
    );

    printer.print_all(&buf[..]).unwrap();
}
