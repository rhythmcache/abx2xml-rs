use abx2xml::cli::Cli;

fn main() {
    if let Err(e) = Cli::run() {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}
