use addr2line::gimli;
use addr2line::LookupResult;
use flate2::read::GzDecoder;
use memmap2::Mmap;
use object::{Object, ObjectSection};
use regex::Regex;
use rustyline::error::ReadlineError;
use rustyline::DefaultEditor;
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::process::Command;

type Reader<'a> = gimli::EndianSlice<'a, gimli::RunTimeEndian>;

mod profile {
    include!(concat!(env!("OUT_DIR"), "/perftools.profiles.rs"));
}

/// Represents a function with its allocation stats
#[derive(Debug, Clone)]
struct FuncStats {
    name: String,
    file: String,
    flat: i64,  // allocations directly in this function
    cum: i64,   // allocations in this function + all callees
}

/// Represents source line with allocation info
#[derive(Debug, Clone, Default)]
struct LineStats {
    flat: i64,
    cum: i64,
}

/// Parsed and symbolized profile data
struct ProfileData {
    funcs: HashMap<String, FuncStats>,
    // file -> line -> stats
    lines: HashMap<String, HashMap<u32, LineStats>>,
    total: i64,
    unit: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();

    // Parse arguments
    let mut binary_path = None;
    let mut profile_path = None;
    let mut command = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-c" => {
                if i + 1 < args.len() {
                    command = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    eprintln!("Error: -c requires a command argument");
                    std::process::exit(1);
                }
            }
            arg if !arg.starts_with('-') => {
                if binary_path.is_none() {
                    binary_path = Some(arg.to_string());
                } else if profile_path.is_none() {
                    profile_path = Some(arg.to_string());
                }
                i += 1;
            }
            _ => {
                eprintln!("Unknown option: {}", args[i]);
                std::process::exit(1);
            }
        }
    }

    let (binary_path, profile_path) = match (binary_path, profile_path) {
        (Some(b), Some(p)) => (b, p),
        _ => {
            eprintln!("Usage: pprof-symbolize <binary> <profile.pb[.gz]> [-c \"command\"]");
            eprintln!("");
            eprintln!("Options:");
            eprintln!("  -c \"command\"      Run command and exit (non-interactive)");
            eprintln!("");
            eprintln!("Interactive commands:");
            eprintln!("  top [N] [-cum]    Show top N functions (default 10)");
            eprintln!("  list <pattern>    Show source for functions matching pattern");
            eprintln!("  web               Open call graph in browser");
            eprintln!("  help              Show this help");
            eprintln!("  quit              Exit");
            eprintln!("");
            eprintln!("Examples:");
            eprintln!("  pprof-symbolize app heap.pb              # Interactive mode");
            eprintln!("  pprof-symbolize app heap.pb -c \"top 20\"  # Run command and exit");
            std::process::exit(1);
        }
    };

    eprintln!("Loading binary: {}", binary_path);

    let file = File::open(&binary_path)?;
    let mmap = unsafe { Mmap::map(&file)? };
    let object = object::File::parse(&*mmap)?;

    // Load DWARF sections
    let endian = if object.is_little_endian() {
        gimli::RunTimeEndian::Little
    } else {
        gimli::RunTimeEndian::Big
    };

    let load_section = |id: gimli::SectionId| -> Result<Reader<'_>, gimli::Error> {
        let data = object
            .section_by_name(id.name())
            .and_then(|s| s.uncompressed_data().ok())
            .unwrap_or(std::borrow::Cow::Borrowed(&[]));
        Ok(gimli::EndianSlice::new(
            // SAFETY: mmap lifetime >= this closure
            unsafe { std::mem::transmute::<&[u8], &'static [u8]>(&data) },
            endian,
        ))
    };

    let dwarf = gimli::Dwarf::load(&load_section)?;
    let ctx = addr2line::Context::from_dwarf(dwarf)?;

    eprintln!("DWARF loaded");
    eprintln!("Loading profile: {}", profile_path);

    let profile_data = load_profile(&ctx, &profile_path)?;

    eprintln!(
        "Profile loaded: {} functions, {:.1}MB total {}",
        profile_data.funcs.len(),
        profile_data.total as f64 / (1024.0 * 1024.0),
        profile_data.unit
    );

    // Run command or enter REPL
    if let Some(cmd) = command {
        run_command(&profile_data, &cmd);
    } else {
        run_repl(&profile_data)?;
    }

    Ok(())
}

fn run_command(data: &ProfileData, cmd: &str) {
    // Support multiple commands separated by semicolons
    for single_cmd in cmd.split(';') {
        let single_cmd = single_cmd.trim();
        if single_cmd.is_empty() {
            continue;
        }

        let parts: Vec<&str> = single_cmd.split_whitespace().collect();
        let cmd_name = parts.first().map(|s| *s).unwrap_or("");

        match cmd_name {
            "top" => cmd_top(data, &parts[1..]),
            "list" => cmd_list(data, &parts[1..]),
            "web" => cmd_web(data),
            "help" | "h" | "?" => print_help(),
            "" => {}
            _ => eprintln!("Unknown command: {}", cmd_name),
        }
    }
}

/// Returns true if the function name belongs to the allocator or profiling
/// infrastructure and should be skipped when determining flat attribution.
fn is_allocator_frame(name: &str) -> bool {
    // jemalloc internals (may have _rjem_je_ prefix from tikv-jemalloc)
    name.starts_with("prof_backtrace")
        || name.starts_with("_rjem_je_")
        || name.starts_with("imalloc")
        || name.starts_with("isalloc")
        || name.starts_with("idalloct")
        || name.starts_with("ifree")
        || name.starts_with("arena_")
        || name.starts_with("je_")
        || name.starts_with("prof_alloc")
        // Rust global allocator
        || name.starts_with("__rust_alloc")
        || name.starts_with("__rdl_alloc")
        || name.starts_with("__rustc")
        // tikv-jemallocator wrapper
        || name.starts_with("tikv_jemallocator::")
        || name.starts_with("<tikv_jemallocator::")
        // Rust alloc crate internals
        || name.starts_with("alloc::alloc::")
        || name.starts_with("<alloc::alloc::")
        || name.starts_with("alloc::raw_vec::")
        || name.starts_with("alloc::vec::Vec<")
}

fn load_profile(
    ctx: &addr2line::Context<Reader<'static>>,
    path: &str,
) -> Result<ProfileData, Box<dyn std::error::Error>> {
    use prost::Message;

    // Read the file
    let mut file = File::open(path)?;
    let mut raw_data = Vec::new();
    file.read_to_end(&mut raw_data)?;

    // Check for gzip magic bytes (1f 8b)
    let data = if raw_data.len() >= 2 && raw_data[0] == 0x1f && raw_data[1] == 0x8b {
        let mut decoder = GzDecoder::new(&raw_data[..]);
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed)?;
        decompressed
    } else {
        raw_data
    };

    let profile = profile::Profile::decode(&data[..])?;

    // Get sample type info (use first type, typically inuse_space)
    let value_idx = 0;
    let unit = if !profile.sample_type.is_empty() {
        let st = &profile.sample_type[value_idx];
        profile
            .string_table
            .get(st.unit as usize)
            .cloned()
            .unwrap_or_else(|| "bytes".to_string())
    } else {
        "bytes".to_string()
    };

    // Build location ID -> address map
    let mut loc_addrs: HashMap<u64, u64> = HashMap::new();
    for loc in &profile.location {
        if loc.address > 0 {
            loc_addrs.insert(loc.id, loc.address);
        }
    }

    // Symbolize all locations once
    let mut loc_symbols: HashMap<u64, Vec<(String, String, u32)>> = HashMap::new();
    for (&loc_id, &addr) in &loc_addrs {
        loc_symbols.insert(loc_id, symbolize_frames(ctx, addr));
    }

    // Aggregate by function
    let mut funcs: HashMap<String, FuncStats> = HashMap::new();
    let mut lines: HashMap<String, HashMap<u32, LineStats>> = HashMap::new();
    let mut total: i64 = 0;

    for sample in &profile.sample {
        let value = sample.value.get(value_idx).copied().unwrap_or(0);
        if value == 0 {
            continue;
        }
        total += value;

        // Track which functions we've seen in this sample (for cum)
        let mut seen_funcs: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut seen_lines: std::collections::HashSet<(String, u32)> =
            std::collections::HashSet::new();

        // Find the flat leaf frame. The leaf locations in jemalloc profiles
        // contain allocator/profiler frames (prof_backtrace_impl, imalloc,
        // __rust_alloc, etc.) spread across multiple locations. We scan
        // through locations and their inline frames to find the first
        // non-allocator frame for flat attribution.
        let flat_frame: Option<(usize, usize)> = 'find_flat: {
            for (i, loc_id) in sample.location_id.iter().enumerate() {
                if let Some(frames) = loc_symbols.get(loc_id) {
                    for (j, (name, _, _)) in frames.iter().enumerate() {
                        if !is_allocator_frame(name) {
                            break 'find_flat Some((i, j));
                        }
                    }
                }
            }
            // All frames are allocator frames (unlikely), fall back to leaf
            Some((0, 0))
        };

        for (i, loc_id) in sample.location_id.iter().enumerate() {
            if let Some(frames) = loc_symbols.get(loc_id) {
                for (j, (func_name, file, line)) in frames.iter().enumerate() {
                    let is_flat = flat_frame == Some((i, j));

                    let entry = funcs.entry(func_name.clone()).or_insert_with(|| FuncStats {
                        name: func_name.clone(),
                        file: file.clone(),
                        flat: 0,
                        cum: 0,
                    });

                    if is_flat {
                        entry.flat += value;
                    }

                    // Cum: count once per function per sample
                    if seen_funcs.insert(func_name.clone()) {
                        entry.cum += value;
                    }

                    // Line stats
                    if *line > 0 {
                        let file_lines = lines.entry(file.clone()).or_default();
                        let line_stat = file_lines.entry(*line).or_default();
                        if is_flat {
                            line_stat.flat += value;
                        }
                        if seen_lines.insert((file.clone(), *line)) {
                            line_stat.cum += value;
                        }
                    }
                }
            }
        }
    }

    Ok(ProfileData {
        funcs,
        lines,
        total,
        unit,
    })
}

fn symbolize_frames(
    ctx: &addr2line::Context<Reader<'static>>,
    addr: u64,
) -> Vec<(String, String, u32)> {
    let lookup = ctx.find_frames(addr);
    let frames_result = match lookup {
        LookupResult::Output(result) => result,
        LookupResult::Load { .. } => return vec![],
    };

    let mut result = Vec::new();
    if let Ok(mut frames) = frames_result {
        while let Ok(Some(frame)) = frames.next() {
            let func_name = frame
                .function
                .as_ref()
                .and_then(|f| f.demangle().ok())
                .map(|c| c.into_owned())
                .unwrap_or_else(|| format!("0x{:x}", addr));

            let file = frame
                .location
                .as_ref()
                .and_then(|l| l.file)
                .unwrap_or("??")
                .to_string();

            let line = frame.location.as_ref().and_then(|l| l.line).unwrap_or(0);

            result.push((func_name, file, line));
        }
    }
    result
}

fn run_repl(data: &ProfileData) -> Result<(), Box<dyn std::error::Error>> {
    let mut rl = DefaultEditor::new()?;

    println!("Type 'help' for available commands.");

    loop {
        let readline = rl.readline("(pprof) ");
        match readline {
            Ok(line) => {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                let _ = rl.add_history_entry(line);

                let parts: Vec<&str> = line.split_whitespace().collect();
                let cmd = parts.first().map(|s| *s).unwrap_or("");

                match cmd {
                    "quit" | "exit" | "q" => break,
                    "help" | "h" | "?" => print_help(),
                    "top" => cmd_top(data, &parts[1..]),
                    "list" => cmd_list(data, &parts[1..]),
                    "web" => cmd_web(data),
                    _ => println!("Unknown command: {}. Type 'help' for help.", cmd),
                }
            }
            Err(ReadlineError::Interrupted) | Err(ReadlineError::Eof) => {
                break;
            }
            Err(err) => {
                eprintln!("Error: {:?}", err);
                break;
            }
        }
    }

    Ok(())
}

fn print_help() {
    println!("Commands:");
    println!("  top [N] [-cum] [pattern]  Show top N functions (filter by regex pattern)");
    println!("  list <pattern>            Show source lines for functions matching regex");
    println!("  web                       Generate and open SVG call graph in browser");
    println!("  help                      Show this help");
    println!("  quit                      Exit");
    println!("");
    println!("Examples:");
    println!("  top 20 -cum               Top 20 by cumulative");
    println!("  top 30 -cum lance         Top 30 cumulative, only 'lance' functions");
    println!("  top 50 decode             Top 50 flat, only 'decode' functions");
    println!("  list scheduler            Show source for scheduler functions");
}

fn cmd_top(data: &ProfileData, args: &[&str]) {
    let mut n = 10;
    let mut by_cum = false;
    let mut filter_pattern: Option<Regex> = None;

    for arg in args {
        if *arg == "-cum" {
            by_cum = true;
        } else if let Ok(num) = arg.parse::<usize>() {
            n = num;
        } else {
            // Treat as filter pattern
            match Regex::new(&format!("(?i){}", arg)) {
                Ok(re) => filter_pattern = Some(re),
                Err(e) => {
                    println!("Invalid regex pattern '{}': {}", arg, e);
                    return;
                }
            }
        }
    }

    let mut funcs: Vec<&FuncStats> = data.funcs.values().collect();

    // Apply filter if specified
    if let Some(ref re) = filter_pattern {
        funcs.retain(|f| re.is_match(&f.name));
    }

    if by_cum {
        funcs.sort_by(|a, b| b.cum.cmp(&a.cum));
    } else {
        funcs.sort_by(|a, b| b.flat.cmp(&a.flat));
    }

    println!(
        "{:>10} {:>6} {:>10} {:>6}  {}",
        "flat", "flat%", "cum", "cum%", "function"
    );

    for func in funcs.iter().take(n) {
        let flat_mb = func.flat as f64 / (1024.0 * 1024.0);
        let cum_mb = func.cum as f64 / (1024.0 * 1024.0);
        let flat_pct = (func.flat as f64 / data.total as f64) * 100.0;
        let cum_pct = (func.cum as f64 / data.total as f64) * 100.0;

        // Truncate function name for display
        let name = if func.name.len() > 80 {
            format!("{}...", &func.name[..77])
        } else {
            func.name.clone()
        };

        println!(
            "{:>8.2}MB {:>5.1}% {:>8.2}MB {:>5.1}%  {}",
            flat_mb, flat_pct, cum_mb, cum_pct, name
        );
    }
}

fn cmd_list(data: &ProfileData, args: &[&str]) {
    if args.is_empty() {
        println!("Usage: list <pattern>");
        println!("Example: list decode");
        return;
    }

    let pattern = args.join(" ");
    let re = match Regex::new(&format!("(?i){}", pattern)) {
        Ok(r) => r,
        Err(e) => {
            println!("Invalid regex: {}", e);
            return;
        }
    };

    // Find matching functions
    let matching: Vec<&FuncStats> = data
        .funcs
        .values()
        .filter(|f| re.is_match(&f.name))
        .collect();

    if matching.is_empty() {
        println!("No functions match '{}'", pattern);
        return;
    }

    // Collect files to show
    let mut files_to_show: HashMap<&str, Vec<&FuncStats>> = HashMap::new();
    for func in &matching {
        if func.file != "??" {
            files_to_show.entry(&func.file).or_default().push(func);
        }
    }

    if files_to_show.is_empty() {
        println!("No source files found for matching functions.");
        println!("Matching functions:");
        for func in matching.iter().take(10) {
            let cum_mb = func.cum as f64 / (1024.0 * 1024.0);
            println!("  {:.2}MB  {}", cum_mb, func.name);
        }
        return;
    }

    // Show each file with annotated lines
    for (file, funcs) in files_to_show {
        println!("\n{}", "=".repeat(80));
        println!("File: {}", file);
        for func in &funcs {
            let cum_mb = func.cum as f64 / (1024.0 * 1024.0);
            println!("  {:.2}MB  {}", cum_mb, func.name);
        }
        println!("{}", "=".repeat(80));

        // Try to read the file
        if let Ok(content) = std::fs::read_to_string(file) {
            if let Some(file_lines) = data.lines.get(file) {
                let lines: Vec<&str> = content.lines().collect();

                // Find range of interesting lines
                let hot_lines: Vec<u32> = file_lines
                    .iter()
                    .filter(|(_, stats)| stats.cum > 0)
                    .map(|(&line, _)| line)
                    .collect();

                if hot_lines.is_empty() {
                    println!("(no allocations in this file)");
                    continue;
                }

                let min_line = hot_lines.iter().min().copied().unwrap_or(1);
                let max_line = hot_lines.iter().max().copied().unwrap_or(1);

                // Show lines with context
                let start = min_line.saturating_sub(3) as usize;
                let end = (max_line as usize + 3).min(lines.len());

                for i in start..end {
                    let line_num = (i + 1) as u32;
                    let stats = file_lines.get(&line_num);

                    let flat_str = stats
                        .map(|s| {
                            if s.flat > 0 {
                                format!("{:>6.2}MB", s.flat as f64 / (1024.0 * 1024.0))
                            } else {
                                "       .".to_string()
                            }
                        })
                        .unwrap_or_else(|| "        ".to_string());

                    let cum_str = stats
                        .map(|s| {
                            if s.cum > 0 {
                                format!("{:>6.2}MB", s.cum as f64 / (1024.0 * 1024.0))
                            } else {
                                "       .".to_string()
                            }
                        })
                        .unwrap_or_else(|| "        ".to_string());

                    let line_content = lines.get(i).unwrap_or(&"");
                    println!("{} {} {:>5}: {}", flat_str, cum_str, line_num, line_content);
                }
            } else {
                println!("(no line-level data for this file)");
            }
        } else {
            println!("(cannot read file: {})", file);

            // Still show line-level stats if we have them
            if let Some(file_lines) = data.lines.get(file) {
                let mut lines: Vec<_> = file_lines.iter().collect();
                lines.sort_by(|a, b| b.1.cum.cmp(&a.1.cum));

                println!("\nTop lines by cumulative:");
                for (line, stats) in lines.iter().take(10) {
                    let flat_mb = stats.flat as f64 / (1024.0 * 1024.0);
                    let cum_mb = stats.cum as f64 / (1024.0 * 1024.0);
                    println!("  line {:>5}: {:>8.2}MB flat, {:>8.2}MB cum", line, flat_mb, cum_mb);
                }
            }
        }
    }
}

fn cmd_web(data: &ProfileData) {
    // Generate DOT graph
    let mut dot = String::new();
    dot.push_str("digraph {\n");
    dot.push_str("  node [shape=box];\n");

    // Get top functions for the graph
    let mut funcs: Vec<&FuncStats> = data.funcs.values().collect();
    funcs.sort_by(|a, b| b.cum.cmp(&a.cum));

    let top_funcs: Vec<&FuncStats> = funcs.into_iter().take(30).collect();

    for func in &top_funcs {
        let cum_mb = func.cum as f64 / (1024.0 * 1024.0);
        let flat_mb = func.flat as f64 / (1024.0 * 1024.0);
        let cum_pct = (func.cum as f64 / data.total as f64) * 100.0;

        // Shorten name for display
        let short_name = shorten_func_name(&func.name);

        // Node size based on cum
        let fontsize = 10.0 + (cum_pct * 0.5).min(20.0);

        // Color based on flat vs cum ratio
        let flat_ratio = if func.cum > 0 {
            func.flat as f64 / func.cum as f64
        } else {
            0.0
        };
        let red = (255.0 * flat_ratio) as u8;
        let color = format!("#{:02x}8080", red);

        dot.push_str(&format!(
            "  \"{}\" [label=\"{}\\n{:.1}MB ({:.1}%)\\nflat: {:.1}MB\", fontsize={}, style=filled, fillcolor=\"{}\"];\n",
            escape_dot(&func.name),
            escape_dot(&short_name),
            cum_mb,
            cum_pct,
            flat_mb,
            fontsize,
            color
        ));
    }

    dot.push_str("}\n");

    // Write to temp file
    let dot_path = "/tmp/pprof.dot";
    let svg_path = "/tmp/pprof.svg";

    if let Err(e) = std::fs::write(dot_path, &dot) {
        println!("Failed to write DOT file: {}", e);
        return;
    }

    // Try to convert to SVG with dot
    let result = Command::new("dot")
        .args(["-Tsvg", "-o", svg_path, dot_path])
        .output();

    match result {
        Ok(output) if output.status.success() => {
            // Try to open in browser
            let open_result = if cfg!(target_os = "macos") {
                Command::new("open").arg(svg_path).spawn()
            } else if cfg!(target_os = "linux") {
                Command::new("xdg-open").arg(svg_path).spawn()
            } else {
                println!("SVG written to: {}", svg_path);
                return;
            };

            match open_result {
                Ok(_) => println!("Opened {} in browser", svg_path),
                Err(_) => println!("SVG written to: {}", svg_path),
            }
        }
        Ok(output) => {
            println!(
                "dot command failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            println!("DOT file written to: {}", dot_path);
        }
        Err(e) => {
            println!("Failed to run dot (is graphviz installed?): {}", e);
            println!("DOT file written to: {}", dot_path);
        }
    }
}

fn shorten_func_name(name: &str) -> String {
    // Remove common prefixes and shorten generics
    let mut s = name.to_string();

    // Remove crate paths like "foo::bar::baz::" keeping just the function
    if let Some(pos) = s.rfind("::") {
        if pos > 0 {
            // Keep last two components
            let parts: Vec<&str> = s.split("::").collect();
            if parts.len() > 2 {
                s = parts[parts.len() - 2..].join("::");
            }
        }
    }

    // Truncate long generics
    if s.len() > 50 {
        if let Some(pos) = s.find('<') {
            s = format!("{}<...>", &s[..pos]);
        }
    }

    if s.len() > 50 {
        s = format!("{}...", &s[..47]);
    }

    s
}

fn escape_dot(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}
