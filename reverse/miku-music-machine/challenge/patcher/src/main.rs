use std::{
    cell,
    collections::{HashMap, HashSet},
    mem::offset_of,
    path::PathBuf,
};

use clap::Parser;
use consts::{
    IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK, IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_SHIFT,
    IMAGE_LOAD_CONFIG_DIRECTORY64,
};
use pdb::{FallibleIterator, SymbolData};
use pelite::pe::{Pe, PeFile, PeObject};
use rand::Rng;

mod consts;

#[derive(Parser)]
struct Args {
    /// Path to input exe. The input PDB should be next to it with the same name.
    #[clap(short, long)]
    input: PathBuf,

    /// Input to maze. Maze format is # for wall, ' ' for empty, small letter for switch, capital letter for door.
    #[clap(short, long)]
    maze: PathBuf,

    /// Target flag. Generates the xor needed for that flag.
    #[clap(short, long)]
    target: String,

    /// Output path for patched binary.
    #[clap(short, long)]
    output: PathBuf,
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
enum Cell {
    Wall,
    Empty,
    Switch(char),
    Door(char), // lowercase to match switch
}

#[derive(Debug, Copy, Clone)]
enum Move {
    Up,    // 0
    Right, // 1
    Down,  // 2
    Left,  // 3
}

#[derive(Debug, Clone)]
struct Maze {
    size: usize, // square maze
    cells: Vec<Cell>,
}

impl Maze {
    fn from_file(path: &std::path::Path) -> Result<Self, Box<dyn std::error::Error>> {
        let maze = std::fs::read_to_string(path).unwrap();

        let size = maze.lines().count();
        let mut cells = Vec::with_capacity(size * size);

        for line in maze.lines() {
            if line.len() != size {
                return Err("Maze is not square".into());
            }

            for ch in line.chars() {
                let cell = match ch {
                    '#' | '█' => Cell::Wall,
                    ' ' => Cell::Empty,
                    'a'..='z' => Cell::Switch(ch),
                    'A'..='Z' => Cell::Door(ch.to_ascii_lowercase()),
                    _ => return Err(format!("Invalid character in maze: {}", ch).into()),
                };
                cells.push(cell);
            }
        }

        Ok(Self { size, cells })
    }

    fn find_path(&self, start: usize, end: usize) -> Option<Vec<Move>> {
        fn valid_moves(maze: &Maze, pos: usize) -> Vec<Move> {
            // we'll just assume that we're always within bounds (i.e., outer wall is always a wall)
            let mut moves = Vec::new();
            if !matches!(maze.cells[pos - maze.size], Cell::Wall) {
                moves.push(Move::Up);
            }
            if !matches!(maze.cells[pos + 1], Cell::Wall) {
                moves.push(Move::Right);
            }
            if !matches!(maze.cells[pos + maze.size], Cell::Wall) {
                moves.push(Move::Down);
            }
            if !matches!(maze.cells[pos - 1], Cell::Wall) {
                moves.push(Move::Left);
            }
            moves
        }

        // dfs to find path
        let mut queue = vec![(start, Vec::new(), HashSet::new())]; // pos, moves, visited
        while let Some((pos, moves, mut visited)) = queue.pop() {
            visited.insert(pos);

            for mov in valid_moves(self, pos) {
                let new_pos = match mov {
                    Move::Up => pos - self.size,
                    Move::Right => pos + 1,
                    Move::Down => pos + self.size,
                    Move::Left => pos - 1,
                };

                if new_pos == end {
                    let mut moves = moves.clone();
                    moves.push(mov);
                    return Some(moves);
                }

                if !visited.contains(&new_pos) {
                    let mut moves = moves.clone();
                    moves.push(mov);
                    queue.push((new_pos, moves, visited.clone()));
                }
            }
        }

        panic!("no path found")
    }
}

#[derive(Debug, Copy, Clone)]
struct CFTableElement {
    rva: u32,
    flags: u8,
}

impl CFTableElement {
    fn from_bytes(bytes: &[u8]) -> Self {
        Self {
            rva: u32::from_le_bytes(bytes[..4].try_into().unwrap()),
            flags: bytes[4],
        }
    }

    fn to_bytes(&self) -> [u8; 5] {
        let mut bytes = [0; 5];
        bytes[..4].copy_from_slice(&self.rva.to_le_bytes());
        bytes[4] = self.flags;
        bytes
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let input_pe = std::fs::read(&args.input).unwrap();
    let input_pdb = std::fs::File::open(&args.input.with_extension("pdb")).unwrap();
    let maze = Maze::from_file(&args.maze).unwrap();

    // compute a full path that moves alphabetically through the switches
    let mut waypoints = maze
        .cells
        .iter()
        .filter_map(|cell| match cell {
            Cell::Switch(ch) => Some(*ch),
            _ => None,
        })
        .collect::<Vec<_>>();
    waypoints.sort();
    let mut path = Vec::new();
    let mut cur_maze = maze.clone();

    for target_pair in waypoints.windows(2) {
        let [from_waypoint, to_waypoint] = target_pair else {
            unreachable!()
        };
        let from = cur_maze
            .cells
            .iter()
            .position(|cell| matches!(cell, Cell::Switch(ch) if ch == from_waypoint))
            .expect("waypoint not found");
        let to = cur_maze
            .cells
            .iter()
            .position(|cell| matches!(cell, Cell::Switch(ch) if ch == to_waypoint))
            .expect("waypoint not found");

        let moves = cur_maze.find_path(from, to).expect("no path found");
        path.extend(moves.iter().cloned());

        // open the door
        let mut new_maze = cur_maze.clone();
        for cell in new_maze.cells.iter_mut() {
            if matches!(cell, Cell::Door(ch) if ch == to_waypoint) {
                *cell = Cell::Empty;
            }
        }
        cur_maze = new_maze;
    }
    assert_eq!(path.len() % 4, 0, "path length not divisible by 4");
    let path_chars = path
        .chunks_exact(4)
        .map(|x| {
            let mut combined_move = 0u8;
            for (i, mov) in x.iter().enumerate() {
                combined_move ^= match mov {
                    Move::Up => 0,
                    Move::Right => 1,
                    Move::Down => 2,
                    Move::Left => 3,
                } << (i * 2);
            }
            combined_move
        })
        .collect::<Vec<_>>();
    assert_eq!(
        args.target.len(),
        path_chars.len(),
        "target length mismatch (want {}, path is {})",
        args.target.len(),
        path_chars.len()
    );

    println!("#define SIZE {}", maze.size);
    println!("#define FLAGLEN {}", args.target.len());
    print!("uint8_t XOR[FLAGLEN] = {{");
    for (target_char, path_char) in args.target.chars().zip(path_chars.iter()) {
        print!("0x{:02x}, ", target_char as u8 ^ path_char);
    }
    println!("}};");

    // modify the input
    let pe = PeFile::from_bytes(&input_pe).unwrap();
    let mut pdb = pdb::PDB::open(&input_pdb).unwrap();

    let mut cell_index_to_rva = vec![0; maze.size.pow(2)];
    let mut rva_to_cell_index = HashMap::new();

    // parse pdb to grab addresses of the cell functions
    let address_map = pdb.address_map().unwrap();
    let dbi = pdb.debug_information().unwrap();
    let mut modules = dbi.modules().unwrap();

    while let Ok(Some(module)) = modules.next() {
        let Ok(Some(module_info)) = pdb.module_info(&module) else {
            continue;
        };

        let Ok(mut symbol_iter) = module_info.symbols() else {
            continue;
        };

        while let Ok(Some(symbol)) = symbol_iter.next() {
            let Ok(SymbolData::Procedure(symbol)) = symbol.parse() else {
                continue;
            };

            let name = symbol.name.to_string();
            if name.starts_with("cell") {
                let i = name[4..].parse::<usize>().unwrap();
                let rva = symbol
                    .offset
                    .to_rva(&address_map)
                    .expect("invalid function rva");
                if i == 1 {
                    println!("cell function 1 rva: {rva:?}");
                }
                cell_index_to_rva[i] = rva.0 as usize;
                rva_to_cell_index.insert(rva.0 as usize, i);
            }
        }
    }

    assert!(
        cell_index_to_rva.iter().all(|&rva| rva != 0),
        "not all cell functions found"
    );

    // grab existing cfg/xfg table
    let load_config_dir = pe
        .data_directory()
        .get(consts::IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG)
        .expect("no load config");
    let load_config = pe
        .derva::<IMAGE_LOAD_CONFIG_DIRECTORY64>(load_config_dir.VirtualAddress)
        .unwrap();

    // check that this is an actual xfg-enabled binary
    assert!(load_config.Size >= 0x78, "load config too small");
    assert!(
        load_config.GuardFlags & consts::IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT != 0,
        "no cfg table present"
    );
    assert!(
        load_config.GuardFlags & consts::IMAGE_GUARD_XFG_ENABLED != 0,
        "xfg not enabled"
    );

    // extra stride per element should be 1 (flags for xfg)
    assert_eq!(
        ((load_config.GuardFlags & IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK)
            >> IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_SHIFT),
        1,
        "invalid stride"
    );

    // grab existing [xc]fg table
    let table_rva = pe.va_to_rva(load_config.GuardCFFunctionTable).unwrap();
    let table_file_offset = pe.rva_to_file_offset(table_rva).unwrap();

    let existing_table = pe.image()[table_file_offset..]
        .chunks_exact(5)
        .take(load_config.GuardCFFunctionCount as usize)
        .map(CFTableElement::from_bytes)
        .collect::<Vec<_>>();

    // strip out any elements that are not walls
    let mut new_table: Vec<_> = existing_table.clone();
    new_table.retain(|elem| {
        let i = rva_to_cell_index.get(&(elem.rva as usize));

        // retain if either not a maze cell, or a wall
        // doors are also in the table, we just mangle their signature (and fix it up later)
        i.is_none() || maze.cells[*i.unwrap()] != Cell::Wall
    });

    let new_table_bytes = new_table
        .iter()
        .flat_map(|elem| elem.to_bytes())
        .collect::<Vec<_>>();

    let mut output_pe = input_pe.clone();

    // update table
    output_pe[table_file_offset..table_file_offset + existing_table.len() * 5].fill(0);
    output_pe[table_file_offset..table_file_offset + new_table_bytes.len()]
        .copy_from_slice(&new_table_bytes);

    // update count
    let load_config_offset = pe
        .rva_to_file_offset(load_config_dir.VirtualAddress)
        .unwrap();
    output_pe
        [load_config_offset + offset_of!(IMAGE_LOAD_CONFIG_DIRECTORY64, GuardCFFunctionCount)..]
        [..4]
        .copy_from_slice(&(new_table.len() as u32).to_le_bytes());

    // add fake push rbp; mov rbp, rsp to the start of each cell function; this ensures that ida/binja detects them as functions
    for rva in &cell_index_to_rva {
        let rva = *rva as u32;
        println!("{rva:x}");
        let file_offset = pe.rva_to_file_offset(rva).unwrap();
        output_pe[file_offset..file_offset + 4].copy_from_slice(&[0x55, 0x48, 0x89, 0xe5]); // push rbp; mov rbp, rsp

        let mut last_nop = rva + 4;
        // continue until we find a nop
        loop {
            let next_file_offset = pe.rva_to_file_offset(last_nop).unwrap();
            if output_pe[next_file_offset] == 0x90 && output_pe[next_file_offset + 1] == 0x90 {
                break;
            }
            last_nop += 1;
        }

        println!("nops for rva {rva:#x}: {last_nop:#x}");

        // then continue until there's no longer a nop
        loop {
            let next_file_offset = pe.rva_to_file_offset(last_nop + 1).unwrap();
            if output_pe[next_file_offset] != 0x90 {
                break;
            }
            last_nop += 1;
        }

        println!("last nop for rva {rva:#x}: {last_nop:#x}");

        // replace last nop with pop rbp
        output_pe[pe.rva_to_file_offset(last_nop).unwrap()] = 0x5d; // pop rbp
    }

    // next, we'll patch a few of the hashes so that switches work as they should
    // first, grab the real xfg hash of a random function
    let real_xfg_hash_offs = pe.rva_to_file_offset(cell_index_to_rva[0] as u32).unwrap();
    let real_xfg_hash = u64::from_le_bytes(output_pe[real_xfg_hash_offs - 8..][..8].try_into()?);
    println!("real xfg hash: {:016x}", real_xfg_hash);

    // ensure all cells have the same hash to avoid potential confusion around lsb not counting in XFG dispatch
    for cell_rva in &cell_index_to_rva {
        let cell_rva = *cell_rva as u32;
        let cell_hash_offs = pe.rva_to_file_offset(cell_rva).unwrap();
        output_pe[cell_hash_offs - 8..][..8].copy_from_slice(&real_xfg_hash.to_le_bytes());
    }

    for waypoint in waypoints {
        let switch_index = maze
            .cells
            .iter()
            .position(|cell| matches!(cell, Cell::Switch(ch) if *ch == waypoint))
            .unwrap();
        let door_indices = maze
            .cells
            .iter()
            .enumerate()
            .filter_map(|(i, cell)| match cell {
                Cell::Door(ch) if *ch == waypoint => Some(i),
                _ => None,
            })
            .collect::<Vec<_>>();
        if door_indices.is_empty() {
            continue; // begin/end marker, no need for adjusting
        }
        assert!(door_indices.len() <= 1, "too many doors for switch"); // we have 23 bytes to work with

        // pick a random bit to flip
        let bit_to_flip = rand::thread_rng().gen_range(1..8); // don't flip the first bit, it's ignored
        let broken_xfg_hash = real_xfg_hash ^ (1 << bit_to_flip);

        // update door indices to have the new (wrong) hash
        for door_index in &door_indices {
            let door_rva = cell_index_to_rva[*door_index] as u32;
            let door_hash_offs = pe.rva_to_file_offset(door_rva).unwrap();
            output_pe[door_hash_offs - 8..][..8].copy_from_slice(&broken_xfg_hash.to_le_bytes());
        }

        println!(
            "switch: {} ({}), doors: {:?}",
            waypoint, switch_index, door_indices
        );

        // update contents of the switch to flip the bit
        for (i, door_index) in door_indices.iter().enumerate() {
            let mut insn_rva = cell_index_to_rva[switch_index] as u32;
            println!("switch rva for {switch_index}: {insn_rva:#x}");
            // scan forwards until we get two consecutive NOPs
            loop {
                let insn_offs = pe.rva_to_file_offset(insn_rva).unwrap();
                if output_pe[insn_offs] != 0x90 || output_pe[insn_offs + 1] != 0x90 {
                    insn_rva += 1;
                    continue;
                }
                break;
            }
            let insn_offs = pe.rva_to_file_offset(insn_rva).unwrap();

            let rva_diff = cell_index_to_rva[*door_index] as i32 - insn_rva as i32 - 7 - 8; // 7 bytes for the instruction, 7 for the offset

            output_pe[insn_offs..][..2].copy_from_slice(&[0x80, 0x35]); // xor byte ptr [rip + 0x12345678], 0x1
            output_pe[insn_offs + 2..][..4].copy_from_slice(&rva_diff.to_le_bytes());
            output_pe[insn_offs + 6] = 1 << bit_to_flip;
        }
    }

    // patch the binary with the new table
    std::fs::write(&args.output, &output_pe).unwrap();

    Ok(())
}
