
fn main() {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("binary.exe")
        .unwrap();
    let mut mmap = unsafe { memmap2::MmapMut::map_mut(&file).unwrap() };

    // Function that references "No activations left. Clearing" ...
    let pattern = "48 89 5C 24 ? 57 48 83 EC 50 48 8B F9 81 FA 13 FC FF FF";
    let location = patternscan::scan_first_match(std::io::Cursor::new(&mmap), &pattern).unwrap().unwrap();
    println!("function location = {:#X}", location);
    let search_start = location + pattern.split(' ').fold(0, |acc, _| acc+1);
    let mut content = &mut mmap[search_start .. search_start+0x200];

    for (i, el) in content.iter().enumerate() {
        if *el == 0x75 || *el == 0xEB {
            let destination = content[i+1];
            if (destination & 0x80) != 0 {
                panic!("Backwards jump! Not a binary we can handle!");
            }

            if *el == 0xEB { println!("JNZ is already patched") } else { println!("patched JNZ") }

            content[i] = 0xEB;
            content = &mut content[i+2 + usize::from(destination) ..];
            break;
        }
    }

    for (i, el) in content.iter().enumerate() {
        if *el == 0x74 || *el == 0xEB {
            let destination = content[i+1];
            if (destination & 0x80) != 0 {
                panic!("Backwards jump! Not a binary we can handle!");
            }

            if *el == 0xEB { println!("JZ is already patched") } else { println!("patched JZ") }

            content[i] = 0xEB;
            break;
        }
    }
}
