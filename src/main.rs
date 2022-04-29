
fn main() {
    std::fs::copy("binary_original.exe", "binary.exe").unwrap();
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("binary.exe")
        .unwrap();
    let mut mmap = unsafe { memmap2::MmapMut::map_mut(&file).unwrap() };

    // Somewhere below the reference to ..."check failed, check the log file"...
    let pattern = "85 C0 74 ? E8 ? ? ? ? 48 8D 4D";
    let location = patternscan::scan_first_match(std::io::Cursor::new(&mmap), &pattern).unwrap().unwrap();
    mmap[location + 2] = 0xEB; // JZ->JMP
    println!("patched @ {:#X}", location);
}
