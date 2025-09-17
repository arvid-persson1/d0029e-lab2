use std::{
    fs::{File, read, write},
    io::{Read, Seek, SeekFrom},
    path::Path,
    process::{Command, Stdio},
};

const BLOCK_SIZE: usize = 128;

fn run(cmd: &str, args: &[&str]) {
    let status = Command::new(cmd)
        .args(args)
        .stdout(Stdio::null())
        .status()
        .unwrap();
    assert!(status.success());
}

fn find(haystack: &[u8], needle: &[u8]) -> usize {
    haystack
        .windows(needle.len())
        .position(|w| w == needle)
        .unwrap()
}

fn read_from(path: impl AsRef<Path>, start: u64) -> Vec<u8> {
    let mut file = File::open(path).unwrap();
    file.seek(SeekFrom::Start(start)).unwrap();

    // This should try to check the length and preallocate accordingly.
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).unwrap();
    buf
}

fn main() {
    run("python", &["-m", "py_compile", "source.py"]);
    let mut pyc = read("__pycache__/source.cpython-313.pyc").unwrap();

    let len_str = BLOCK_SIZE * 2 - 1;
    let start_x = find(&pyc, &vec![b'x'; len_str]);
    let start_y = find(&pyc, &vec![b'y'; len_str]);
    let prefix_len = start_x.next_multiple_of(BLOCK_SIZE);

    // We've found the y-string. Replace 'y' with 'x'.
    let offset = start_y + prefix_len - start_x;
    pyc[start_y..offset].fill(b'x');
    pyc[offset + BLOCK_SIZE..start_y + len_str].fill(b'x');

    write("prefix", &pyc[..prefix_len]).unwrap();
    run("md5collgen", &["-p", "prefix", "-o", "p", "q"]);

    let p = read_from("p", prefix_len as u64);
    let q = read_from("q", prefix_len as u64);
    assert_eq!(p.len(), BLOCK_SIZE);
    assert_eq!(q.len(), BLOCK_SIZE);

    // Write same bytes to first string, but different bytes to second.
    pyc[offset..offset + BLOCK_SIZE].copy_from_slice(&p);
    pyc[prefix_len..prefix_len + BLOCK_SIZE].copy_from_slice(&p);
    write("benign.pyc", &pyc).unwrap();
    pyc[prefix_len..prefix_len + BLOCK_SIZE].copy_from_slice(&q);
    write("malicious.pyc", &pyc).unwrap();
}
