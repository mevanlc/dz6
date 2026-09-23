use std::{
    collections::HashSet,
    fs::{File, OpenOptions},
    io::{self, Seek, SeekFrom, Write},
    path::Path,
    string::FromUtf8Error,
};

use arboard::Clipboard;
use goblin::Object;
use goblin::error;
use mmap_io::{MemoryMappedFile, MmapMode};
use ratatui::{Frame, layout::Rect, widgets::ListState};

use crate::{
    config::*,
    editor::*,
    global::calculator::Calculator,
    header::header_view::{Elf, HeaderView, Pe},
    hex::{hex_view::HexView, strings::FoundString},
    input_history::InputHistory,
    reader::Reader,
    themes::*,
};

#[derive(Default)]
pub struct FileInfo {
    pub file: Option<File>,
    pub path: String,
    pub is_read_only: bool,
    pub is_symlink: bool,
    pub name: String,
    pub r#type: &'static str,
    pub size: usize,
    pub mmap: Option<MemoryMappedFile>,
    pub buffer: Option<Vec<u8>>,
}

impl FileInfo {
    /// Get memory mapped file buffer.
    ///
    /// This slice appears to have all file, but beware it is just a mapping from it and every
    /// time you access a page that is not mapped it will load from disk to memory by the OS,
    /// which also takes care of unloading it if memory constrained.
    pub fn get_buffer(&mut self) -> &[u8] {
        if let Some(buffer) = &self.buffer {
            return buffer.as_slice();
        }

        if let Some(mmap) = self.mmap.as_mut() {
            return mmap.as_slice_bytes(0, self.size as u64).unwrap();
        }

        &[]
    }
}

#[derive(Debug)]
pub struct TextView {
    pub area_height: u16,
    pub lines_to_show: usize,
    pub scroll_offset: (u16, u16), // order is (y, x)
    pub table: &'static encoding_rs::Encoding,
}

pub struct Dz6Error {
    // pub code: u16,
    pub message: String,
}

pub struct App {
    pub calculator: Calculator,
    pub clipboard: Result<Clipboard, arboard::Error>,
    pub command_area: Rect,
    pub command_input: InputHistory,
    pub config: Config,
    pub dialog_2nd_renderer: Option<fn(&mut App, &mut Frame)>,
    pub dialog_renderer: Option<fn(&mut App, &mut Frame)>,
    pub editor_view: AppView,
    pub file_info: FileInfo,
    pub header_view: HeaderView,
    pub hex_view: HexView,
    pub last_error: Dz6Error,
    pub list_state: ListState,
    pub log_scroll_offset: (u16, u16),
    pub logs: Vec<String>,
    pub reader: Reader,
    pub running: bool,
    pub screen: Rect,
    pub state: UIState,
    pub string_regex: String,
    pub strings: Vec<FoundString>,
    pub text_view: TextView,
}

#[cfg(unix)]
fn read_link_bytes(path: &Path) -> io::Result<Vec<u8>> {
    use std::os::unix::ffi::OsStrExt;
    let target = std::fs::read_link(path)?;
    Ok(target.as_os_str().as_bytes().to_vec())
}

#[cfg(not(unix))]
fn read_link_bytes(path: &Path) -> io::Result<Vec<u8>> {
    let target = std::fs::read_link(path)?;
    Ok(target.to_string_lossy().into_owned().into_bytes())
}

impl App {
    pub fn new() -> Self {
        App {
            calculator: Calculator::default(),
            clipboard: Clipboard::new(),
            command_area: Rect::default(),
            command_input: InputHistory::default(),
            config: Config {
                database: true,
                dim_control_chars: false,
                dim_zeroes: true,
                header_base: 16,
                hex_mode_bytes_per_line: 16,
                hex_mode_bytes_per_line_auto: false,
                hex_mode_non_graphic_char: '.',
                maximum_strings_to_show: 3000,
                minimum_string_length: 4,
                search_wrap: true,
                theme: DARK,
                // hex_mode_dword_separator: '-',
                // text_mode_tab_spaces: 4,
            },
            dialog_renderer: None,
            dialog_2nd_renderer: None,
            editor_view: AppView::Hex,
            file_info: FileInfo::default(),
            header_view: HeaderView {
                // elf_header_table_state: TableState::new().with_selected_cell(Some((0, 1))),
                ..Default::default()
            },
            hex_view: HexView {
                editing_hex: true,
                highlights: HashSet::with_capacity(8),
                ..Default::default()
            },
            list_state: ListState::default(),
            log_scroll_offset: (0, 0),
            logs: Vec::with_capacity(100),
            reader: Reader::new(),
            running: true,
            screen: Rect::default(),
            state: UIState::Normal,
            string_regex: String::new(),
            strings: Vec::new(),
            text_view: TextView {
                area_height: 0,
                lines_to_show: 0,
                scroll_offset: (0, 0),
                table: encoding_rs::UTF_8,
            },
            last_error: Dz6Error {
                message: "Success".to_string(),
            },
        }
    }

    /// this function tries to identify a file type; this is a boilerplate implementation.
    fn id_file(&mut self) -> error::Result<()> {
        let buffer = self.file_info.get_buffer();

        self.file_info.r#type = match Object::parse(buffer)? {
            Object::COFF(_coff) => "COFF",
            Object::Elf(elf) => {
                self.header_view.elf = Some(Elf {
                    header: elf.header,
                    phdrs: elf.program_headers.clone(),
                    sections: elf.section_headers.clone(),
                    dynsymtab: elf.dynsyms.to_vec(),
                    dynstrtab: elf
                        .dynsyms
                        .iter()
                        .map(|s| s.st_name)
                        .filter_map(|idx| {
                            elf.dynstrtab.get_at(idx).map(|name| (idx, name.to_owned()))
                        })
                        .collect(),
                    symtab: elf.syms.to_vec(),
                    strtab: elf
                        .syms
                        .iter()
                        .map(|s| s.st_name)
                        .filter_map(|idx| elf.strtab.get_at(idx).map(|name| (idx, name.to_owned())))
                        .collect(),
                    // for now we'll just create a single vector containing all relocations as generic ones
                    relocs: [
                        elf.pltrelocs.to_vec(),
                        elf.dynrelas.to_vec(),
                        elf.dynrels.to_vec(),
                    ]
                    .concat(),
                });
                "ELF"
            }
            Object::Mach(_mach) => "Mach-O",
            Object::PE(pe) => {
                let mut imports = Vec::new();
                for imp in pe.imports {
                    imports.push(crate::header::header_view::PEImport {
                        dll: imp.dll.to_string(),
                        name: imp.name.to_string(),
                        offset: imp.offset,
                        ordinal: imp.ordinal,
                        rva: imp.rva,
                        _size: imp.size,
                    });
                }

                let mut exports = Vec::new();
                for exp in pe.exports {
                    exports.push(crate::header::header_view::PEExport {
                        name: exp.name.unwrap_or_default().to_string(),
                        offset: exp.offset.unwrap_or_default(),
                        rva: exp.rva,
                        size: exp.size,
                    });
                }

                self.header_view.pe = Some(Pe {
                    dos_header: pe.header.dos_header,
                    coff_header: pe.header.coff_header,
                    optional_header: pe.header.optional_header,
                    sections: pe.sections,
                    imports,
                    exports,
                });

                "PE"
            }
            Object::TE(_magic) => "TE",
            _ => "",
        };

        Ok(())
    }

    /// load a file
    pub fn load_file(
        &mut self,
        filepath: &str,
        initial_offset: usize,
        read_only: bool,
        open_symlink: bool,
    ) -> io::Result<()> {
        let clean_path =
            if filepath.len() > 1 && (filepath.ends_with('/') || filepath.ends_with('\\')) {
                filepath.trim_end_matches(['/', '\\'])
            } else {
                filepath
            };
        let path = Path::new(clean_path);

        if let Some(f) = path.file_name()
            && let Some(fname) = f.to_str()
        {
            self.file_info.name = String::from(fname);
            self.file_info.path = String::from(filepath);
        }

        let symlink_meta = path.symlink_metadata()?;
        if open_symlink && symlink_meta.file_type().is_symlink() {
            let link_bytes = read_link_bytes(path)?;
            self.file_info.size = link_bytes.len();
            self.file_info.buffer = Some(link_bytes);
            self.file_info.is_read_only = true;
            self.file_info.is_symlink = true;
            self.file_info.file = None;
            self.file_info.mmap = None;
        } else {
            let meta = path.metadata()?;

            // We try to open file readwrite to use this later for saving
            if !read_only && let Ok(file) = OpenOptions::new().read(true).write(true).open(path) {
                self.file_info.file = Some(file);
                self.file_info.is_read_only = false;
            } else {
                self.file_info.file = None;
                self.file_info.is_read_only = true;
            }

            // We map it on memory readonly as changed to mapped memory also changes it on disk
            if let Ok(mmap) = MemoryMappedFile::builder(path)
                .mode(MmapMode::ReadOnly)
                .open()
            {
                self.file_info.mmap = Some(mmap);
            } else {
                return Err(std::io::Error::other("could not open file"));
            }

            self.file_info.size = meta.len() as usize;
            self.file_info.is_symlink = false;
            self.file_info.buffer = None;
        }

        if self.file_info.size > 0 {
            _ = self.id_file();
        }

        self.log(format!(
            "filesize: {} (0x{:x})",
            self.file_info.size, self.file_info.size
        ));

        if initial_offset != 0 {
            self.goto(0);
        }
        self.goto(initial_offset);

        // try to load a database for this file, but continue otherwise
        if self.config.database {
            let _ = self.load_database();
        }

        Ok(())
    }

    pub fn reload_file(&mut self) {
        let fp = self.file_info.path.clone();
        self.load_file(
            &fp,
            self.hex_view.offset,
            self.file_info.is_read_only,
            self.file_info.is_symlink,
        )
        .expect("could not reload the file");
    }

    /// write what's cached to the actual file
    pub fn write_to_file(&mut self) -> io::Result<()> {
        if self.file_info.file.is_none() {
            return Err(io::Error::other("file not open"));
        }

        let mut total_written = 0;

        if let Some(f) = &mut self.file_info.file {
            // changed bytes are not necessairily contiguous, so we
            // loop through them when writing to file
            for (k, v) in &self.hex_view.changed_bytes {
                f.seek(SeekFrom::Start(*k as u64))?;
                if let Ok(b) = u8::from_str_radix(v, 16) {
                    let buf = vec![b];
                    let written = f.write(&buf)?;
                    if written != 1 {
                        return Err(io::Error::other("could not write to file"));
                    }
                    total_written += written;
                }
            }
        }

        App::log(self, format!("{} bytes written to file", total_written));
        self.hex_view.changed_bytes.clear();
        Ok(())
    }

    pub fn read_u8(&mut self, offset: usize) -> Option<u8> {
        if offset >= self.file_info.size {
            return None;
        }

        let buffer = self.file_info.get_buffer();
        Some(buffer[offset])
    }

    pub fn read_i8(&mut self, offset: usize) -> Option<i8> {
        if offset >= self.file_info.size {
            return None;
        }

        let buffer = self.file_info.get_buffer();
        Some(buffer[offset] as i8)
    }

    pub fn read_u16(&mut self, offset: usize) -> Option<u16> {
        if offset + 1 >= self.file_info.size {
            return None;
        }

        let buffer = self.file_info.get_buffer();
        let b1 = buffer[offset];
        let b2 = buffer[offset + 1];

        Some(u16::from_le_bytes([b1, b2]))
    }

    pub fn read_i16(&mut self, offset: usize) -> Option<i16> {
        if offset + 1 >= self.file_info.size {
            return None;
        }

        let buffer = self.file_info.get_buffer();
        let b1 = buffer[offset];
        let b2 = buffer[offset + 1];

        Some(i16::from_le_bytes([b1, b2]))
    }

    pub fn read_u32(&mut self, offset: usize) -> Option<u32> {
        if offset + 3 >= self.file_info.size {
            return None;
        }

        let buffer = self.file_info.get_buffer();
        let b1 = buffer[offset];
        let b2 = buffer[offset + 1];
        let b3 = buffer[offset + 2];
        let b4 = buffer[offset + 3];

        Some(u32::from_le_bytes([b1, b2, b3, b4]))
    }

    pub fn read_i32(&mut self, offset: usize) -> Option<i32> {
        if offset + 3 >= self.file_info.size {
            return None;
        }

        let buffer = self.file_info.get_buffer();
        let b1 = buffer[offset];
        let b2 = buffer[offset + 1];
        let b3 = buffer[offset + 2];
        let b4 = buffer[offset + 3];

        Some(i32::from_le_bytes([b1, b2, b3, b4]))
    }

    pub fn read_u64(&mut self, offset: usize) -> Option<u64> {
        if offset + 7 >= self.file_info.size {
            return None;
        }

        let buffer = self.file_info.get_buffer();
        let b1 = buffer[offset];
        let b2 = buffer[offset + 1];
        let b3 = buffer[offset + 2];
        let b4 = buffer[offset + 3];
        let b5 = buffer[offset + 4];
        let b6 = buffer[offset + 5];
        let b7 = buffer[offset + 6];
        let b8 = buffer[offset + 7];

        Some(u64::from_le_bytes([b1, b2, b3, b4, b5, b6, b7, b8]))
    }

    pub fn read_i64(&mut self, offset: usize) -> Option<i64> {
        if offset + 7 >= self.file_info.size {
            return None;
        }

        let buffer = self.file_info.get_buffer();
        let b1 = buffer[offset];
        let b2 = buffer[offset + 1];
        let b3 = buffer[offset + 2];
        let b4 = buffer[offset + 3];
        let b5 = buffer[offset + 4];
        let b6 = buffer[offset + 5];
        let b7 = buffer[offset + 6];
        let b8 = buffer[offset + 7];

        Some(i64::from_le_bytes([b1, b2, b3, b4, b5, b6, b7, b8]))
    }

    pub fn _read_string(&mut self, offset: usize) -> Result<String, FromUtf8Error> {
        let buffer = self.file_info.get_buffer();

        let it = buffer.iter().skip(offset);

        let mut v = Vec::new();
        for e in it {
            v.push(*e);
        }

        String::from_utf8(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_load_file_regular() {
        let dir = std::env::temp_dir().join(format!("dz6-test-{}", rand::random::<u32>()));
        std::fs::create_dir_all(&dir).unwrap();
        let file_path = dir.join("regular.txt");
        let mut f = File::create(&file_path).unwrap();
        f.write_all(b"regular file content").unwrap();
        drop(f);

        let mut app_no_link = App::new();
        app_no_link
            .load_file(file_path.to_str().unwrap(), 0, false, false)
            .unwrap();
        assert_eq!(app_no_link.file_info.get_buffer(), b"regular file content");
        assert!(!app_no_link.file_info.is_symlink);

        let mut app_link = App::new();
        app_link
            .load_file(file_path.to_str().unwrap(), 0, false, true)
            .unwrap();
        assert_eq!(app_link.file_info.get_buffer(), b"regular file content");
        assert!(!app_link.file_info.is_symlink);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn test_load_file_symlink() {
        use std::os::unix::fs::symlink;

        let dir = std::env::temp_dir().join(format!("dz6-test-{}", rand::random::<u32>()));
        std::fs::create_dir_all(&dir).unwrap();
        let target_path = dir.join("target.txt");
        let mut f = File::create(&target_path).unwrap();
        f.write_all(b"target file content").unwrap();
        drop(f);

        let link_path = dir.join("link_to_target");
        symlink("target.txt", &link_path).unwrap();

        // Without -l (open_symlink = false): follows symlink to target
        let mut app_follow = App::new();
        app_follow
            .load_file(link_path.to_str().unwrap(), 0, false, false)
            .unwrap();
        assert_eq!(app_follow.file_info.get_buffer(), b"target file content");
        assert_eq!(app_follow.file_info.size, 19);
        assert!(!app_follow.file_info.is_symlink);

        // With -l (open_symlink = true): opens softlink contents directly
        let mut app_link = App::new();
        app_link
            .load_file(link_path.to_str().unwrap(), 0, false, true)
            .unwrap();
        assert_eq!(app_link.file_info.get_buffer(), b"target.txt");
        assert_eq!(app_link.file_info.size, 10);
        assert!(app_link.file_info.is_symlink);
        assert!(app_link.file_info.is_read_only);

        // Broken symlink
        let broken_link_path = dir.join("broken_link");
        symlink("nonexistent.bin", &broken_link_path).unwrap();

        // Without -l: fails
        let mut app_broken_follow = App::new();
        assert!(
            app_broken_follow
                .load_file(broken_link_path.to_str().unwrap(), 0, false, false)
                .is_err()
        );

        // With -l: succeeds and opens contents directly
        let mut app_broken_link = App::new();
        app_broken_link
            .load_file(broken_link_path.to_str().unwrap(), 0, false, true)
            .unwrap();
        assert_eq!(app_broken_link.file_info.get_buffer(), b"nonexistent.bin");
        assert_eq!(app_broken_link.file_info.size, 15);
        assert!(app_broken_link.file_info.is_symlink);
        assert!(app_broken_link.file_info.is_read_only);

        // Symlink to symlink
        let link_to_link_path = dir.join("link_to_link");
        symlink("link_to_target", &link_to_link_path).unwrap();

        let mut app_nested = App::new();
        app_nested
            .load_file(link_to_link_path.to_str().unwrap(), 0, false, true)
            .unwrap();
        assert_eq!(app_nested.file_info.get_buffer(), b"link_to_target");
        assert_eq!(app_nested.file_info.size, 14);
        assert!(app_nested.file_info.is_symlink);

        // Symlink to directory
        let real_sub_dir = dir.join("real_sub_dir");
        std::fs::create_dir_all(&real_sub_dir).unwrap();
        let sub_file = real_sub_dir.join("sub_file.txt");
        let mut f = File::create(&sub_file).unwrap();
        f.write_all(b"sub file content").unwrap();
        drop(f);

        let dir_link = dir.join("dir_link");
        symlink("real_sub_dir", &dir_link).unwrap();

        let mut app_dir_link = App::new();
        app_dir_link
            .load_file(dir_link.to_str().unwrap(), 0, false, true)
            .unwrap();
        assert_eq!(app_dir_link.file_info.get_buffer(), b"real_sub_dir");
        assert!(app_dir_link.file_info.is_symlink);

        // With trailing slash
        let mut app_dir_link_slash = App::new();
        let dir_link_slash_str = format!("{}/", dir_link.to_str().unwrap());
        app_dir_link_slash
            .load_file(&dir_link_slash_str, 0, false, true)
            .unwrap();
        assert_eq!(app_dir_link_slash.file_info.get_buffer(), b"real_sub_dir");
        assert!(app_dir_link_slash.file_info.is_symlink);

        // Symlink as intermediate directory component, regular file as leaf
        let sub_file_via_dir_link = dir_link.join("sub_file.txt");
        let mut app_leaf_test = App::new();
        app_leaf_test
            .load_file(sub_file_via_dir_link.to_str().unwrap(), 0, false, true)
            .unwrap();
        // Since sub_file.txt is a regular file (not a symlink leaf), it opens regular file content
        assert_eq!(app_leaf_test.file_info.get_buffer(), b"sub file content");
        assert!(!app_leaf_test.file_info.is_symlink);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
