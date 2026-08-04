use std::collections::{HashMap, HashSet};
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, BufReader, BufWriter, Seek, Write};
use std::path::{Path, PathBuf};

use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::Zeroizing;

use crate::error::{IronlockError, Result};
use crate::stream_crypto::{encrypt_stream, StreamDecryptor};

pub const IRONLOCK_EXTENSION: &str = "il";
const LARGE_FILE_THRESHOLD: u64 = 1024 * 1024 * 1024;
const OVERWRITE_BUFFER_SIZE: usize = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptionPlan {
    pub source: PathBuf,
    pub output: PathBuf,
}

pub fn prompt_confirmation(message: &str) -> Result<bool> {
    print!("{message} [y/N]: ");
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let response = input.trim().to_lowercase();
    Ok(response == "y" || response == "yes")
}

pub fn check_overwrite(path: &Path, force: bool) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            reject_link_or_reparse(path, &metadata)?;
            if !metadata.is_file() {
                return Err(IronlockError::UnsafePath(format!(
                    "'{}' is not a regular file",
                    path.display()
                )));
            }
            if force
                || prompt_confirmation(&format!(
                    "File '{}' already exists. Overwrite?",
                    path.display()
                ))?
            {
                Ok(())
            } else {
                Err(IronlockError::Cancelled)
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn is_link_or_reparse(metadata: &Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return true;
        }
    }
    false
}

fn reject_link_or_reparse(path: &Path, metadata: &Metadata) -> Result<()> {
    if is_link_or_reparse(metadata) {
        return Err(IronlockError::UnsafePath(format!(
            "symbolic links and reparse points are not followed: '{}'",
            path.display()
        )));
    }
    Ok(())
}

fn validate_regular_source(path: &Path) -> Result<Metadata> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            IronlockError::FileNotFound(path.display().to_string())
        } else {
            IronlockError::IoError(error)
        }
    })?;
    reject_link_or_reparse(path, &metadata)?;
    if !metadata.is_file() {
        return Err(IronlockError::UnsafePath(format!(
            "'{}' is not a regular file",
            path.display()
        )));
    }
    Ok(metadata)
}

fn ensure_safe_directory(path: &Path) -> Result<()> {
    let absolute = std::path::absolute(path)?;
    let mut current = PathBuf::new();
    for component in absolute.components() {
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) => {
                reject_link_or_reparse(&current, &metadata)?;
                if !metadata.is_dir() {
                    return Err(IronlockError::UnsafePath(format!(
                        "'{}' is not a directory",
                        current.display()
                    )));
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                match fs::create_dir(&current) {
                    Ok(()) => {}
                    Err(create_error) if create_error.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(create_error) => return Err(create_error.into()),
                }
                let metadata = fs::symlink_metadata(&current)?;
                reject_link_or_reparse(&current, &metadata)?;
                if !metadata.is_dir() {
                    return Err(IronlockError::UnsafePath(format!(
                        "'{}' is not a directory",
                        current.display()
                    )));
                }
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn path_matches_open_file(path: &Path, file: &File) -> Result<bool> {
    let path_handle = same_file::Handle::from_path(path)?;
    let file_handle = same_file::Handle::from_file(file.try_clone()?)?;
    Ok(path_handle == file_handle)
}

fn normalized_path_key(path: &Path) -> Result<String> {
    let absolute = std::path::absolute(path)?;
    let key = absolute.to_string_lossy().into_owned();
    #[cfg(windows)]
    let key = key.to_lowercase();
    Ok(key)
}

fn paths_refer_to_same_file(source: &Path, output: &Path) -> Result<bool> {
    if normalized_path_key(source)? == normalized_path_key(output)? {
        return Ok(true);
    }
    match fs::symlink_metadata(output) {
        Ok(output_metadata) => {
            reject_link_or_reparse(output, &output_metadata)?;
            Ok(same_file::is_same_file(source, output)?)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

#[cfg(unix)]
fn open_source_nofollow(path: &Path) -> Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    Ok(OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?)
}

#[cfg(windows)]
fn open_source_nofollow(path: &Path) -> Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    Ok(OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?)
}

#[cfg(not(any(unix, windows)))]
fn open_source_nofollow(path: &Path) -> Result<File> {
    Ok(File::open(path)?)
}

#[cfg(unix)]
fn open_write_nofollow(path: &Path) -> Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    Ok(OpenOptions::new()
        .write(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?)
}

#[cfg(windows)]
fn open_write_nofollow(path: &Path) -> Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    Ok(OpenOptions::new()
        .write(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?)
}

#[cfg(not(any(unix, windows)))]
fn open_write_nofollow(path: &Path) -> Result<File> {
    Ok(OpenOptions::new().write(true).open(path)?)
}

fn verified_source_file(path: &Path) -> Result<(File, Metadata)> {
    validate_regular_source(path)?;
    let file = open_source_nofollow(path)?;
    let handle_metadata = file.metadata()?;
    reject_link_or_reparse(path, &handle_metadata)?;
    if !handle_metadata.is_file() || !path_matches_open_file(path, &file)? {
        return Err(IronlockError::UnsafePath(format!(
            "source changed while opening '{}'",
            path.display()
        )));
    }
    Ok((file, handle_metadata))
}

fn random_temp_path(parent: &Path) -> PathBuf {
    parent.join(format!(
        ".ironlock-{:016x}-{:016x}.tmp",
        OsRng.next_u64(),
        OsRng.next_u64()
    ))
}

#[cfg(unix)]
fn open_private_new(path: &Path) -> Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    Ok(OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?)
}

#[cfg(windows)]
fn open_private_new(path: &Path) -> Result<File> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::{FromRawHandle, RawHandle};
    use std::ptr::null_mut;
    use windows_sys::Win32::Foundation::{LocalFree, GENERIC_WRITE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
    use windows_sys::Win32::Storage::FileSystem::{CreateFileW, CREATE_NEW, FILE_ATTRIBUTE_NORMAL};

    fn wide(value: &OsStr) -> Vec<u16> {
        value.encode_wide().chain(Some(0)).collect()
    }

    let descriptor_text = wide(OsStr::new("D:P(A;;FA;;;SY)(A;;FA;;;OW)"));
    let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
    let converted = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            descriptor_text.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            null_mut(),
        )
    };
    if converted == 0 {
        return Err(io::Error::last_os_error().into());
    }

    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    let path_wide = wide(path.as_os_str());
    let handle = unsafe {
        CreateFileW(
            path_wide.as_ptr(),
            GENERIC_WRITE,
            0,
            &attributes,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            null_mut(),
        )
    };
    unsafe {
        LocalFree(descriptor);
    }
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error().into());
    }
    Ok(unsafe { File::from_raw_handle(handle as RawHandle) })
}

#[cfg(not(any(unix, windows)))]
fn open_private_new(path: &Path) -> Result<File> {
    Ok(OpenOptions::new().write(true).create_new(true).open(path)?)
}

fn create_private_temp(parent: &Path) -> Result<(PathBuf, File)> {
    for _ in 0..128 {
        let path = random_temp_path(parent);
        match open_private_new(&path) {
            Ok(file) => return Ok((path, file)),
            Err(IronlockError::IoError(error)) if error.kind() == io::ErrorKind::AlreadyExists => {
                continue;
            }
            Err(error) => return Err(error),
        }
    }
    Err(IronlockError::IoError(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not allocate a unique temporary output file",
    )))
}

#[cfg(unix)]
fn unix_path(path: &Path) -> Result<std::ffi::CString> {
    use std::os::unix::ffi::OsStrExt;
    std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(|_| {
        IronlockError::UnsafePath(format!("path contains a NUL byte: '{}'", path.display()))
    })
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn install_temp(temp: &Path, destination: &Path, replace: bool) -> Result<()> {
    if replace {
        fs::rename(temp, destination)?;
        return Ok(());
    }

    let temp = unix_path(temp)?;
    let destination = unix_path(destination)?;
    let renamed = unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            temp.as_ptr(),
            libc::AT_FDCWD,
            destination.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if renamed != 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}

#[cfg(target_vendor = "apple")]
fn install_temp(temp: &Path, destination: &Path, replace: bool) -> Result<()> {
    if replace {
        fs::rename(temp, destination)?;
        return Ok(());
    }

    let temp = unix_path(temp)?;
    let destination = unix_path(destination)?;
    let renamed = unsafe {
        libc::renameatx_np(
            libc::AT_FDCWD,
            temp.as_ptr(),
            libc::AT_FDCWD,
            destination.as_ptr(),
            libc::RENAME_EXCL,
        )
    };
    if renamed != 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}

#[cfg(all(
    unix,
    not(any(target_os = "linux", target_os = "android")),
    not(target_vendor = "apple")
))]
fn install_temp(temp: &Path, destination: &Path, replace: bool) -> Result<()> {
    if replace {
        fs::rename(temp, destination)?;
    } else {
        // No portable no-replace rename exists here. Both names are in the same
        // directory, and the random temporary name is linked before it is
        // removed so the fully written inode is never partially exposed.
        fs::hard_link(temp, destination)?;
        fs::remove_file(temp)?;
    }
    Ok(())
}

#[cfg(windows)]
fn install_temp(temp: &Path, destination: &Path, replace: bool) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };
    let temp_wide: Vec<u16> = temp.as_os_str().encode_wide().chain(Some(0)).collect();
    let destination_wide: Vec<u16> = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    let flags = MOVEFILE_WRITE_THROUGH
        | if replace {
            MOVEFILE_REPLACE_EXISTING
        } else {
            0
        };
    let moved = unsafe { MoveFileExW(temp_wide.as_ptr(), destination_wide.as_ptr(), flags) };
    if moved == 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn install_temp(temp: &Path, destination: &Path, replace: bool) -> Result<()> {
    if !replace && destination.exists() {
        return Err(
            io::Error::new(io::ErrorKind::AlreadyExists, "output appeared during write").into(),
        );
    }
    fs::rename(temp, destination)?;
    Ok(())
}

#[cfg(unix)]
fn sync_parent(path: &Path) -> Result<()> {
    File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn sync_parent(_path: &Path) -> Result<()> {
    Ok(())
}

struct AtomicOutput {
    destination: PathBuf,
    temp_path: PathBuf,
    file: Option<File>,
    replace: bool,
    committed: bool,
}

impl AtomicOutput {
    fn new(destination: &Path, force: bool) -> Result<Self> {
        let parent = destination.parent().unwrap_or_else(|| Path::new("."));
        ensure_safe_directory(parent)?;
        let existed = match fs::symlink_metadata(destination) {
            Ok(metadata) => {
                reject_link_or_reparse(destination, &metadata)?;
                if !metadata.is_file() {
                    return Err(IronlockError::UnsafePath(format!(
                        "'{}' is not a regular file",
                        destination.display()
                    )));
                }
                true
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => false,
            Err(error) => return Err(error.into()),
        };
        if existed {
            check_overwrite(destination, force)?;
        }
        let (temp_path, file) = create_private_temp(parent)?;
        Ok(Self {
            destination: destination.to_path_buf(),
            temp_path,
            file: Some(file),
            replace: existed || force,
            committed: false,
        })
    }

    fn writer(&mut self) -> &mut File {
        self.file.as_mut().expect("temporary output is open")
    }

    fn commit(mut self) -> Result<PathBuf> {
        {
            let file = self.file.as_mut().expect("temporary output is open");
            file.flush()?;
            file.sync_all()?;
        }
        drop(self.file.take());
        match fs::symlink_metadata(&self.destination) {
            Ok(metadata) => {
                reject_link_or_reparse(&self.destination, &metadata)?;
                if !metadata.is_file() {
                    return Err(IronlockError::UnsafePath(format!(
                        "'{}' is not a regular file",
                        self.destination.display()
                    )));
                }
                if !self.replace {
                    return Err(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        "output appeared while data was being written",
                    )
                    .into());
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        install_temp(&self.temp_path, &self.destination, self.replace)?;
        let parent = self.destination.parent().unwrap_or_else(|| Path::new("."));
        sync_parent(parent)?;
        self.committed = true;
        Ok(self.destination.clone())
    }
}

impl Drop for AtomicOutput {
    fn drop(&mut self) {
        if !self.committed {
            self.file.take();
            let _ = fs::remove_file(&self.temp_path);
        }
    }
}

struct QuarantinedFile {
    original: PathBuf,
    quarantine: PathBuf,
    active: bool,
}

impl QuarantinedFile {
    fn new(original: &Path) -> Result<Self> {
        let parent = original.parent().unwrap_or_else(|| Path::new("."));
        for _ in 0..128 {
            let quarantine = random_temp_path(parent);
            match install_temp(original, &quarantine, false) {
                Ok(()) => {
                    return Ok(Self {
                        original: original.to_path_buf(),
                        quarantine,
                        active: true,
                    });
                }
                Err(IronlockError::IoError(error))
                    if error.kind() == io::ErrorKind::AlreadyExists =>
                {
                    continue;
                }
                Err(error) => return Err(error),
            }
        }
        Err(IronlockError::SecureDeletionFailed(
            "could not quarantine the source under a unique name".into(),
        ))
    }

    fn path(&self) -> &Path {
        &self.quarantine
    }

    fn remove(mut self) -> Result<()> {
        fs::remove_file(&self.quarantine)?;
        let parent = self.quarantine.parent().unwrap_or_else(|| Path::new("."));
        sync_parent(parent)?;
        self.active = false;
        Ok(())
    }

    fn restore(&mut self) {
        if self.active
            && !self.original.exists()
            && install_temp(&self.quarantine, &self.original, false).is_ok()
        {
            self.active = false;
        }
    }
}

impl Drop for QuarantinedFile {
    fn drop(&mut self) {
        self.restore();
    }
}

pub fn secure_delete(path: &Path) -> Result<()> {
    validate_regular_source(path)
        .map_err(|error| IronlockError::SecureDeletionFailed(error.to_string()))?;
    let quarantine = QuarantinedFile::new(path)
        .map_err(|error| IronlockError::SecureDeletionFailed(error.to_string()))?;
    let quarantine_path = quarantine.path();

    let mut file = open_write_nofollow(quarantine_path)
        .map_err(|error| IronlockError::SecureDeletionFailed(error.to_string()))?;
    let handle_metadata = file
        .metadata()
        .map_err(|error| IronlockError::SecureDeletionFailed(error.to_string()))?;
    if !path_matches_open_file(quarantine_path, &file)
        .map_err(|error| IronlockError::SecureDeletionFailed(error.to_string()))?
    {
        return Err(IronlockError::SecureDeletionFailed(
            "quarantined file changed while opening it".into(),
        ));
    }

    let file_size = handle_metadata.len();
    let mut random_data = Zeroizing::new(vec![0u8; OVERWRITE_BUFFER_SIZE]);
    for _ in 0..3 {
        file.rewind()
            .map_err(|error| IronlockError::SecureDeletionFailed(error.to_string()))?;
        let mut remaining = file_size;
        while remaining != 0 {
            let amount = usize::try_from(remaining.min(random_data.len() as u64))
                .map_err(|error| IronlockError::SecureDeletionFailed(error.to_string()))?;
            OsRng.fill_bytes(&mut random_data[..amount]);
            file.write_all(&random_data[..amount])
                .map_err(|error| IronlockError::SecureDeletionFailed(error.to_string()))?;
            remaining -= amount as u64;
        }
        file.flush()
            .map_err(|error| IronlockError::SecureDeletionFailed(error.to_string()))?;
        file.sync_all()
            .map_err(|error| IronlockError::SecureDeletionFailed(error.to_string()))?;
    }

    let final_metadata = fs::symlink_metadata(quarantine_path)
        .map_err(|error| IronlockError::SecureDeletionFailed(error.to_string()))?;
    reject_link_or_reparse(quarantine_path, &final_metadata)
        .map_err(|error| IronlockError::SecureDeletionFailed(error.to_string()))?;
    if !path_matches_open_file(quarantine_path, &file)
        .map_err(|error| IronlockError::SecureDeletionFailed(error.to_string()))?
    {
        return Err(IronlockError::SecureDeletionFailed(
            "quarantined file changed before deletion".into(),
        ));
    }

    drop(file);
    quarantine
        .remove()
        .map_err(|error| IronlockError::SecureDeletionFailed(error.to_string()))
}

fn default_encrypted_path(source_path: &Path) -> Result<PathBuf> {
    let file_stem = source_path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .ok_or_else(|| {
            IronlockError::IoError(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid UTF-8 filename",
            ))
        })?;
    Ok(source_path
        .parent()
        .unwrap_or_else(|| Path::new(""))
        .join(format!("{file_stem}.{IRONLOCK_EXTENSION}")))
}

fn unique_encrypted_path(source: &Path, unavailable: &HashSet<String>) -> Result<PathBuf> {
    let stem = source
        .file_stem()
        .and_then(|value| value.to_str())
        .ok_or_else(|| IronlockError::UnsafePath("invalid UTF-8 filename".into()))?;
    let parent = source.parent().unwrap_or_else(|| Path::new(""));
    for _ in 0..128 {
        let candidate = parent.join(format!(
            "{stem}-{:016x}.{IRONLOCK_EXTENSION}",
            OsRng.next_u64()
        ));
        let key = normalized_path_key(&candidate)?;
        if !unavailable.contains(&key) && !candidate.exists() {
            return Ok(candidate);
        }
    }
    Err(IronlockError::OutputCollision(format!(
        "could not generate a unique output for '{}'",
        source.display()
    )))
}

fn collect_inputs(inputs: &[PathBuf], decrypting: bool) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    for input in inputs {
        let metadata = fs::symlink_metadata(input).map_err(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                IronlockError::FileNotFound(input.display().to_string())
            } else {
                IronlockError::IoError(error)
            }
        })?;
        reject_link_or_reparse(input, &metadata)?;
        if metadata.is_dir() {
            let directory_files = collect_files_recursive(input)?;
            files.extend(directory_files.into_iter().filter(|path| {
                let encrypted = path.extension().and_then(|extension| extension.to_str())
                    == Some(IRONLOCK_EXTENSION);
                if decrypting {
                    encrypted
                } else {
                    !encrypted
                }
            }));
        } else if metadata.is_file() {
            files.push(input.clone());
        } else {
            return Err(IronlockError::UnsafePath(format!(
                "'{}' is not a regular file or directory",
                input.display()
            )));
        }
    }
    files.sort();
    Ok(files)
}

pub fn plan_encryption_inputs(inputs: &[PathBuf]) -> Result<Vec<EncryptionPlan>> {
    let sources = collect_inputs(inputs, false)?;
    let mut source_keys = HashSet::new();
    for source in &sources {
        let key = normalized_path_key(source)?;
        if !source_keys.insert(key) {
            return Err(IronlockError::OutputCollision(format!(
                "input '{}' was specified more than once",
                source.display()
            )));
        }
    }
    let defaults: Vec<PathBuf> = sources
        .iter()
        .map(|source| default_encrypted_path(source))
        .collect::<Result<_>>()?;
    let mut default_counts = HashMap::<String, usize>::new();
    for output in &defaults {
        *default_counts
            .entry(normalized_path_key(output)?)
            .or_default() += 1;
    }
    let mut unavailable = source_keys;
    let mut plans = Vec::with_capacity(sources.len());
    for (source, default_output) in sources.into_iter().zip(defaults) {
        let default_key = normalized_path_key(&default_output)?;
        let collides = default_counts.get(&default_key).copied().unwrap_or(0) > 1
            || unavailable.contains(&default_key)
            || paths_refer_to_same_file(&source, &default_output)?;
        let output = if collides {
            unique_encrypted_path(&source, &unavailable)?
        } else {
            default_output
        };
        let output_key = normalized_path_key(&output)?;
        if !unavailable.insert(output_key) {
            return Err(IronlockError::OutputCollision(format!(
                "multiple inputs map to '{}'",
                output.display()
            )));
        }
        plans.push(EncryptionPlan { source, output });
    }
    Ok(plans)
}

pub fn encrypt_file_to_path(
    source_path: &Path,
    output_path: &Path,
    password: &[u8],
    force: bool,
    shred: bool,
) -> Result<PathBuf> {
    if paths_refer_to_same_file(source_path, output_path)? {
        return Err(IronlockError::OutputCollision(format!(
            "source and output are the same file: '{}'",
            source_path.display()
        )));
    }
    let (source, metadata) = verified_source_file(source_path)?;
    if metadata.len() > LARGE_FILE_THRESHOLD {
        eprintln!(
            "Notice: streaming large file '{}' ({:.1} GiB)",
            source_path.display(),
            metadata.len() as f64 / (1024.0 * 1024.0 * 1024.0)
        );
    }
    let original_filename = source_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| IronlockError::UnsafePath("invalid UTF-8 filename".into()))?;
    let mut output = AtomicOutput::new(output_path, force)?;
    {
        let mut reader = BufReader::new(source);
        let mut writer = BufWriter::new(output.writer());
        encrypt_stream(password, original_filename, &mut reader, &mut writer)?;
        writer.flush()?;
    }
    let committed = output.commit()?;
    if shred {
        secure_delete(source_path)?;
    }
    Ok(committed)
}

#[cfg(test)]
pub fn encrypt_file(
    source_path: &Path,
    password: &[u8],
    force: bool,
    shred: bool,
) -> Result<PathBuf> {
    validate_regular_source(source_path)?;
    let default = default_encrypted_path(source_path)?;
    let output = if paths_refer_to_same_file(source_path, &default)? {
        let mut unavailable = HashSet::new();
        unavailable.insert(normalized_path_key(source_path)?);
        unique_encrypted_path(source_path, &unavailable)?
    } else {
        default
    };
    encrypt_file_to_path(source_path, &output, password, force, shred)
}

fn sanitized_filename(original_filename: &str) -> Result<String> {
    Path::new(original_filename)
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty() && *name != "." && *name != "..")
        .map(str::to_owned)
        .ok_or_else(|| {
            IronlockError::UnsafePath(
                "invalid or empty filename in authenticated encrypted metadata".into(),
            )
        })
}

fn unique_decrypted_path(path: &Path) -> Result<PathBuf> {
    let parent = path.parent().unwrap_or_else(|| Path::new(""));
    let stem = path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("decrypted");
    let extension = path.extension().and_then(|value| value.to_str());
    for _ in 0..128 {
        let suffix = OsRng.next_u64();
        let filename = match extension {
            Some(extension) => format!("{stem}-decrypted-{suffix:016x}.{extension}"),
            None => format!("{stem}-decrypted-{suffix:016x}"),
        };
        let candidate = parent.join(filename);
        if !candidate.exists() {
            return Ok(candidate);
        }
    }
    Err(IronlockError::OutputCollision(format!(
        "could not generate a safe decrypted path for '{}'",
        path.display()
    )))
}

pub fn decrypt_file_to_path(
    source_path: &Path,
    password: &[u8],
    output_dir: Option<&Path>,
    force: bool,
) -> Result<PathBuf> {
    if source_path
        .extension()
        .and_then(|extension| extension.to_str())
        != Some(IRONLOCK_EXTENSION)
    {
        return Err(IronlockError::InvalidExtension);
    }
    let (source, _) = verified_source_file(source_path)?;
    let decryptor = StreamDecryptor::new(BufReader::new(source), password)?;
    let safe_filename = sanitized_filename(decryptor.filename())?;
    let directory = output_dir.unwrap_or_else(|| Path::new("."));
    ensure_safe_directory(directory)?;
    let mut output_path = directory.join(safe_filename);
    if paths_refer_to_same_file(source_path, &output_path)? {
        output_path = unique_decrypted_path(&output_path)?;
    }
    let mut output = AtomicOutput::new(&output_path, force)?;
    {
        let mut writer = BufWriter::new(output.writer());
        decryptor.decrypt_to(&mut writer)?;
        writer.flush()?;
    }
    output.commit()
}

pub fn collect_files_recursive(dir: &Path) -> Result<Vec<PathBuf>> {
    let root_metadata = fs::symlink_metadata(dir).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            IronlockError::FileNotFound(dir.display().to_string())
        } else {
            IronlockError::IoError(error)
        }
    })?;
    reject_link_or_reparse(dir, &root_metadata)?;
    if !root_metadata.is_dir() {
        return Err(IronlockError::NotADirectory(dir.display().to_string()));
    }
    let root = fs::canonicalize(dir)?;
    let mut files = Vec::new();
    let mut stack = vec![root.clone()];
    while let Some(current) = stack.pop() {
        for entry in fs::read_dir(&current)? {
            let entry = entry?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path)?;
            reject_link_or_reparse(&path, &metadata)?;
            if metadata.is_dir() {
                let canonical = fs::canonicalize(&path)?;
                if !canonical.starts_with(&root) {
                    return Err(IronlockError::UnsafePath(format!(
                        "directory escaped traversal root: '{}'",
                        path.display()
                    )));
                }
                stack.push(canonical);
            } else if metadata.is_file() {
                files.push(path);
            } else {
                return Err(IronlockError::UnsafePath(format!(
                    "unsupported filesystem entry: '{}'",
                    path.display()
                )));
            }
        }
    }
    files.sort();
    Ok(files)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecryptionPlan {
    pub source: PathBuf,
    pub target_dir: PathBuf,
}

pub fn plan_decryption_inputs(
    inputs: &[PathBuf],
    output_base: Option<&Path>,
) -> Result<Vec<DecryptionPlan>> {
    let mut plans = Vec::new();
    let mut seen = HashSet::new();

    for input in inputs {
        let metadata = fs::symlink_metadata(input).map_err(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                IronlockError::FileNotFound(input.display().to_string())
            } else {
                IronlockError::IoError(error)
            }
        })?;
        reject_link_or_reparse(input, &metadata)?;

        if metadata.is_dir() {
            let root = fs::canonicalize(input)?;
            for source in collect_files_recursive(input)? {
                if source.extension().and_then(|extension| extension.to_str())
                    != Some(IRONLOCK_EXTENSION)
                {
                    continue;
                }
                let relative = source.strip_prefix(&root).map_err(|_| {
                    IronlockError::UnsafePath(format!(
                        "'{}' escaped the requested directory",
                        source.display()
                    ))
                })?;
                let target_dir = match output_base {
                    Some(base) => base.join(relative.parent().unwrap_or_else(|| Path::new(""))),
                    None => source
                        .parent()
                        .unwrap_or_else(|| Path::new(""))
                        .to_path_buf(),
                };
                let key = normalized_path_key(&source)?;
                if !seen.insert(key) {
                    return Err(IronlockError::OutputCollision(format!(
                        "input '{}' was specified more than once",
                        source.display()
                    )));
                }
                plans.push(DecryptionPlan { source, target_dir });
            }
        } else if metadata.is_file() {
            let source = input.clone();
            let key = normalized_path_key(&source)?;
            if !seen.insert(key) {
                return Err(IronlockError::OutputCollision(format!(
                    "input '{}' was specified more than once",
                    source.display()
                )));
            }
            let target_dir = output_base
                .map(Path::to_path_buf)
                .unwrap_or_else(|| PathBuf::from("."));
            plans.push(DecryptionPlan { source, target_dir });
        } else {
            return Err(IronlockError::UnsafePath(format!(
                "'{}' is not a regular file or directory",
                input.display()
            )));
        }
    }

    plans.sort_by(|left, right| left.source.cmp(&right.source));
    Ok(plans)
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use tempfile::TempDir;

    fn source(directory: &TempDir, name: &str, content: &[u8]) -> PathBuf {
        let path = directory.path().join(name);
        fs::write(&path, content).unwrap();
        path
    }

    #[test]
    fn file_roundtrip_uses_v2_and_atomic_output() {
        let temp = TempDir::new().unwrap();
        let input = source(&temp, "records.pdf", b"secret records");
        let encrypted = encrypt_file(&input, b"password", false, false).unwrap();

        let mut prefix = [0u8; 9];
        File::open(&encrypted)
            .unwrap()
            .read_exact(&mut prefix)
            .unwrap();
        assert_eq!(&prefix[..8], b"IRONLOCK");
        assert_eq!(prefix[8], crate::stream_crypto::FORMAT_VERSION);

        let output_dir = temp.path().join("out");
        let decrypted =
            decrypt_file_to_path(&encrypted, b"password", Some(&output_dir), false).unwrap();
        assert_eq!(fs::read(decrypted).unwrap(), b"secret records");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(encrypted).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[test]
    fn same_stem_inputs_receive_distinct_outputs_and_roundtrip() {
        let temp = TempDir::new().unwrap();
        let text = source(&temp, "report.txt", b"text version");
        let pdf = source(&temp, "report.pdf", b"pdf version");

        let plans = plan_encryption_inputs(&[text, pdf]).unwrap();
        assert_eq!(plans.len(), 2);
        assert_ne!(plans[0].output, plans[1].output);

        let output = temp.path().join("decrypted");
        for plan in plans {
            let encrypted =
                encrypt_file_to_path(&plan.source, &plan.output, b"password", true, true).unwrap();
            assert!(encrypted.exists());
            assert!(!plan.source.exists());
            decrypt_file_to_path(&encrypted, b"password", Some(&output), false).unwrap();
        }
        assert_eq!(
            fs::read(output.join("report.txt")).unwrap(),
            b"text version"
        );
        assert_eq!(fs::read(output.join("report.pdf")).unwrap(), b"pdf version");
    }

    #[test]
    fn il_input_with_shred_keeps_a_distinct_result() {
        let temp = TempDir::new().unwrap();
        let input = source(&temp, "existing.il", b"already encrypted-looking");
        let encrypted = encrypt_file(&input, b"password", true, true).unwrap();
        assert_ne!(encrypted, input);
        assert!(encrypted.exists());
        assert!(!input.exists());
    }

    #[test]
    fn hostile_kdf_header_is_rejected_before_argon2_allocation() {
        let temp = TempDir::new().unwrap();
        let input = source(&temp, "file.txt", b"data");
        let encrypted = encrypt_file(&input, b"password", false, false).unwrap();
        let mut bytes = fs::read(&encrypted).unwrap();
        bytes[9..13].copy_from_slice(&u32::MAX.to_be_bytes());
        fs::write(&encrypted, bytes).unwrap();

        let result = decrypt_file_to_path(
            &encrypted,
            b"password",
            Some(&temp.path().join("out")),
            false,
        );
        assert!(matches!(result, Err(IronlockError::ResourceLimit(_))));
    }

    #[test]
    fn failed_decryption_does_not_replace_existing_output() {
        let temp = TempDir::new().unwrap();
        let input = source(&temp, "file.txt", b"correct plaintext");
        let encrypted = encrypt_file(&input, b"right", false, false).unwrap();
        let output_dir = temp.path().join("out");
        fs::create_dir(&output_dir).unwrap();
        let existing = output_dir.join("file.txt");
        fs::write(&existing, b"keep me").unwrap();

        let result = decrypt_file_to_path(&encrypted, b"wrong", Some(&output_dir), true);
        assert!(result.is_err());
        assert_eq!(fs::read(existing).unwrap(), b"keep me");
        assert!(!fs::read_dir(output_dir).unwrap().any(|entry| entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .contains(".ironlock-")));
    }

    #[test]
    fn explicit_duplicate_input_is_rejected_before_writes() {
        let temp = TempDir::new().unwrap();
        let input = source(&temp, "file.txt", b"data");
        let result = plan_encryption_inputs(&[input.clone(), input]);
        assert!(matches!(result, Err(IronlockError::OutputCollision(_))));
        assert!(!temp.path().join("file.il").exists());
    }

    #[cfg(unix)]
    #[test]
    fn recursive_collection_rejects_symlinks_without_touching_target() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().unwrap();
        let root = temp.path().join("root");
        let outside = temp.path().join("outside");
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("secret.txt"), b"outside").unwrap();
        symlink(&outside, root.join("escape")).unwrap();

        let result = collect_files_recursive(&root);
        assert!(matches!(result, Err(IronlockError::UnsafePath(_))));
        assert_eq!(fs::read(outside.join("secret.txt")).unwrap(), b"outside");
    }

    #[cfg(unix)]
    #[test]
    fn output_symlink_is_rejected() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().unwrap();
        let input = source(&temp, "file.txt", b"data");
        let victim = source(&temp, "victim.txt", b"victim");
        let output = temp.path().join("file.il");
        symlink(&victim, &output).unwrap();

        let result = encrypt_file_to_path(&input, &output, b"password", true, false);
        assert!(matches!(result, Err(IronlockError::UnsafePath(_))));
        assert_eq!(fs::read(victim).unwrap(), b"victim");
    }
}
