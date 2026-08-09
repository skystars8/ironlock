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

#[cfg(unix)]
fn hard_link_count(file: &File) -> Result<u64> {
    use std::os::unix::fs::MetadataExt;
    Ok(file.metadata()?.nlink())
}

#[cfg(windows)]
fn hard_link_count(file: &File) -> Result<u64> {
    use std::mem::MaybeUninit;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
    };

    let mut information = MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::zeroed();
    // SAFETY: file owns a valid OS handle for this call, and information points
    // to writable storage large enough for BY_HANDLE_FILE_INFORMATION.
    let succeeded =
        unsafe { GetFileInformationByHandle(file.as_raw_handle() as _, information.as_mut_ptr()) };
    if succeeded == 0 {
        return Err(io::Error::last_os_error().into());
    }
    // SAFETY: GetFileInformationByHandle reported success, so it initialized
    // the complete output structure.
    Ok(u64::from(
        unsafe { information.assume_init() }.nNumberOfLinks,
    ))
}

#[cfg(not(any(unix, windows)))]
fn hard_link_count(_file: &File) -> Result<u64> {
    Ok(1)
}

fn normalized_path_key(path: &Path) -> Result<String> {
    // Normalize lexical parent components first, then canonicalize the closest
    // existing ancestor. This makes not-yet-created output paths share a key
    // across spellings such as `dir/../report.il` and `report.il`, and also
    // resolves any existing ancestor aliases.
    let absolute = std::path::absolute(path)?;
    let mut lexical = PathBuf::new();
    for component in absolute.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                lexical.pop();
            }
            _ => lexical.push(component.as_os_str()),
        }
    }

    let mut ancestor = lexical.as_path();
    let mut missing = Vec::new();
    let mut resolved = loop {
        match fs::canonicalize(ancestor) {
            Ok(existing) => break existing,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let name = ancestor.file_name().ok_or_else(|| {
                    IronlockError::UnsafePath(format!(
                        "could not resolve path '{}'",
                        path.display()
                    ))
                })?;
                missing.push(name.to_os_string());
                ancestor = ancestor.parent().ok_or_else(|| {
                    IronlockError::UnsafePath(format!(
                        "could not resolve path '{}'",
                        path.display()
                    ))
                })?;
            }
            Err(error) => return Err(error.into()),
        }
    };
    for component in missing.into_iter().rev() {
        resolved.push(component);
    }

    let key = resolved.to_string_lossy().into_owned();
    #[cfg(any(windows, target_os = "macos"))]
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
    // SAFETY: descriptor_text is NUL-terminated and descriptor is a valid out
    // pointer. A successful call returns memory owned by LocalFree.
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
    // SAFETY: path_wide is NUL-terminated, attributes references the live
    // descriptor, and every other pointer follows CreateFileW's contract.
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
    // SAFETY: descriptor was allocated by the successful conversion call and
    // is no longer referenced after CreateFileW returns.
    unsafe {
        LocalFree(descriptor);
    }
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error().into());
    }
    // SAFETY: CreateFileW returned a valid, uniquely owned handle. Transferring
    // it to File ensures exactly one CloseHandle when the File is dropped.
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
    // SAFETY: both CString pointers are valid NUL-terminated paths for the
    // duration of renameat2; no Rust memory is aliased or retained.
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
    // SAFETY: both CString pointers are valid NUL-terminated paths for the
    // duration of renameatx_np; no Rust memory is aliased or retained.
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
    // SAFETY: both UTF-16 buffers are NUL-terminated and remain live for the
    // duration of MoveFileExW.
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
    observed_destination: Option<same_file::Handle>,
    committed: bool,
}

impl AtomicOutput {
    fn new(destination: &Path, force: bool) -> Result<Self> {
        let parent = destination.parent().unwrap_or_else(|| Path::new("."));
        ensure_safe_directory(parent)?;
        let observed_destination = match fs::symlink_metadata(destination) {
            Ok(metadata) => {
                reject_link_or_reparse(destination, &metadata)?;
                if !metadata.is_file() {
                    return Err(IronlockError::UnsafePath(format!(
                        "'{}' is not a regular file",
                        destination.display()
                    )));
                }
                Some(same_file::Handle::from_path(destination)?)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(error.into()),
        };
        if let Some(observed) = &observed_destination {
            check_overwrite(destination, force)?;
            let current = same_file::Handle::from_path(destination)?;
            if &current != observed {
                return Err(IronlockError::UnsafePath(format!(
                    "destination changed during overwrite approval: '{}'",
                    destination.display()
                )));
            }
        }
        let (temp_path, file) = create_private_temp(parent)?;
        Ok(Self {
            destination: destination.to_path_buf(),
            temp_path,
            file: Some(file),
            observed_destination,
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
        let replaced = if let Some(observed) = self.observed_destination.take() {
            // Move the destination out of the way without replacing anything,
            // then verify the moved inode/file ID. A path-only check followed
            // by rename would leave another attacker-controlled race window.
            let quarantine = QuarantinedFile::new(&self.destination)?;
            let moved = same_file::Handle::from_path(quarantine.path())?;
            if moved != observed {
                return Err(IronlockError::UnsafePath(format!(
                    "destination changed before atomic replacement: '{}'",
                    self.destination.display()
                )));
            }
            install_temp(&self.temp_path, &self.destination, false)?;
            Some(quarantine)
        } else {
            match fs::symlink_metadata(&self.destination) {
                Ok(metadata) => {
                    reject_link_or_reparse(&self.destination, &metadata)?;
                    return Err(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        "output appeared while data was being written",
                    )
                    .into());
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
            install_temp(&self.temp_path, &self.destination, false)?;
            None
        };
        let parent = self.destination.parent().unwrap_or_else(|| Path::new("."));
        sync_parent(parent)?;
        self.committed = true;
        if let Some(quarantine) = replaced {
            quarantine.remove()?;
        }
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

    #[cfg_attr(windows, allow(clippy::permissions_set_readonly_false))]
    fn remove(mut self) -> Result<()> {
        #[cfg(windows)]
        {
            let mut permissions = fs::metadata(&self.quarantine)?.permissions();
            if permissions.readonly() {
                // On Windows this clears only FILE_ATTRIBUTE_READONLY. Without
                // it, an approved read-only destination could be installed
                // successfully but fail during old-file cleanup.
                permissions.set_readonly(false);
                fs::set_permissions(&self.quarantine, permissions)?;
            }
        }
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

#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_vendor = "apple",
    windows
))]
fn secure_delete_inner(path: &Path, expected_source: Option<&same_file::Handle>) -> Result<()> {
    let (source, _) = verified_source_file(path)
        .map_err(|error| IronlockError::SecureDeletionFailed(error.to_string()))?;
    let expected_handle = same_file::Handle::from_file(source)
        .map_err(|error| IronlockError::SecureDeletionFailed(error.to_string()))?;
    if expected_source.is_some_and(|expected| expected != &expected_handle) {
        return Err(IronlockError::SecureDeletionFailed(
            "source identity changed after encryption; refusing to overwrite it".into(),
        ));
    }
    let quarantine = QuarantinedFile::new(path)
        .map_err(|error| IronlockError::SecureDeletionFailed(error.to_string()))?;
    let quarantine_path = quarantine.path();

    let mut file = open_write_nofollow(quarantine_path)
        .map_err(|error| IronlockError::SecureDeletionFailed(error.to_string()))?;
    let handle_metadata = file
        .metadata()
        .map_err(|error| IronlockError::SecureDeletionFailed(error.to_string()))?;
    let quarantine_handle = same_file::Handle::from_file(
        file.try_clone()
            .map_err(|error| IronlockError::SecureDeletionFailed(error.to_string()))?,
    )
    .map_err(|error| IronlockError::SecureDeletionFailed(error.to_string()))?;
    if quarantine_handle != expected_handle {
        return Err(IronlockError::SecureDeletionFailed(
            "quarantined file changed while opening it".into(),
        ));
    }
    let links = hard_link_count(&file)
        .map_err(|error| IronlockError::SecureDeletionFailed(error.to_string()))?;
    if links != 1 {
        return Err(IronlockError::SecureDeletionFailed(format!(
            "refusing to overwrite a file with {links} hard links"
        )));
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

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_vendor = "apple",
    windows
)))]
fn secure_delete_inner(_path: &Path, _expected_source: Option<&same_file::Handle>) -> Result<()> {
    Err(IronlockError::SecureDeletionFailed(
        "best-effort shredding is unsupported on this platform".into(),
    ))
}

#[cfg(test)]
pub fn secure_delete(path: &Path) -> Result<()> {
    secure_delete_inner(path, None)
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
    let mut source_handles = HashSet::new();
    for source in &sources {
        let key = normalized_path_key(source)?;
        let handle = same_file::Handle::from_path(source)?;
        if !source_keys.insert(key) || !source_handles.insert(handle) {
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
    let source_handle = if shred {
        Some(same_file::Handle::from_file(source.try_clone()?)?)
    } else {
        None
    };
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
        secure_delete_inner(source_path, source_handle.as_ref())?;
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

#[cfg(test)]
pub fn decrypt_file_to_path(
    source_path: &Path,
    password: &[u8],
    output_dir: Option<&Path>,
    force: bool,
) -> Result<PathBuf> {
    decrypt_file_to_path_inner(source_path, password, output_dir, force, None)
}

pub fn decrypt_file_to_path_guarded(
    source_path: &Path,
    password: &[u8],
    output_dir: Option<&Path>,
    force: bool,
    guard: &mut DecryptionBatchGuard,
) -> Result<PathBuf> {
    decrypt_file_to_path_inner(source_path, password, output_dir, force, Some(guard))
}

fn decrypt_file_to_path_inner(
    source_path: &Path,
    password: &[u8],
    output_dir: Option<&Path>,
    force: bool,
    guard: Option<&mut DecryptionBatchGuard>,
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
    if let Some(guard) = guard {
        guard.reserve(source_path, &output_path)?;
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

#[derive(Debug)]
pub struct DecryptionBatchGuard {
    source_keys: HashSet<String>,
    source_handles: HashSet<same_file::Handle>,
    reserved_outputs: HashSet<String>,
}

impl DecryptionBatchGuard {
    pub fn new(plans: &[DecryptionPlan]) -> Result<Self> {
        let mut source_keys = HashSet::new();
        let mut source_handles = HashSet::new();
        for plan in plans {
            let key = normalized_path_key(&plan.source)?;
            let handle = same_file::Handle::from_path(&plan.source)?;
            if !source_keys.insert(key) || !source_handles.insert(handle) {
                return Err(IronlockError::OutputCollision(format!(
                    "input '{}' was specified more than once",
                    plan.source.display()
                )));
            }
        }
        Ok(Self {
            source_keys,
            source_handles,
            reserved_outputs: HashSet::new(),
        })
    }

    fn reserve(&mut self, source: &Path, output: &Path) -> Result<()> {
        let source_key = normalized_path_key(source)?;
        if !self.source_keys.contains(&source_key) {
            return Err(IronlockError::UnsafePath(format!(
                "decryption source '{}' is not part of this batch",
                source.display()
            )));
        }

        let output_key = normalized_path_key(output)?;
        if self.source_keys.contains(&output_key) {
            return Err(IronlockError::OutputCollision(format!(
                "decrypted output '{}' would replace a pending batch input",
                output.display()
            )));
        }
        match fs::symlink_metadata(output) {
            Ok(metadata) => {
                reject_link_or_reparse(output, &metadata)?;
                if metadata.is_file()
                    && self
                        .source_handles
                        .contains(&same_file::Handle::from_path(output)?)
                {
                    return Err(IronlockError::OutputCollision(format!(
                        "decrypted output '{}' aliases a pending batch input",
                        output.display()
                    )));
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        if !self.reserved_outputs.insert(output_key) {
            return Err(IronlockError::OutputCollision(format!(
                "multiple encrypted inputs contain the output filename '{}'",
                output.display()
            )));
        }
        Ok(())
    }
}

pub fn plan_decryption_inputs(
    inputs: &[PathBuf],
    output_base: Option<&Path>,
) -> Result<Vec<DecryptionPlan>> {
    let mut plans = Vec::new();
    let mut seen = HashSet::new();
    let mut seen_handles = HashSet::new();

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
                let handle = same_file::Handle::from_path(&source)?;
                if !seen.insert(key) || !seen_handles.insert(handle) {
                    return Err(IronlockError::OutputCollision(format!(
                        "input '{}' was specified more than once",
                        source.display()
                    )));
                }
                plans.push(DecryptionPlan { source, target_dir });
            }
        } else if metadata.is_file() {
            let source = input.clone();
            if source.extension().and_then(|extension| extension.to_str())
                != Some(IRONLOCK_EXTENSION)
            {
                return Err(IronlockError::InvalidExtension);
            }
            let key = normalized_path_key(&source)?;
            let handle = same_file::Handle::from_path(&source)?;
            if !seen.insert(key) || !seen_handles.insert(handle) {
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

    #[test]
    fn overwrite_preflight_accepts_absent_path_and_forced_regular_file() {
        let temp = TempDir::new().unwrap();
        let absent = temp.path().join("absent.il");
        check_overwrite(&absent, false).unwrap();

        let existing = source(&temp, "existing.il", b"preserve");
        check_overwrite(&existing, true).unwrap();
        assert_eq!(fs::read(existing).unwrap(), b"preserve");
    }

    #[test]
    fn overwrite_preflight_rejects_a_directory_even_when_forced() {
        let temp = TempDir::new().unwrap();
        let directory = temp.path().join("output.il");
        fs::create_dir(&directory).unwrap();

        let result = check_overwrite(&directory, true);
        assert!(matches!(result, Err(IronlockError::UnsafePath(_))));
        assert!(directory.is_dir());
    }

    #[test]
    fn regular_source_validation_distinguishes_missing_and_non_file_inputs() {
        let temp = TempDir::new().unwrap();
        let missing = temp.path().join("missing");
        assert!(matches!(
            validate_regular_source(&missing),
            Err(IronlockError::FileNotFound(_))
        ));
        assert!(matches!(
            validate_regular_source(temp.path()),
            Err(IronlockError::UnsafePath(_))
        ));
    }

    #[test]
    fn authenticated_filename_is_reduced_to_a_safe_basename() {
        assert_eq!(sanitized_filename("plain.txt").unwrap(), "plain.txt");
        assert_eq!(
            sanitized_filename("../../nested/plain.txt").unwrap(),
            "plain.txt"
        );
        assert_eq!(
            sanitized_filename("/absolute/name.bin").unwrap(),
            "name.bin"
        );
    }

    #[test]
    fn authenticated_filename_rejects_empty_and_directory_only_values() {
        for invalid in ["", ".", "..", "/"] {
            assert!(matches!(
                sanitized_filename(invalid),
                Err(IronlockError::UnsafePath(_))
            ));
        }
    }

    #[test]
    fn default_encrypted_path_replaces_only_the_final_extension() {
        let temp = TempDir::new().unwrap();
        assert_eq!(
            default_encrypted_path(&temp.path().join("archive.tar.gz")).unwrap(),
            temp.path().join("archive.tar.il")
        );
        assert_eq!(
            default_encrypted_path(&temp.path().join("extensionless")).unwrap(),
            temp.path().join("extensionless.il")
        );
    }

    #[test]
    fn same_file_detection_handles_lexical_and_hard_link_aliases() {
        let temp = TempDir::new().unwrap();
        let input = source(&temp, "input.txt", b"data");
        let alias = temp.path().join("alias.txt");
        fs::hard_link(&input, &alias).unwrap();

        assert!(paths_refer_to_same_file(&input, &input).unwrap());
        assert!(paths_refer_to_same_file(&input, &alias).unwrap());
        assert!(!paths_refer_to_same_file(&input, &temp.path().join("missing")).unwrap());
    }

    #[test]
    fn normalized_path_keys_collapse_parent_components_for_missing_outputs() {
        let temp = TempDir::new().unwrap();
        fs::create_dir(temp.path().join("nested")).unwrap();
        let direct = temp.path().join("report.il");
        let aliased = temp.path().join("nested").join("..").join("report.il");

        assert_eq!(
            normalized_path_key(&direct).unwrap(),
            normalized_path_key(&aliased).unwrap()
        );
    }

    #[test]
    fn recursive_collection_rejects_a_file_root_and_missing_root() {
        let temp = TempDir::new().unwrap();
        let file = source(&temp, "file.txt", b"data");
        assert!(matches!(
            collect_files_recursive(&file),
            Err(IronlockError::NotADirectory(_))
        ));
        assert!(matches!(
            collect_files_recursive(&temp.path().join("missing")),
            Err(IronlockError::FileNotFound(_))
        ));
    }

    #[test]
    fn recursive_collection_is_complete_and_sorted() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().join("root");
        fs::create_dir_all(root.join("nested")).unwrap();
        fs::write(root.join("z.txt"), b"z").unwrap();
        fs::write(root.join("a.txt"), b"a").unwrap();
        fs::write(root.join("nested").join("m.txt"), b"m").unwrap();

        let files = collect_files_recursive(&root).unwrap();
        let mut sorted = files.clone();
        sorted.sort();
        assert_eq!(files, sorted);
        assert_eq!(files.len(), 3);
    }

    #[test]
    fn safe_directory_creation_builds_nested_paths_and_rejects_file_components() {
        let temp = TempDir::new().unwrap();
        let nested = temp.path().join("one").join("two");
        ensure_safe_directory(&nested).unwrap();
        assert!(nested.is_dir());

        let file = source(&temp, "blocking", b"data");
        let result = ensure_safe_directory(&file.join("child"));
        assert!(matches!(result, Err(IronlockError::UnsafePath(_))));
        assert_eq!(fs::read(file).unwrap(), b"data");
    }

    #[test]
    fn encryption_planning_handles_empty_and_missing_inputs_without_writes() {
        let temp = TempDir::new().unwrap();
        assert!(plan_encryption_inputs(&[]).unwrap().is_empty());
        let result = plan_encryption_inputs(&[temp.path().join("missing.txt")]);
        assert!(matches!(result, Err(IronlockError::FileNotFound(_))));
        assert!(fs::read_dir(temp.path()).unwrap().next().is_none());
    }

    #[test]
    fn encryption_directory_planning_filters_il_files_and_preserves_sources() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().join("root");
        fs::create_dir_all(root.join("nested")).unwrap();
        fs::write(root.join("plain.txt"), b"plain").unwrap();
        fs::write(root.join("skip.il"), b"encrypted").unwrap();
        fs::write(root.join("nested").join("data.bin"), b"binary").unwrap();

        let canonical_root = fs::canonicalize(&root).unwrap();
        let plans = plan_encryption_inputs(std::slice::from_ref(&root)).unwrap();
        assert_eq!(plans.len(), 2);
        assert_eq!(
            plans[0].source,
            canonical_root.join("nested").join("data.bin")
        );
        assert_eq!(
            plans[0].output,
            canonical_root.join("nested").join("data.il")
        );
        assert_eq!(plans[1].source, canonical_root.join("plain.txt"));
        assert_eq!(plans[1].output, canonical_root.join("plain.il"));
        assert_eq!(fs::read(root.join("plain.txt")).unwrap(), b"plain");
        assert_eq!(fs::read(root.join("skip.il")).unwrap(), b"encrypted");
        assert!(!root.join("plain.il").exists());
    }

    #[test]
    fn encryption_planning_rejects_directory_and_explicit_file_duplication() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().join("root");
        fs::create_dir(&root).unwrap();
        let file = root.join("file.txt");
        fs::write(&file, b"data").unwrap();

        let result = plan_encryption_inputs(&[root, file]);
        assert!(matches!(result, Err(IronlockError::OutputCollision(_))));
        assert!(!temp.path().join("root").join("file.il").exists());
    }

    #[test]
    fn encryption_planning_rejects_hard_link_aliases() {
        let temp = TempDir::new().unwrap();
        let original = source(&temp, "original.txt", b"data");
        let alias = temp.path().join("alias.txt");
        fs::hard_link(&original, &alias).unwrap();

        let result = plan_encryption_inputs(&[original.clone(), alias.clone()]);
        assert!(matches!(result, Err(IronlockError::OutputCollision(_))));
        assert_eq!(fs::read(original).unwrap(), b"data");
        assert_eq!(fs::read(alias).unwrap(), b"data");
    }

    #[test]
    fn encryption_planning_prevents_parent_component_output_aliases() {
        let temp = TempDir::new().unwrap();
        fs::create_dir(temp.path().join("nested")).unwrap();
        let text = source(&temp, "report.txt", b"text");
        let pdf = source(&temp, "report.pdf", b"pdf");
        let aliased_text = temp.path().join("nested").join("..").join("report.txt");

        let plans = plan_encryption_inputs(&[aliased_text, pdf]).unwrap();

        assert_eq!(plans.len(), 2);
        assert_ne!(
            normalized_path_key(&plans[0].output).unwrap(),
            normalized_path_key(&plans[1].output).unwrap()
        );
        assert!(text.exists());
    }

    #[cfg(any(windows, target_os = "macos"))]
    #[test]
    fn encryption_planning_prevents_case_insensitive_output_aliases() {
        let temp = TempDir::new().unwrap();
        let lower = source(&temp, "report.txt", b"text");
        let upper = source(&temp, "REPORT.pdf", b"pdf");

        let plans = plan_encryption_inputs(&[lower, upper]).unwrap();

        assert_eq!(plans.len(), 2);
        assert_ne!(
            normalized_path_key(&plans[0].output).unwrap(),
            normalized_path_key(&plans[1].output).unwrap()
        );
    }

    #[test]
    fn decryption_planning_handles_empty_and_missing_inputs_without_writes() {
        let temp = TempDir::new().unwrap();
        let output = temp.path().join("output");
        assert!(plan_decryption_inputs(&[], Some(&output))
            .unwrap()
            .is_empty());
        assert!(!output.exists());

        let result = plan_decryption_inputs(&[temp.path().join("missing.il")], Some(&output));
        assert!(matches!(result, Err(IronlockError::FileNotFound(_))));
        assert!(!output.exists());
    }

    #[test]
    fn decryption_directory_planning_filters_and_preserves_relative_layout() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().join("encrypted");
        let output = temp.path().join("output");
        fs::create_dir_all(root.join("nested")).unwrap();
        fs::write(root.join("top.il"), b"one").unwrap();
        fs::write(root.join("ignore.txt"), b"two").unwrap();
        fs::write(root.join("nested").join("deep.il"), b"three").unwrap();

        let canonical_root = fs::canonicalize(&root).unwrap();
        let plans = plan_decryption_inputs(std::slice::from_ref(&root), Some(&output)).unwrap();
        assert_eq!(plans.len(), 2);
        assert_eq!(
            plans[0].source,
            canonical_root.join("nested").join("deep.il")
        );
        assert_eq!(plans[0].target_dir, output.join("nested"));
        assert_eq!(plans[1].source, canonical_root.join("top.il"));
        assert_eq!(plans[1].target_dir, output);
        assert!(!output.exists());
    }

    #[test]
    fn decryption_directory_planning_without_output_uses_source_directories() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().join("encrypted");
        fs::create_dir_all(root.join("nested")).unwrap();
        let encrypted = root.join("nested").join("data.il");
        fs::write(&encrypted, b"data").unwrap();

        let canonical_root = fs::canonicalize(&root).unwrap();
        let plans = plan_decryption_inputs(&[root], None).unwrap();
        assert_eq!(plans.len(), 1);
        assert_eq!(
            plans[0].source,
            canonical_root.join("nested").join("data.il")
        );
        assert_eq!(plans[0].target_dir, canonical_root.join("nested"));
    }

    #[test]
    fn decryption_planning_rejects_duplicate_and_hard_link_inputs() {
        let temp = TempDir::new().unwrap();
        let encrypted = source(&temp, "one.il", b"data");
        assert!(matches!(
            plan_decryption_inputs(&[encrypted.clone(), encrypted.clone()], None),
            Err(IronlockError::OutputCollision(_))
        ));

        let alias = temp.path().join("two.il");
        fs::hard_link(&encrypted, &alias).unwrap();
        assert!(matches!(
            plan_decryption_inputs(&[encrypted, alias], None),
            Err(IronlockError::OutputCollision(_))
        ));
    }

    #[test]
    fn decryption_rejects_non_il_extensions_before_opening_the_source() {
        let temp = TempDir::new().unwrap();
        for name in ["missing.txt", "missing.IL", "extensionless"] {
            let result = decrypt_file_to_path(&temp.path().join(name), b"password", None, false);
            assert!(matches!(result, Err(IronlockError::InvalidExtension)));
        }
    }

    #[test]
    fn decryption_reports_missing_il_source_without_creating_output_directory() {
        let temp = TempDir::new().unwrap();
        let output = temp.path().join("output");
        let result = decrypt_file_to_path(
            &temp.path().join("missing.il"),
            b"password",
            Some(&output),
            false,
        );
        assert!(matches!(result, Err(IronlockError::FileNotFound(_))));
        assert!(!output.exists());
    }

    #[test]
    fn decryption_planning_rejects_direct_non_il_input_before_writes() {
        let temp = TempDir::new().unwrap();
        let input = source(&temp, "plaintext.txt", b"data");
        let output = temp.path().join("output");

        let result = plan_decryption_inputs(std::slice::from_ref(&input), Some(&output));
        assert!(matches!(result, Err(IronlockError::InvalidExtension)));
        assert_eq!(fs::read(input).unwrap(), b"data");
        assert!(!output.exists());
    }

    #[test]
    fn direct_decryption_plan_uses_requested_output_base() {
        let temp = TempDir::new().unwrap();
        let input = source(&temp, "input.il", b"data");
        let output = temp.path().join("output");

        let plans = plan_decryption_inputs(std::slice::from_ref(&input), Some(&output)).unwrap();
        assert_eq!(
            plans,
            vec![DecryptionPlan {
                source: input,
                target_dir: output.clone(),
            }]
        );
        assert!(!output.exists());
    }

    #[test]
    fn encryption_plan_does_not_modify_an_existing_default_output() {
        let temp = TempDir::new().unwrap();
        let input = source(&temp, "input.txt", b"plaintext");
        let existing = source(&temp, "input.il", b"existing ciphertext");

        let plans = plan_encryption_inputs(std::slice::from_ref(&input)).unwrap();
        assert_eq!(
            plans,
            vec![EncryptionPlan {
                source: input.clone(),
                output: existing.clone(),
            }]
        );
        assert_eq!(fs::read(input).unwrap(), b"plaintext");
        assert_eq!(fs::read(existing).unwrap(), b"existing ciphertext");
    }

    #[test]
    fn malformed_ciphertext_does_not_create_output_directories_or_temps() {
        let temp = TempDir::new().unwrap();
        let input = source(&temp, "malformed.il", b"not an ironlock file");
        let output = temp.path().join("output");

        let result = decrypt_file_to_path(&input, b"password", Some(&output), false);
        assert!(result.is_err());
        assert!(!output.exists());
        assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 1);
    }

    #[test]
    fn unique_decrypted_path_preserves_parent_and_extension() {
        let temp = TempDir::new().unwrap();
        let requested = temp.path().join("report.txt");
        let candidate = unique_decrypted_path(&requested).unwrap();
        assert_eq!(candidate.parent(), Some(temp.path()));
        assert_eq!(
            candidate.extension().and_then(|value| value.to_str()),
            Some("txt")
        );
        assert!(candidate
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("report-decrypted-"));
        assert!(!candidate.exists());
    }

    #[test]
    fn private_new_file_creation_is_exclusive() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("private.tmp");
        let file = open_private_new(&path).unwrap();
        assert!(path.is_file());
        assert!(open_private_new(&path).is_err());
        drop(file);
    }

    #[test]
    fn abandoned_atomic_output_removes_its_private_temporary_file() {
        let temp = TempDir::new().unwrap();
        let destination = temp.path().join("output.il");
        let temporary = {
            let mut output = AtomicOutput::new(&destination, false).unwrap();
            output.writer().write_all(b"partial").unwrap();
            let temporary = output.temp_path.clone();
            assert!(temporary.exists());
            temporary
        };

        assert!(!temporary.exists());
        assert!(!destination.exists());
        assert!(fs::read_dir(temp.path()).unwrap().next().is_none());
    }

    #[test]
    fn force_does_not_clobber_a_file_that_appears_during_atomic_write() {
        let temp = TempDir::new().unwrap();
        let destination = temp.path().join("output.il");
        let mut output = AtomicOutput::new(&destination, true).unwrap();
        output.writer().write_all(b"new encrypted data").unwrap();
        let temporary = output.temp_path.clone();
        fs::write(&destination, b"appeared concurrently").unwrap();

        let result = output.commit();
        assert!(matches!(
            result,
            Err(IronlockError::IoError(ref error))
                if error.kind() == io::ErrorKind::AlreadyExists
        ));
        assert_eq!(fs::read(&destination).unwrap(), b"appeared concurrently");
        assert!(!temporary.exists());
    }

    #[test]
    fn forced_atomic_output_replaces_a_file_observed_at_preflight() {
        let temp = TempDir::new().unwrap();
        let destination = source(&temp, "output.il", b"old");
        let mut output = AtomicOutput::new(&destination, true).unwrap();
        output.writer().write_all(b"new").unwrap();

        assert_eq!(output.commit().unwrap(), destination);
        assert_eq!(fs::read(destination).unwrap(), b"new");
    }

    #[test]
    fn forced_atomic_output_refuses_a_replaced_destination_identity() {
        let temp = TempDir::new().unwrap();
        let destination = source(&temp, "destination", b"approved original");
        let moved_original = temp.path().join("moved-original");
        let mut output = AtomicOutput::new(&destination, true).unwrap();
        output.writer().write_all(b"new output").unwrap();
        fs::rename(&destination, &moved_original).unwrap();
        fs::write(&destination, b"replacement must survive").unwrap();

        let result = output.commit();

        assert!(matches!(
            result,
            Err(IronlockError::UnsafePath(ref message))
                if message.contains("changed before atomic replacement")
        ));
        assert_eq!(fs::read(destination).unwrap(), b"replacement must survive");
        assert_eq!(fs::read(moved_original).unwrap(), b"approved original");
        assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 2);
    }

    #[cfg(windows)]
    #[test]
    fn forced_atomic_output_replaces_and_cleans_up_a_read_only_destination() {
        let temp = TempDir::new().unwrap();
        let destination = source(&temp, "destination", b"old");
        let mut permissions = fs::metadata(&destination).unwrap().permissions();
        permissions.set_readonly(true);
        fs::set_permissions(&destination, permissions).unwrap();
        let mut output = AtomicOutput::new(&destination, true).unwrap();
        output.writer().write_all(b"new").unwrap();

        let committed = output.commit().unwrap();

        assert_eq!(committed, destination);
        assert_eq!(fs::read(&destination).unwrap(), b"new");
        assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 1);
    }

    #[test]
    fn atomic_output_creates_nested_directories_and_commits_complete_data() {
        let temp = TempDir::new().unwrap();
        let destination = temp.path().join("nested").join("deeper").join("output.il");
        let mut output = AtomicOutput::new(&destination, false).unwrap();
        output.writer().write_all(b"complete").unwrap();

        assert_eq!(output.commit().unwrap(), destination);
        assert_eq!(fs::read(&destination).unwrap(), b"complete");
        assert!(!fs::read_dir(destination.parent().unwrap())
            .unwrap()
            .any(|entry| entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".ironlock-")));
    }

    #[cfg(unix)]
    #[test]
    fn newly_committed_atomic_output_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let temp = TempDir::new().unwrap();
        let destination = temp.path().join("output.il");
        let mut output = AtomicOutput::new(&destination, false).unwrap();
        output.writer().write_all(b"private").unwrap();
        output.commit().unwrap();

        assert_eq!(
            fs::metadata(destination).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn atomic_output_rejects_a_directory_destination_without_temp_artifacts() {
        let temp = TempDir::new().unwrap();
        let destination = temp.path().join("output.il");
        fs::create_dir(&destination).unwrap();

        let result = AtomicOutput::new(&destination, true);
        assert!(matches!(result, Err(IronlockError::UnsafePath(_))));
        assert!(destination.is_dir());
        assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 1);
    }

    #[test]
    fn no_replace_install_preserves_both_files_on_collision() {
        let temp = TempDir::new().unwrap();
        let temporary = source(&temp, "temporary", b"new");
        let destination = source(&temp, "destination", b"old");

        assert!(install_temp(&temporary, &destination, false).is_err());
        assert_eq!(fs::read(temporary).unwrap(), b"new");
        assert_eq!(fs::read(destination).unwrap(), b"old");
    }

    #[test]
    fn replace_install_atomically_moves_the_temporary_file() {
        let temp = TempDir::new().unwrap();
        let temporary = source(&temp, "temporary", b"new");
        let destination = source(&temp, "destination", b"old");

        install_temp(&temporary, &destination, true).unwrap();
        assert!(!temporary.exists());
        assert_eq!(fs::read(destination).unwrap(), b"new");
    }

    #[test]
    fn quarantined_file_is_restored_when_not_explicitly_removed() {
        let temp = TempDir::new().unwrap();
        let original = source(&temp, "original", b"data");
        let quarantine_path = {
            let quarantine = QuarantinedFile::new(&original).unwrap();
            assert!(!original.exists());
            assert_eq!(fs::read(quarantine.path()).unwrap(), b"data");
            quarantine.path().to_path_buf()
        };

        assert_eq!(fs::read(&original).unwrap(), b"data");
        assert!(!quarantine_path.exists());
    }

    #[test]
    fn explicitly_removed_quarantine_does_not_restore_the_original() {
        let temp = TempDir::new().unwrap();
        let original = source(&temp, "original", b"data");
        let quarantine = QuarantinedFile::new(&original).unwrap();
        let quarantine_path = quarantine.path().to_path_buf();
        quarantine.remove().unwrap();

        assert!(!original.exists());
        assert!(!quarantine_path.exists());
    }

    #[test]
    fn secure_delete_removes_empty_small_and_multichunk_files() {
        let temp = TempDir::new().unwrap();
        let cases = [
            ("empty", Vec::new()),
            ("small", b"sensitive".to_vec()),
            (
                "multichunk",
                vec![0x5a; OVERWRITE_BUFFER_SIZE.saturating_add(17)],
            ),
        ];

        for (name, contents) in cases {
            let path = temp.path().join(name);
            fs::write(&path, contents).unwrap();
            secure_delete(&path).unwrap();
            assert!(!path.exists());
        }
        assert!(fs::read_dir(temp.path()).unwrap().next().is_none());
    }

    #[test]
    fn secure_delete_rejects_missing_paths_and_directories_without_mutation() {
        let temp = TempDir::new().unwrap();
        let missing = temp.path().join("missing");
        assert!(matches!(
            secure_delete(&missing),
            Err(IronlockError::SecureDeletionFailed(_))
        ));

        let directory = temp.path().join("directory");
        fs::create_dir(&directory).unwrap();
        assert!(matches!(
            secure_delete(&directory),
            Err(IronlockError::SecureDeletionFailed(_))
        ));
        assert!(directory.is_dir());
    }

    #[test]
    fn secure_delete_refuses_hard_linked_files_and_preserves_every_alias() {
        let temp = TempDir::new().unwrap();
        let original = source(&temp, "original", b"sensitive");
        let alias = temp.path().join("alias");
        fs::hard_link(&original, &alias).unwrap();

        let result = secure_delete(&original);
        assert!(matches!(
            result,
            Err(IronlockError::SecureDeletionFailed(ref message))
                if message.contains("hard links")
        ));
        assert_eq!(fs::read(original).unwrap(), b"sensitive");
        assert_eq!(fs::read(alias).unwrap(), b"sensitive");
        assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 2);
    }

    #[test]
    fn secure_delete_refuses_a_source_replaced_after_encryption_opened_it() {
        let temp = TempDir::new().unwrap();
        let original = source(&temp, "original", b"encrypted content");
        let expected = same_file::Handle::from_path(&original).unwrap();
        let moved = temp.path().join("moved");
        fs::rename(&original, &moved).unwrap();
        fs::write(&original, b"replacement must survive").unwrap();

        let result = secure_delete_inner(&original, Some(&expected));

        assert!(matches!(
            result,
            Err(IronlockError::SecureDeletionFailed(ref message))
                if message.contains("identity changed")
        ));
        assert_eq!(fs::read(original).unwrap(), b"replacement must survive");
        assert_eq!(fs::read(moved).unwrap(), b"encrypted content");
        assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 2);
    }

    #[cfg(windows)]
    #[test]
    #[allow(clippy::permissions_set_readonly_false)]
    fn secure_delete_failure_restores_a_read_only_file() {
        let temp = TempDir::new().unwrap();
        let path = source(&temp, "readonly", b"sensitive");
        let mut permissions = fs::metadata(&path).unwrap().permissions();
        permissions.set_readonly(true);
        fs::set_permissions(&path, permissions).unwrap();

        let result = secure_delete(&path);
        assert!(matches!(
            result,
            Err(IronlockError::SecureDeletionFailed(_))
        ));
        assert_eq!(fs::read(&path).unwrap(), b"sensitive");

        let mut permissions = fs::metadata(&path).unwrap().permissions();
        permissions.set_readonly(false);
        fs::set_permissions(path, permissions).unwrap();
    }

    #[test]
    fn encryption_rejects_same_path_and_hard_link_output_before_writing() {
        let temp = TempDir::new().unwrap();
        let source_path = source(&temp, "source.txt", b"plaintext");
        assert!(matches!(
            encrypt_file_to_path(&source_path, &source_path, b"password", true, false),
            Err(IronlockError::OutputCollision(_))
        ));

        let alias = temp.path().join("alias.il");
        fs::hard_link(&source_path, &alias).unwrap();
        assert!(matches!(
            encrypt_file_to_path(&source_path, &alias, b"password", true, false),
            Err(IronlockError::OutputCollision(_))
        ));
        assert_eq!(fs::read(source_path).unwrap(), b"plaintext");
        assert_eq!(fs::read(alias).unwrap(), b"plaintext");
    }

    #[test]
    fn encryption_rejects_directory_output_without_leaving_a_temp_file() {
        let temp = TempDir::new().unwrap();
        let input = source(&temp, "input.txt", b"plaintext");
        let destination = temp.path().join("output.il");
        fs::create_dir(&destination).unwrap();

        let result = encrypt_file_to_path(&input, &destination, b"password", true, false);
        assert!(matches!(result, Err(IronlockError::UnsafePath(_))));
        assert_eq!(fs::read(input).unwrap(), b"plaintext");
        assert!(destination.is_dir());
        assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 2);
    }

    #[test]
    fn batch_guard_rejects_duplicate_and_hard_link_plan_sources() {
        let temp = TempDir::new().unwrap();
        let first = source(&temp, "first.il", b"one");
        let duplicate_plans = vec![
            DecryptionPlan {
                source: first.clone(),
                target_dir: temp.path().join("out"),
            },
            DecryptionPlan {
                source: first.clone(),
                target_dir: temp.path().join("out"),
            },
        ];
        assert!(matches!(
            DecryptionBatchGuard::new(&duplicate_plans),
            Err(IronlockError::OutputCollision(_))
        ));

        let alias = temp.path().join("alias.il");
        fs::hard_link(&first, &alias).unwrap();
        let alias_plans = vec![
            DecryptionPlan {
                source: first,
                target_dir: temp.path().join("out"),
            },
            DecryptionPlan {
                source: alias,
                target_dir: temp.path().join("out"),
            },
        ];
        assert!(matches!(
            DecryptionBatchGuard::new(&alias_plans),
            Err(IronlockError::OutputCollision(_))
        ));
    }

    #[test]
    fn batch_guard_rejects_output_that_is_a_pending_source() {
        let temp = TempDir::new().unwrap();
        let first = source(&temp, "first.il", b"one");
        let pending = source(&temp, "pending.il", b"two");
        let plans = vec![
            DecryptionPlan {
                source: first.clone(),
                target_dir: temp.path().to_path_buf(),
            },
            DecryptionPlan {
                source: pending.clone(),
                target_dir: temp.path().to_path_buf(),
            },
        ];
        let mut guard = DecryptionBatchGuard::new(&plans).unwrap();

        let result = guard.reserve(&first, &pending);
        assert!(matches!(result, Err(IronlockError::OutputCollision(_))));
        assert_eq!(fs::read(first).unwrap(), b"one");
        assert_eq!(fs::read(pending).unwrap(), b"two");
    }

    #[test]
    fn batch_guard_rejects_output_hard_linked_to_a_pending_source() {
        let temp = TempDir::new().unwrap();
        let first = source(&temp, "first.il", b"one");
        let pending = source(&temp, "pending.il", b"two");
        let output_alias = temp.path().join("output.txt");
        fs::hard_link(&pending, &output_alias).unwrap();
        let plans = vec![
            DecryptionPlan {
                source: first.clone(),
                target_dir: temp.path().to_path_buf(),
            },
            DecryptionPlan {
                source: pending,
                target_dir: temp.path().to_path_buf(),
            },
        ];
        let mut guard = DecryptionBatchGuard::new(&plans).unwrap();

        assert!(matches!(
            guard.reserve(&first, &output_alias),
            Err(IronlockError::OutputCollision(_))
        ));
        assert_eq!(fs::read(output_alias).unwrap(), b"two");
    }

    #[test]
    fn batch_guard_rejects_repeated_output_reservations() {
        let temp = TempDir::new().unwrap();
        let first = source(&temp, "first.il", b"one");
        let second = source(&temp, "second.il", b"two");
        let plans = vec![
            DecryptionPlan {
                source: first.clone(),
                target_dir: temp.path().join("out"),
            },
            DecryptionPlan {
                source: second.clone(),
                target_dir: temp.path().join("out"),
            },
        ];
        let mut guard = DecryptionBatchGuard::new(&plans).unwrap();
        let output = temp.path().join("out").join("same.txt");

        guard.reserve(&first, &output).unwrap();
        assert!(matches!(
            guard.reserve(&second, &output),
            Err(IronlockError::OutputCollision(_))
        ));
        assert!(!output.exists());
    }

    #[test]
    fn batch_guard_rejects_unregistered_sources() {
        let temp = TempDir::new().unwrap();
        let registered = source(&temp, "registered.il", b"one");
        let unregistered = source(&temp, "unregistered.il", b"two");
        let plans = vec![DecryptionPlan {
            source: registered,
            target_dir: temp.path().join("out"),
        }];
        let mut guard = DecryptionBatchGuard::new(&plans).unwrap();

        assert!(matches!(
            guard.reserve(&unregistered, &temp.path().join("out.txt")),
            Err(IronlockError::UnsafePath(_))
        ));
    }

    #[test]
    fn guarded_decryption_does_not_replace_a_pending_ciphertext_source() {
        let temp = TempDir::new().unwrap();
        let plaintext_dir = temp.path().join("plaintext");
        let batch_dir = temp.path().join("batch");
        fs::create_dir_all(&plaintext_dir).unwrap();
        fs::create_dir_all(&batch_dir).unwrap();
        let plaintext = plaintext_dir.join("pending.il");
        fs::write(&plaintext, b"decrypted content").unwrap();
        let first = batch_dir.join("first.il");
        encrypt_file_to_path(&plaintext, &first, b"password", false, false).unwrap();
        let pending = batch_dir.join("pending.il");
        fs::write(&pending, b"pending ciphertext bytes").unwrap();
        let plans = vec![
            DecryptionPlan {
                source: first.clone(),
                target_dir: batch_dir.clone(),
            },
            DecryptionPlan {
                source: pending.clone(),
                target_dir: batch_dir.clone(),
            },
        ];
        let mut guard = DecryptionBatchGuard::new(&plans).unwrap();

        let result =
            decrypt_file_to_path_guarded(&first, b"password", Some(&batch_dir), true, &mut guard);
        assert!(matches!(result, Err(IronlockError::OutputCollision(_))));
        assert_eq!(fs::read(&pending).unwrap(), b"pending ciphertext bytes");
        assert!(first.exists());
        assert!(!fs::read_dir(&batch_dir).unwrap().any(|entry| entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".ironlock-")));
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
