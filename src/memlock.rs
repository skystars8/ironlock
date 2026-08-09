use std::ops::Deref;

use zeroize::Zeroize;

/// Attempts to keep a valid allocation resident in physical memory.
///
/// Locking is deliberately best-effort: operating-system quotas or policy can
/// deny the request, and encryption must remain available in that case. The
/// return value records whether a matching unlock should be attempted.
///
/// # Safety
///
/// `pointer..pointer + length` must remain a valid allocation until it is
/// unlocked. The operating-system calls do not inspect the allocation's bytes,
/// so they may be uninitialized (as with spare `String` capacity).
#[cfg(unix)]
unsafe fn try_lock_region(pointer: *const u8, length: usize) -> bool {
    // SAFETY: the caller guarantees this region is a live allocation for the
    // duration of the syscall and until a successful lock is paired with
    // unlock_region.
    length != 0 && unsafe { libc::mlock(pointer.cast::<libc::c_void>(), length) } == 0
}

#[cfg(unix)]
unsafe fn unlock_region(pointer: *const u8, length: usize) {
    if length != 0 {
        // SAFETY: the caller supplies the same still-live allocation that was
        // passed to a successful try_lock_region call.
        let _ = unsafe { libc::munlock(pointer.cast::<libc::c_void>(), length) };
    }
}

#[cfg(windows)]
#[link(name = "kernel32")]
extern "system" {
    fn VirtualLock(address: *mut core::ffi::c_void, size: usize) -> i32;
    fn VirtualUnlock(address: *mut core::ffi::c_void, size: usize) -> i32;
}

#[cfg(windows)]
unsafe fn try_lock_region(pointer: *const u8, length: usize) -> bool {
    // SAFETY: the caller keeps the allocation live and at a stable address
    // until a successful lock is paired with unlock_region.
    length != 0
        && unsafe { VirtualLock(pointer.cast_mut().cast::<core::ffi::c_void>(), length) } != 0
}

#[cfg(windows)]
unsafe fn unlock_region(pointer: *const u8, length: usize) {
    if length != 0 {
        // SAFETY: the caller supplies the same still-live allocation that was
        // passed to a successful VirtualLock call.
        let _ = unsafe { VirtualUnlock(pointer.cast_mut().cast::<core::ffi::c_void>(), length) };
    }
}

#[cfg(not(any(unix, windows)))]
unsafe fn try_lock_region(_pointer: *const u8, _length: usize) -> bool {
    false
}

#[cfg(not(any(unix, windows)))]
unsafe fn unlock_region(_pointer: *const u8, _length: usize) {}

/// Test helper for exercising the operating-system primitive on borrowed data.
#[cfg(test)]
pub fn mlock_slice(data: &[u8]) -> bool {
    // SAFETY: the borrowed slice is live for the call. Tests that observe a
    // successful lock keep it alive until munlock_slice is called.
    unsafe { try_lock_region(data.as_ptr(), data.len()) }
}

/// Test helper for a best-effort unlock of borrowed data.
#[cfg(test)]
pub fn munlock_slice(data: &[u8]) {
    // SAFETY: the borrowed slice is live for the syscall. An unmatched
    // best-effort unlock is safely rejected or treated as a no-op by the OS.
    unsafe { unlock_region(data.as_ptr(), data.len()) }
}

/// Fixed-size secret bytes stored at a stable heap address.
///
/// The allocation is created before locking and never reallocates. Locking is
/// best-effort; regardless of whether it succeeds, the bytes are zeroized on
/// drop. When locking succeeds, zeroization happens before the matching unlock.
pub struct LockedBytes<const N: usize> {
    bytes: Box<[u8; N]>,
    locked: bool,
}

impl<const N: usize> LockedBytes<N> {
    /// Allocates stable, zero-filled storage and then attempts to lock it.
    pub fn zeroed() -> Self {
        let bytes = Box::new([0u8; N]);
        // SAFETY: Box gives the allocation a stable address, and this type
        // retains it until Drop performs the matching unlock.
        let locked = unsafe { try_lock_region(bytes.as_ptr(), N) };
        Self { bytes, locked }
    }

    pub fn as_mut_bytes(&mut self) -> &mut [u8] {
        self.bytes.as_mut_slice()
    }

    fn clear_and_unlock(&mut self) {
        self.bytes.zeroize();
        if self.locked {
            // SAFETY: the Box has not moved or reallocated and is still alive;
            // locked records that try_lock_region succeeded for this region.
            unsafe { unlock_region(self.bytes.as_ptr(), N) };
            self.locked = false;
        }
    }
}

impl<const N: usize> Deref for LockedBytes<N> {
    type Target = [u8; N];

    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}

impl<const N: usize> Drop for LockedBytes<N> {
    fn drop(&mut self) {
        self.clear_and_unlock();
    }
}

/// Password text kept in its original, stable `String` allocation.
///
/// Construction does not copy or reallocate the password. The entire capacity
/// is locked when possible and zeroized before it is unlocked and deallocated.
/// Lock failures are non-fatal and never weaken the zeroization guarantee.
pub struct LockedString {
    value: String,
    locked: bool,
}

impl LockedString {
    pub fn new(value: String) -> Self {
        // SAFETY: this type takes ownership of the String without mutating its
        // capacity, so the allocation remains stable through Drop.
        let locked = unsafe { try_lock_region(value.as_ptr(), value.capacity()) };
        Self { value, locked }
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.value.as_bytes()
    }

    fn clear_and_unlock(&mut self) {
        let pointer = self.value.as_ptr();
        let capacity = self.value.capacity();

        // SAFETY: writing zeroes preserves UTF-8 validity. Zeroize the live
        // bytes and every spare byte so no password fragment remains anywhere
        // in the allocation currently owned by this String.
        let bytes = unsafe { self.value.as_mut_vec() };
        bytes.as_mut_slice().zeroize();
        bytes.spare_capacity_mut().zeroize();

        if self.locked {
            // SAFETY: the String allocation and capacity are unchanged and
            // remain live; locked records a successful lock of this region.
            unsafe { unlock_region(pointer, capacity) };
            self.locked = false;
        }
    }
}

impl Deref for LockedString {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

impl Drop for LockedString {
    fn drop(&mut self) {
        self.clear_and_unlock();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mlock_unlock_roundtrip() {
        let data = [1u8, 2, 3, 4, 5, 6, 7, 8];
        if mlock_slice(&data) {
            munlock_slice(&data);
        }
        // Should complete without panicking
    }

    #[test]
    fn test_mlock_empty_slice() {
        let data: [u8; 0] = [];
        assert!(!mlock_slice(&data));
        // Locking an empty slice should not panic
    }

    #[test]
    fn test_mlock_large_allocation() {
        let data = vec![0xABu8; 4096];
        if mlock_slice(&data) {
            munlock_slice(&data);
        }
        // Locking a large buffer should not panic
    }

    #[test]
    fn locking_does_not_modify_mutable_secret_bytes() {
        let mut data = vec![0x11, 0x22, 0x33, 0x44];
        let expected = data.clone();
        let locked = mlock_slice(&data);
        data[0] ^= 0xff;
        data[0] ^= 0xff;
        if locked {
            munlock_slice(&data);
        }
        assert_eq!(data, expected);
    }

    #[test]
    fn unaligned_subslice_roundtrip_does_not_panic_or_modify_data() {
        let data = [0x5au8; 37];
        let subslice = &data[1..36];
        if mlock_slice(subslice) {
            munlock_slice(subslice);
        }
        assert!(subslice.iter().all(|byte| *byte == 0x5a));
    }

    #[test]
    fn repeated_best_effort_locking_is_idempotent_for_callers() {
        let data = [0xa5u8; 64];
        let mut locked = false;
        for _ in 0..8 {
            locked |= mlock_slice(&data);
        }
        if locked {
            munlock_slice(&data);
        }
        assert_eq!(data, [0xa5; 64]);
    }

    #[test]
    fn locked_bytes_keep_a_stable_address_across_moves() {
        let mut secret = LockedBytes::<32>::zeroed();
        let expected = [0xA5; 32];
        secret.as_mut_bytes().copy_from_slice(&expected);
        let pointer = secret.as_ptr();

        let moved = secret;

        assert_eq!(moved.as_ptr(), pointer);
        assert_eq!(*moved, expected);
    }

    #[test]
    fn locked_bytes_clear_before_releasing_lock_state() {
        let mut secret = LockedBytes::<32>::zeroed();
        secret.as_mut_bytes().fill(0xA5);

        secret.clear_and_unlock();

        assert_eq!(*secret, [0; 32]);
        assert!(!secret.locked);
    }

    #[test]
    fn locked_string_adopts_allocation_without_copying_or_mutating() {
        let mut password = String::with_capacity(64);
        password.push_str("pässword 🔐");
        let pointer = password.as_ptr();
        let capacity = password.capacity();

        let locked = LockedString::new(password);
        let moved = locked;

        assert_eq!(moved.as_ptr(), pointer);
        assert_eq!(moved.value.capacity(), capacity);
        assert_eq!(&*moved, "pässword 🔐");
        assert_eq!(moved.as_bytes(), "pässword 🔐".as_bytes());
    }

    #[test]
    fn locked_string_clears_full_capacity_before_releasing_lock_state() {
        let mut password = String::with_capacity(64);
        password.push_str("top secret");
        let mut locked = LockedString::new(password);
        let pointer = locked.value.as_ptr();
        let capacity = locked.value.capacity();

        locked.clear_and_unlock();

        assert!(locked.as_bytes().iter().all(|byte| *byte == 0));
        assert!(!locked.locked);
        // SAFETY: clear_and_unlock initializes the String's entire allocation
        // with zeroes and retains the allocation until `locked` is dropped.
        let allocation = unsafe { std::slice::from_raw_parts(pointer, capacity) };
        assert!(allocation.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn empty_locked_values_are_supported() {
        let mut bytes = LockedBytes::<0>::zeroed();
        assert!(bytes.is_empty());
        bytes.clear_and_unlock();

        let mut text = LockedString::new(String::new());
        assert!(text.is_empty());
        text.clear_and_unlock();
        assert!(text.is_empty());
    }
}
