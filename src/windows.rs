extern crate fs2;
extern crate kernel32;
extern crate winapi;

use std::{io, mem, ptr};
use std::fs::File;
use std::os::raw::c_void;
use std::os::windows::io::AsRawHandle;

use self::fs2::FileExt;

pub struct MmapInner {
    file: Option<File>,
    ptr: *mut c_void,
    len: usize,
}

impl MmapInner {

    /// Creates a new `MmapInner`.
    ///
    /// This is a thin wrapper around the `CreateFileMappingW` and `MapViewOfFile` system calls.
    pub fn new(file: Option<&File>,
               protect: winapi::DWORD,
               desired_access: winapi::DWORD,
               offset: usize,
               len: usize) -> io::Result<MmapInner> {
        let alignment = offset % allocation_granularity();
        let aligned_offset = offset - alignment;
        let aligned_len = len + alignment;

        unsafe {
            let handle = kernel32::CreateFileMappingW(file.map_or(winapi::INVALID_HANDLE_VALUE,
                                                                  AsRawHandle::as_raw_handle),
                                                      ptr::null_mut(),
                                                      protect,
                                                      0,
                                                      0,
                                                      ptr::null());
            if handle == ptr::null_mut() {
                return Err(io::Error::last_os_error());
            }

            let ptr = kernel32::MapViewOfFile(handle,
                                              desired_access,
                                              (aligned_offset >> 16 >> 16) as winapi::DWORD,
                                              (aligned_offset & 0xffffffff) as winapi::DWORD,
                                              aligned_len as winapi::SIZE_T);
            kernel32::CloseHandle(handle);

            let file = try!(file.map_or(Ok(None), |file| file.duplicate().map(Some)));

            if ptr == ptr::null_mut() {
                Err(io::Error::last_os_error())
            } else {
                Ok(MmapInner {
                    file: file,
                    ptr: ptr.offset(alignment as isize),
                    len: len as usize,
                })
            }
        }
    }

    pub fn map(len: usize, file: &File, offset: usize) -> io::Result<MmapInner> {
        MmapInner::new(Some(file),
                       winapi::PAGE_READONLY,
                       winapi::FILE_MAP_READ,
                       offset, len)
    }

    pub fn map_exec(len: usize, file: &File, offset: usize) -> io::Result<MmapInner> {
        MmapInner::new(Some(file),
                       winapi::PAGE_READONLY,
                       winapi::FILE_MAP_READ | winapi::FILE_MAP_EXECUTE,
                       offset, len)
    }

    pub fn map_mut(len: usize, file: &File, offset: usize) -> io::Result<MmapInner> {
        MmapInner::new(Some(file),
                       winapi::PAGE_READWRITE,
                       winapi::FILE_MAP_WRITE,
                       offset, len)
    }

    pub fn map_copy(len: usize, file: &File, offset: usize) -> io::Result<MmapInner> {
        MmapInner::new(Some(file),
                       winapi::PAGE_READONLY,
                       winapi::FILE_MAP_COPY,
                       offset, len)
    }

    pub fn map_anon(len: usize, _stack: bool) -> io::Result<MmapInner> {
        // Create a mapping and view with maximum access permissions, then use `VirtualProtect`
        // to set the actual `Protection`. This way, we can set more permissive protection later
        // on.
        // Also see https://msdn.microsoft.com/en-us/library/windows/desktop/aa366537.aspx
        let mut mmap = try!(MmapInner::new(None,
                                           winapi::PAGE_EXECUTE_READWRITE,
                                           winapi::FILE_MAP_COPY,
                                           0, len));
        try!(mmap.make_mut());
        Ok(mmap)
    }

    pub fn flush(&self, offset: usize, len: usize) -> io::Result<()> {
        try!(self.flush_async(offset, len));
         if let Some(ref file) = self.file {
             try!(file.sync_data());
         }
         Ok(())
    }

    pub fn flush_async(&self, offset: usize, len: usize) -> io::Result<()> {
        let result = unsafe { kernel32::FlushViewOfFile(self.ptr.offset(offset as isize),
                                                        len as winapi::SIZE_T) };
        if result != 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn virtual_protect(&mut self, protect: winapi::DWORD) -> io::Result<()> {
        unsafe {
            let alignment = self.ptr as usize % allocation_granularity();
            let ptr = self.ptr.offset(- (alignment as isize));
            let aligned_len = self.len as winapi::SIZE_T + alignment as winapi::SIZE_T;

            let mut old = 0;
            let result = kernel32::VirtualProtect(ptr,
                                                  aligned_len,
                                                  protect,
                                                  &mut old);

            if result != 0 {
                Ok(())
            } else {
                Err(io::Error::last_os_error())
            }
        }
    }

    pub fn make_read_only(&mut self) -> io::Result<()> {
        self.virtual_protect(winapi::PAGE_READONLY)
    }

    pub fn make_exec(&mut self) -> io::Result<()> {
        self.virtual_protect(winapi::PAGE_EXECUTE_READ)
    }

    pub fn make_mut(&mut self) -> io::Result<()> {
        self.virtual_protect(winapi::PAGE_READWRITE)
    }

    pub fn ptr(&self) -> *const u8 {
        self.ptr as *const u8
    }

    pub fn mut_ptr(&mut self) -> *mut u8 {
        self.ptr as *mut u8
    }

    pub fn len(&self) -> usize {
        self.len
    }
}

impl Drop for MmapInner {
    fn drop(&mut self) {
        let alignment = self.ptr as usize % allocation_granularity();
        unsafe {
            let ptr = self.ptr.offset(- (alignment as isize));
            assert!(kernel32::UnmapViewOfFile(ptr) != 0,
                    "unable to unmap mmap: {}", io::Error::last_os_error());
        }
    }
}

unsafe impl Sync for MmapInner { }
unsafe impl Send for MmapInner { }

fn allocation_granularity() -> usize {
    unsafe {
        let mut info = mem::zeroed();
        kernel32::GetSystemInfo(&mut info);
        return info.dwAllocationGranularity as usize;
    }
}
