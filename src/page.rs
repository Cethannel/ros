use core::{mem::size_of, ptr::null_mut};

use crate::{print, println};

extern "C" {
    static HEAP_START: usize;
    static HEAP_SIZE: usize;
}

static mut ALLOC_START: usize = 0;
const PAGE_ORDER: usize = 12;
pub const PAGE_SIZE: usize = 1 << 12;

#[repr(u8)]
pub enum PageBits {
    Empty = 0,
    Taken = 1 << 0,
    Last = 1 << 1,
}

impl PageBits {
    // We convert PageBits to a u8 a lot, so this is
    // for convenience.
    pub fn val(self) -> u8 {
        self as u8
    }
}

struct Page {
    flags: u8,
}

impl Page {
    pub fn is_taken(&self) -> bool {
        (self.flags & PageBits::Taken.val()) != 0
    }

    pub fn is_free(&self) -> bool {
        !self.is_taken()
    }

    pub fn is_last(&self) -> bool {
        (self.flags & PageBits::Last.val()) != 0
    }

    pub fn set_flag(&mut self, flag: PageBits) {
        self.flags |= flag.val();
    }

    pub fn clear_flag(&mut self, flag: PageBits) {
        self.flags &= !flag.val();
    }

    pub fn set_taken(&mut self) {
        self.set_flag(PageBits::Taken);
    }

    pub fn clear(&mut self) {
        self.flags = PageBits::Empty.val();
    }
}

pub fn alloc(pages: usize) -> *mut u8 {
    // We have to find a contiguous allocation of pages
    assert!(pages > 0);
    unsafe {
        // We create a Page structure for each page on the heap. We
        // actually might have more since HEAP_SIZE moves and so does
        // the size of our structure, but we'll only waste a few bytes.
        let num_pages = HEAP_SIZE / PAGE_SIZE;
        let ptr = HEAP_START as *mut Page;
        for i in 0..num_pages - pages {
            let mut found = false;
            // Check to see if this Page is free. If so, we have our
            // first candidate memory address.
            if (*ptr.add(i)).is_free() {
                // It was FREE! Yay!
                found = true;
                for j in i..i + pages {
                    // Now check to see if we have a
                    // contiguous allocation for all of the
                    // request pages. If not, we should
                    // check somewhere else.
                    if (*ptr.add(j)).is_taken() {
                        found = false;
                        break;
                    }
                }
            }
            // We've checked to see if there are enough contiguous
            // pages to form what we need. If we couldn't, found
            // will be false, otherwise it will be true, which means
            // we've found valid memory we can allocate.
            if found {
                for k in i..i + pages - 1 {
                    (*ptr.add(k)).set_flag(PageBits::Taken);
                }
                // The marker for the last page is
                // PageBits::Last This lets us know when we've
                // hit the end of this particular allocation.
                (*ptr.add(i + pages - 1)).set_flag(PageBits::Taken);
                (*ptr.add(i + pages - 1)).set_flag(PageBits::Last);
                // The Page structures themselves aren't the
                // useful memory. Instead, there is 1 Page
                // structure per 4096 bytes starting at
                // ALLOC_START.
                return (ALLOC_START + PAGE_SIZE * i) as *mut u8;
            }
        }
    }

    // If we get here, that means that no contiguous allocation was
    // found.
    null_mut()
}

pub fn dealloc(ptr: *mut u8) {
    // Make sure we don't try to free a null pointer.
    assert!(!ptr.is_null());
    unsafe {
        let addr = HEAP_START + (ptr as usize - ALLOC_START) / PAGE_SIZE;
        // Make sure that the address makes sense. The address we
        // calculate here is the page structure, not the HEAP address!
        assert!(addr >= HEAP_START && addr < HEAP_START + HEAP_SIZE);
        let mut p = addr as *mut Page;
        // Keep clearing pages until we hit the last page.
        while (*p).is_taken() && !(*p).is_last() {
            (*p).clear();
            p = p.add(1);
        }
        // If the following assertion fails, it is most likely
        // caused by a double-free.
        assert!(
            (*p).is_last() == true,
            "Possible double-free detected! (Not taken found \
					before last)"
        );
        // If we get here, we've taken care of all previous pages and
        // we are on the last page.
        (*p).clear();
    }
}

pub fn zalloc(pages: usize) -> *mut u8 {
    // Allocate and zero a page.
    // First, let's get the allocation
    let ret = alloc(pages);
    if !ret.is_null() {
        let size = (PAGE_SIZE * pages) / 8;
        let big_ptr = ret as *mut u64;
        for i in 0..size {
            // We use big_ptr so that we can force an
            // sd (store doubleword) instruction rather than
            // the sb. This means 8x fewer stores than before.
            // Typically we have to be concerned about remaining
            // bytes, but fortunately 4096 % 8 = 0, so we
            // won't have any remaining bytes.
            unsafe {
                (*big_ptr.add(i)) = 0;
            }
        }
    }

    ret
}

pub fn print_page_allocations() {
    unsafe {
        println!("Page size: {} bytes", PAGE_SIZE);
        println!("Heap size: {} bytes", HEAP_SIZE);
        let num_pages = HEAP_SIZE / PAGE_SIZE;
        let mut beg = HEAP_START as *const Page;
        let end = beg.add(num_pages);
        let alloc_beg = ALLOC_START;
        let alloc_end = ALLOC_START + num_pages * PAGE_SIZE;
        println!();
        println!(
            "PAGE ALLOCATION TABLE\nMETA: {:p} -> {:p}\nPHYS: \
					0x{:x} -> 0x{:x}",
            beg, end, alloc_beg, alloc_end
        );
        println!("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
        let mut num = 0;
        while beg < end {
            if (*beg).is_taken() {
                let start = beg as usize;
                let memaddr = ALLOC_START + (start - HEAP_START) * PAGE_SIZE;
                print!("0x{:x} => ", memaddr);
                loop {
                    num += 1;
                    if (*beg).is_last() {
                        let end = beg as usize;
                        let memaddr = ALLOC_START + (end - HEAP_START) * PAGE_SIZE + PAGE_SIZE - 1;
                        print!("0x{:x}: {:>3} page(s)", memaddr, (end - start + 1));
                        println!(".");
                        break;
                    }
                    beg = beg.add(1);
                }
            }
            beg = beg.add(1);
        }
        println!("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
        println!(
            "Allocated: {:>6} pages ({:>10} bytes).",
            num,
            num * PAGE_SIZE
        );
        println!(
            "Free     : {:>6} pages ({:>10} bytes).",
            num_pages - num,
            (num_pages - num) * PAGE_SIZE
        );
        println!();
    }
}

pub fn init() {
    unsafe {
        let num_pages = HEAP_SIZE / PAGE_SIZE;
        let ptr = HEAP_START as *mut Page;
        // Clear all pages to make sure that they aren't accidentally
        // taken
        for i in 0..num_pages {
            (*ptr.add(i)).clear();
        }
        // Determine where the actual useful memory starts. This will be
        // after all Page structures. We also must align the ALLOC_START
        // to a page-boundary (PAGE_SIZE = 4096). ALLOC_START =
        // (HEAP_START + num_pages * size_of::<Page>() + PAGE_SIZE - 1)
        // & !(PAGE_SIZE - 1);
        ALLOC_START = align_val(HEAP_START + num_pages * size_of::<Page>(), PAGE_ORDER);
    }
}

pub const fn align_val(val: usize, order: usize) -> usize {
    let o = (1usize << order) - 1;
    (val + o) & !o
}

pub struct Table {
    pub entries: [Entry; 512],
}

impl Table {
    pub const fn len() -> usize {
        512
    }
}

pub struct Entry {
    pub entry: i64,
}

#[repr(i64)]
pub enum EntryBits {
    Valid = 1 << 0,
}

impl EntryBits {
    pub fn val(self) -> i64 {
        self as i64
    }
}

impl Entry {
    pub fn is_valid(&self) -> bool {
        self.get_entry() & EntryBits::Valid.val() != 0
    }

    pub fn is_invalid(&self) -> bool {
        !self.is_valid()
    }

    pub fn is_leaf(&self) -> bool {
        self.get_entry() & 0xe != 0
    }

    pub fn is_table(&self) -> bool {
        !self.is_leaf()
    }

    pub fn set_entry(&mut self, entry: i64) {
        self.entry = entry;
    }

    pub fn get_entry(&self) -> i64 {
        self.entry
    }

    pub fn is_branch(&self) -> bool {
        self.is_table()
    }
}

pub fn map(root: &mut Table, vaddr: usize, paddr: usize, bits: i64, level: usize) {
    assert!(bits & 0xe != 0);

    let vpn = [
        // VPN[0] = vaddr[20:12]
        (vaddr >> 12) & 0x1ff,
        // VPN[1] = vaddr[29:21]
        (vaddr >> 21) & 0x1ff,
        // VPN[2] = vaddr[38:30]
        (vaddr >> 30) & 0x1ff,
    ];

    let ppn = [
        // PPN[0] = paddr[20:12]
        (paddr >> 12) & 0x1ff,
        // PPN[1] = paddr[29:21]
        (paddr >> 21) & 0x1ff,
        // PPN[2] = paddr[55:30]
        (paddr >> 30) & 0x3ff_ffff,
    ];

    let mut v = &mut root.entries[vpn[2]];

    for i in (level..2).rev() {
        if !v.is_valid() {
            let page = zalloc(1);
            v.set_entry((page as i64 >> 2) | EntryBits::Valid.val())
        }
        let entry = ((v.get_entry() & !0x3ff) << 2) as *mut Entry;
        v = unsafe { &mut *entry.add(vpn[i]) };
    }

    let entry = (ppn[2] << 28) as i64
        | (ppn[1] << 19) as i64
        | (ppn[0] << 10) as i64
        | bits
        | EntryBits::Valid.val();

    v.set_entry(entry);
}

pub fn unmap(root: &mut Table) {
    for lv2 in 0..Table::len() {
        let ref entry_lv2 = root.entries[lv2];
        if entry_lv2.is_valid() && entry_lv2.is_branch() {
            let memaddr_lv1 = (entry_lv2.get_entry() & !0x3ff) << 2;
            let table_lv1 = unsafe { (memaddr_lv1 as *mut Table).as_mut().unwrap() };

            for lv1 in 0..Table::len() {
                let ref entry_lv1 = table_lv1.entries[lv1];
                if entry_lv1.is_valid() && entry_lv1.is_branch() {
                    let memarrd_lv0 = (entry_lv1.get_entry() & !0x3ff) << 2;
                    dealloc(memarrd_lv0 as *mut u8);
                }
            }
            dealloc(memaddr_lv1 as *mut u8);
        }
    }
}

pub fn virt_to_phys(root: &mut Table, vaddr: usize) -> Option<usize> {
    let vpn = [
        // VPN[0] = vaddr[20:12]
        (vaddr >> 12) & 0x1ff,
        // VPN[1] = vaddr[29:21]
        (vaddr >> 21) & 0x1ff,
        // VPN[2] = vaddr[38:30]
        (vaddr >> 30) & 0x1ff,
    ];

    let mut v = &root.entries[vpn[2]];
    for i in (0..2).rev() {
        if v.is_valid() {
            break;
        }
        if v.is_leaf() {
            let off_mask = (1 << (12 + 9 * i)) - 1;
            let vaddr_pgoff = vaddr & off_mask;
            let addr = ((v.get_entry() << 2) as usize) | !off_mask;
            return Some(addr | vaddr_pgoff);
        }

        let entry = ((v.get_entry() & !0x3ff) << 2) as *mut Entry;

        v = unsafe { &mut *entry.add(vpn[i]) };
    }

    None
}

