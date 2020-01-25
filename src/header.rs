use core::fmt;
use core::mem;

use crate::{P32, P64, ElfFile};
use zero::{read, Pod};


pub fn parse_header<'a>(input: &'a [u8]) -> Result<Header<'a>, &'static str> {
    let size_pt1 = mem::size_of::<HeaderPt1>();
    if input.len() < size_pt1 {
        return Err("File is shorter than the first ELF header part");
    }

    let header_1: &'a HeaderPt1 = read(&input[..size_pt1]);
    if header_1.magic != MAGIC {
        return Err("Did not find ELF magic number");
    }

    let header_2 = match header_1.class() {
        Class::ThirtyTwo => {
            let header_2: &'a HeaderPt2_<P32> =
            read(&input[size_pt1..size_pt1 + mem::size_of::<HeaderPt2_<P32>>()]);
            HeaderPt2::Header32(header_2)
        }
        Class::SixtyFour => {
            let header_2: &'a HeaderPt2_<P64> =
            read(&input[size_pt1..size_pt1 + mem::size_of::<HeaderPt2_<P64>>()]);
            HeaderPt2::Header64(header_2)
        }
        _ => return Err("Invalid ELF class"),
    };
    Ok(Header {
        pt1: header_1,
        pt2: header_2,
    })
}

pub const MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];

#[derive(Clone, Copy, Debug)]
pub struct Header<'a> {
    pub pt1: &'a HeaderPt1,
    pub pt2: HeaderPt2<'a>,
}

// TODO add Header::section_count, because if sh_count = 0, then the real count is in the first section.

impl<'a> fmt::Display for Header<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "ELF header:")?;
        writeln!(f, "    magic:            {:?}", self.pt1.magic)?;
        writeln!(f, "    class:            {:?}", self.pt1.class)?;
        writeln!(f, "    data:             {:?}", self.pt1.data)?;
        writeln!(f, "    version:          {:?}", self.pt1.version)?;
        writeln!(f, "    os abi:           {:?}", self.pt1.os_abi)?;
        writeln!(f, "    abi version:      {:?}", self.pt1.abi_version)?;
        writeln!(f, "    padding:          {:?}", self.pt1.padding)?;
        write!(f, "{}", self.pt2)?;
        Ok(())
    }
}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct HeaderPt1 {
    pub magic: [u8; 4],
    pub class: Class,
    pub data: Data,
    pub version: Version,
    pub os_abi: OsAbi,
    // Often also just padding.
    pub abi_version: u8,
    pub padding: [u8; 7],
}

unsafe impl Pod for HeaderPt1 {}

impl HeaderPt1 {
    pub fn class(&self) -> Class {
        self.class
    }

    pub fn data(&self) -> Data {
        self.data
    }

    pub fn version(&self) -> Version {
        self.version
    }

    pub fn os_abi(&self) -> OsAbi {
        self.os_abi
    }
}

#[derive(Clone, Copy, Debug)]
pub enum HeaderPt2<'a> {
    Header32(&'a HeaderPt2_<P32>),
    Header64(&'a HeaderPt2_<P64>),
}

macro_rules! getter {
    ($name: ident, $typ: ident) => {
        pub fn $name(&self) -> $typ {
            match *self {
                HeaderPt2::Header32(h) => h.$name as $typ,
                HeaderPt2::Header64(h) => h.$name as $typ,
            }
        }
    }
}

impl<'a> HeaderPt2<'a> {
    pub fn size(&self) -> usize {
        match *self {
            HeaderPt2::Header32(_) => mem::size_of::<HeaderPt2_<P32>>(),
            HeaderPt2::Header64(_) => mem::size_of::<HeaderPt2_<P64>>(),
        }
    }

    // TODO move to impl Header
    getter!(type_, Type);
    getter!(machine, Machine_);
    getter!(version, u32);
    getter!(header_size, u16);
    getter!(entry_point, u64);
    getter!(ph_offset, u64);
    getter!(sh_offset, u64);
    getter!(ph_entry_size, u16);
    getter!(ph_count, u16);
    getter!(sh_entry_size, u16);
    getter!(sh_count, u16);
    getter!(sh_str_index, u16);
}

impl<'a> fmt::Display for HeaderPt2<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            HeaderPt2::Header32(h) => write!(f, "{}", h),
            HeaderPt2::Header64(h) => write!(f, "{}", h),
        }
    }
}

#[derive(Debug)]
#[repr(C)]
pub struct HeaderPt2_<P> {
    pub type_: Type,
    pub machine: Machine_,
    pub version: u32,
    pub entry_point: P,
    pub ph_offset: P,
    pub sh_offset: P,
    pub flags: u32,
    pub header_size: u16,
    pub ph_entry_size: u16,
    pub ph_count: u16,
    pub sh_entry_size: u16,
    pub sh_count: u16,
    pub sh_str_index: u16,
}

unsafe impl<P> Pod for HeaderPt2_<P> {}

impl<P: fmt::Display> fmt::Display for HeaderPt2_<P> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "    type:             {:?}", self.type_)?;
        writeln!(f, "    machine:          {:?}", self.machine)?;
        writeln!(f, "    version:          {}", self.version)?;
        writeln!(f, "    entry_point:      {}", self.entry_point)?;
        writeln!(f, "    ph_offset:        {}", self.ph_offset)?;
        writeln!(f, "    sh_offset:        {}", self.sh_offset)?;
        writeln!(f, "    flags:            {}", self.flags)?;
        writeln!(f, "    header_size:      {}", self.header_size)?;
        writeln!(f, "    ph_entry_size:    {}", self.ph_entry_size)?;
        writeln!(f, "    ph_count:         {}", self.ph_count)?;
        writeln!(f, "    sh_entry_size:    {}", self.sh_entry_size)?;
        writeln!(f, "    sh_count:         {}", self.sh_count)?;
        writeln!(f, "    sh_str_index:     {}", self.sh_str_index)?;
        Ok(())
    }
}
macro_rules! tagged {
    (
        $(#[$struct_meta:meta])*
        pub $name:ident($orig:ty) [
            $($fname:ident: $val:expr),*
        ]
    ) => {
        $(#[$struct_meta])*
        #[derive(PartialEq, Eq)]
        pub struct $name(pub $orig);

        impl $name {
            $(
                #[allow(non_upper_case_globals)]
                pub const $fname: Self = Self($val);
            )*

            fn tag_str(&self) -> Option<&'static str> {
                match *self {
                    $(
                        Self::$fname => Some(stringify!($fname)),
                    )*
                    _ => None
                }
            }
        }
    };
}

tagged! {
    #[derive(Clone, Copy)]
    pub Class(u8) [
        None: 0,
        ThirtyTwo: 1,
        SixtyFour: 2
    ]
}
impl Class {
    pub fn is_none(&self) -> bool {
        *self == Self::None
    }
}
impl fmt::Debug for Class {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.tag_str() {
            Some(s) => write!(f, "{}", s),
            None => write!(f, "Other({})", self.0)
        }
    }
}

tagged! {
    #[derive(Clone, Copy)]
    pub Data(u8) [
        None: 0,
        LittleEndian: 1,
        BigEndian: 2
    ]
}
impl Data {
    pub fn is_none(&self) -> bool {
        *self == Self::None
    }
}
impl fmt::Debug for Data {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.tag_str() {
            Some(s) => write!(f, "{}", s),
            None => write!(f, "Other({})", self.0)
        }
    }
}

tagged! {
    #[derive(Clone, Copy)]
    pub Version(u8) [
        None: 0,
        Current: 1
    ]
}
impl Version {
    pub fn is_none(&self) -> bool {
        *self == Self::None
    }
}
impl fmt::Debug for Version {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.tag_str() {
            Some(s) => write!(f, "{}", s),
            None => write!(f, "Other({})", self.0)
        }
    }
}

tagged! {
    #[derive(Clone, Copy)]
    pub OsAbi(u8) [
        SystemV: 0x00,
        HpUx: 0x01,
        NetBSD: 0x02,
        Linux: 0x03,
        GnuHurd: 0x04,
        Solaris: 0x06,
        Aix: 0x07,
        Irix: 0x08,
        FreeBSD: 0x09,
        Tru64: 0x0A,
        NovellModesto: 0x0B,
        OpenBSD: 0x0C,
        OpenVMS: 0x0D,
        NonStopKernel: 0x0E,
        AROS: 0x0F,
        FenixOS: 0x10,
        CloudABI: 0x11
    ]
}

impl fmt::Debug for OsAbi {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.tag_str() {
            Some(s) => write!(f, "{}", s),
            None => write!(f, "Other({})", self.0)
        }
    }
}

tagged! {
    #[derive(Clone, Copy)]
    pub Type(u16) [
        None: 0,
        Relocatable: 1,
        Executable: 2,
        SharedObject: 3,
        Core: 4
    ]
}

impl fmt::Debug for Type {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.tag_str() {
            Some(s) => write!(f, "{}", s),
            None => write!(f, "ProcessorSpecific({})", self.0)
        }
    }
}

#[derive(Clone, Copy)]
pub struct Machine_(u16);

impl Machine_ {
    pub fn as_machine(self) -> Machine {
        match self.0 {
            0x00 => Machine::None,
            0x02 => Machine::Sparc,
            0x03 => Machine::X86,
            0x08 => Machine::Mips,
            0x14 => Machine::PowerPC,
            0x28 => Machine::Arm,
            0x2A => Machine::SuperH,
            0x32 => Machine::Ia64,
            0x3E => Machine::X86_64,
            0xB7 => Machine::AArch64,
            0xF7 => Machine::BPF,
            other => Machine::Other(other),
        }
    }
}

impl fmt::Debug for Machine_ {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.as_machine().fmt(f)
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Machine {
    None,
    Sparc,
    X86,
    Mips,
    PowerPC,
    Arm,
    SuperH,
    Ia64,
    X86_64,
    AArch64,
    BPF,
    Other(u16), // FIXME there are many, many more of these
}

// TODO any more constants that need to go in here?

pub fn sanity_check(file: &ElfFile) -> Result<(), &'static str> {
    check!(mem::size_of::<HeaderPt1>() == 16);
    check!(file.header.pt1.magic == MAGIC, "bad magic number");
    let pt2 = &file.header.pt2;
    check!(mem::size_of::<HeaderPt1>() + pt2.size() == pt2.header_size() as usize,
           "header_size does not match size of header");
    match (&file.header.pt1.class(), &file.header.pt2) {
        (&Class::None, _) => return Err("No class"),
        (&Class::ThirtyTwo, &HeaderPt2::Header32(_)) |
        (&Class::SixtyFour, &HeaderPt2::Header64(_)) => {}
        _ => return Err("Mismatch between specified and actual class"),
    }
    check!(!file.header.pt1.version.is_none(), "no version");
    check!(!file.header.pt1.data.is_none(), "no data format");

    check!(pt2.ph_offset() + (pt2.ph_entry_size() as u64) * (pt2.ph_count() as u64) <=
           file.input.len() as u64,
           "program header table out of range");
    check!(pt2.sh_offset() + (pt2.sh_entry_size() as u64) * (pt2.sh_count() as u64) <=
           file.input.len() as u64,
           "section header table out of range");

    // TODO check that SectionHeader_ is the same size as sh_entry_size, depending on class

    Ok(())
}
