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
    getter!(machine, Machine);
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
    pub machine: Machine,
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
            $($(#[$field_meta:meta])* $fname:ident: $val:expr),*
        ]
    ) => {
        $(#[$struct_meta])*
        #[derive(PartialEq, Eq)]
        pub struct $name(pub $orig);

        impl $name {
            $(
                #[allow(non_upper_case_globals)]
                $(#[$field_meta])*
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

tagged! {
#[derive(Clone, Copy)]
    pub Machine(u16) [
        ///  No machine
        None: 0,
        ///  AT&T WE 32100
        M32: 1,
        ///  SUN SPARC
        SPArc: 2,
        ///  Intel 80386
        x386: 3,
        ///  Motorola m68k family
        x68K: 4,
        ///  Motorola m88k family
        x88K: 5,
        ///  Intel MCU
        IAMCU: 6,
        ///  Intel 80860
        x860: 7,
        ///  MIPS R3000 big-endian
        MIPS: 8,
        ///  IBM System/370
        System370: 9,
        ///  MIPS R3000 little-endian
        MIPS_R3000: 10,
        /* reserved 11-14 */
        ///  HPPA
        PARISC: 15,
        /* reserved 16 */
        ///  Fujitsu VPP500
        VPP500: 17,
        ///  Sun's "v8plus"
        SPArc32Plus: 18,
        ///  Intel 80960
        x960: 19,
        ///  PowerPC
        PowerPC: 20,
        ///  PowerPC 64-bit
        PowerPC64: 21,
        ///  IBM S390
        S390: 22,
        ///  IBM SPU/SPC
        SPU: 23,
        /* reserved 24-35 */
        ///  NEC V800 series
        V800: 36,
        ///  Fujitsu FR20
        FR20: 37,
        ///  TRW RH-32
        RH32: 38,
        ///  Motorola RCE
        RCE: 39,
        ///  ARM
        ARM: 40,
        ///  Digital Alpha
        FAKE_ALPHA: 41,
        ///  Hitachi SH
        SH: 42,
        ///  SPARC v9 64-bit
        SPArcV9: 43,
        ///  Siemens Tricore
        Tricore: 44,
        ///  Argonaut RISC Core
        ARC: 45,
        ///  Hitachi H8/300
        H8_300: 46,
        ///  Hitachi H8/300H
        H8_300H: 47,
        ///  Hitachi H8S
        H8S: 48,
        ///  Hitachi H8/500
        H8_500: 49,
        ///  Intel Merced
        IA_64: 50,
        ///  Stanford MIPS-X
        MIPS_X: 51,
        ///  Motorola Coldfire
        Coldfire: 52,
        ///  Motorola M68HC12
        x68HC12: 53,
        ///  Fujitsu MMA Multimedia Accelerator
        MMA: 54,
        ///  Siemens PCP
        PCP: 55,
        ///  Sony nCPU embeeded RISC
        nCPU: 56,
        ///  Denso NDR1 microprocessor
        NDR1: 57,
        /// Motorola StarCore processor
        StarCore: 58,
        ///  Toyota ME16 processor
        ME16: 59,
        ///  STMicroelectronic ST100 processor
        ST100: 60,
        ///  Advanced Logic Corp. Tinyj emb.fam
        Tinyj: 61,
        ///  AMD x86-64 architecture
        x86_64: 62,
        ///  Sony DSP Processor
        PDSP: 63,
        ///  Digital PDP-10
        PDP10: 64,
        ///  Digital PDP-11
        PDP11: 65,
        ///  Siemens FX66 microcontroller
        FX66: 66,
        ///  STMicroelectronics ST9+ 8/16 mc
        ST9Plus: 67,
        ///  STmicroelectronics ST7 8 bit mc
        ST7: 68,
        ///  Motorola MC68HC16 microcontroller
        x68HC16: 69,
        ///  Motorola MC68HC11 microcontroller
        x68HC11: 70,
        ///  Motorola MC68HC08 microcontroller
        x68HC08: 71,
        ///  Motorola MC68HC05 microcontroller
        x68HC05: 72,
        ///  Silicon Graphics SVx
        SVx: 73,
        ///  STMicroelectronics ST19 8 bit mc
        ST19: 74,
        ///  Digital VAX
        VAX: 75,
        ///  Axis Communications 32-bit emb.proc
        CRIS: 76,
        ///  Infineon Technologies 32-bit emb.proc
        Javelin: 77,
        ///  Element14 64-bit DSP Processor
        FirePath: 78,
        ///  LSI Logic 16-bit DSP Processor
        ZSP: 79,
        ///  Donald Knuth's educational 64-bit proc
        MMIX: 80,
        ///  Harvard University machine-independent object files
        HUAny: 81,
        ///  SiTera Prism
        Prism: 82,
        ///  Atmel AVR 8-bit microcontroller
        AVR: 83,
        ///  Fujitsu FR30
        FR30: 84,
        ///  Mitsubishi D10V
        D10V: 85,
        ///  Mitsubishi D30V
        D30V: 86,
        ///  NEC v850
        V850: 87,
        ///  Mitsubishi M32R
        M32R: 88,
        ///  Matsushita MN10300
        MN10300: 89,
        ///  Matsushita MN10200
        MN10200: 90,
        ///  picoJava
        picoJava: 91,
        ///  OpenRISC 32-bit embedded processor
        OpenRISC: 92,
        ///  ARC International ARCompact
        ARCompact: 93,
        ///  Tensilica Xtensa Architecture
        Xtensa: 94,
        ///  Alphamosaic VideoCore
        VideoCore: 95,
        ///  Thompson Multimedia General Purpose Proc
        TMM_GPP: 96,
        ///  National Semi. 32000
        NS32K: 97,
        ///  Tenor Network TPC
        TPC: 98,
        ///  Trebia SNP 1000
        SNP1K: 99,
        ///  STMicroelectronics ST200
        ST200: 100,
        ///  Ubicom IP2xxx
        IP2K: 101,
        ///  MAX processor
        MAX: 102,
        ///  National Semi. CompactRISC
        CompactRISC: 103,
        ///  Fujitsu F2MC16
        F2MC16: 104,
        ///  Texas Instruments msp430
        msp430: 105,
        ///  Analog Devices Blackfin DSP
        Blackfin: 106,
        ///  Seiko Epson S1C33 family
        SE_C33: 107,
        ///  Sharp embedded microprocessor
        SEP: 108,
        ///  Arca RISC
        Arca: 109,
        ///  PKU-Unity & MPRC Peking Uni. mc series
        Unicore: 110,
        ///  eXcess configurable cpu
        eXcess: 111,
        ///  Icera Semi. Deep Execution Processor
        DXP: 112,
        ///  Altera Nios II
        AlteraNios2: 113,
        ///  National Semi. CompactRISC CRX
        CRX: 114,
        ///  Motorola XGATE
        XGATE: 115,
        ///  Infineon C16x/XC16x
        C166: 116,
        ///  Renesas M16C
        M16C: 117,
        ///  Microchip Technology dsPIC30F
        DSPIC30F: 118,
        ///  Freescale Communication Engine RISC
        CE: 119,
        ///  Renesas M32C
        M32C: 120,
        /* reserved 121-130 */
        ///  Altium TSK3000
        TSK3000: 131,
        ///  Freescale RS08
        RS08: 132,
        ///  Analog Devices SHARC family
        SHARC: 133,
        ///  Cyan Technology eCOG2
        eCOG2: 134,
        ///  Sunplus S+core7 RISC
        S_core7: 135,
        ///  New Japan Radio (NJR) 24-bit DSP
        DSP24: 136,
        ///  Broadcom VideoCore III
        VideoCore3: 137,
        ///  RISC for Lattice FPGA
        LatticeMICO32: 138,
        ///  Seiko Epson C17
        SE_C17: 139,
        ///  Texas Instruments TMS320C6000 DSP
        TI_C6000: 140,
        ///  Texas Instruments TMS320C2000 DSP
        TI_C2000: 141,
        ///  Texas Instruments TMS320C55x DSP
        TI_C5500: 142,
        ///  Texas Instruments App. Specific RISC
        TI_ARP32: 143,
        ///  Texas Instruments Prog. Realtime Unit
        TI_PRU: 144,
        /* reserved 145-159 */
        ///  STMicroelectronics 64bit VLIW DSP
        MMDSP_Plus: 160,
        ///  Cypress M8C
        CypressM8C: 161,
        ///  Renesas R32C
        R32C: 162,
        ///  NXP Semi. TriMedia
        TriMedia: 163,
        ///  QUALCOMM DSP6
        QDSP6: 164,
        ///  Intel 8051 and variants
        x8051: 165,
        ///  STMicroelectronics STxP7x
        STXP7X: 166,
        ///  Andes Tech. compact code emb. RISC
        NDS32: 167,
        ///  Cyan Technology eCOG1X
        eCOG1X: 168,
        ///  Dallas Semi. MAXQ30 mc
        MAXQ30: 169,
        ///  New Japan Radio (NJR) 16-bit DSP
        XIMO16: 170,
        ///  M2000 Reconfigurable RISC
        MANIK: 171,
        ///  Cray NV2 vector architecture
        CrayNV2: 172,
        ///  Renesas RX
        RX: 173,
        ///  Imagination Tech. META
        METAG: 174,
        ///  MCST Elbrus
        MCST_Elbrus: 175,
        ///  Cyan Technology eCOG16
        eCOG16: 176,
        ///  National Semi. CompactRISC CR16
        CR16: 177,
        ///  Freescale Extended Time Processing Unit
        ETPU: 178,
        ///  Infineon Tech. SLE9X
        SLE9X: 179,
        ///  Intel L10M
        L10M: 180,
        ///  Intel K10M
        K10M: 181,
        /* reserved 182 */
        ///  ARM AARCH64
        AArch64: 183,
        /* reserved 184 */
        ///  Amtel 32-bit microprocessor
        AVR32: 185,
        ///  STMicroelectronics STM8
        STM8: 186,
        ///  Tileta TILE64
        TILE64: 187,
        ///  Tilera TILEPro
        TILEPro: 188,
        ///  Xilinx MicroBlaze
        MicroBlaze: 189,
        ///  NVIDIA CUDA
        CUDA: 190,
        ///  Tilera TILE-Gx
        TILEGX: 191,
        ///  CloudShield
        CloudShield: 192,
        ///  KIPO-KAIST Core-A 1st gen.
        CoreA_1st: 193,
        ///  KIPO-KAIST Core-A 2nd gen.
        CoreA_2nd: 194,
        ///  Synopsys ARCompact V2
        ARCompact2: 195,
        ///  Open8 RISC
        Open8: 196,
        ///  Renesas RL78
        RL78: 197,
        ///  Broadcom VideoCore V
        VideoCore5: 198,
        ///  Renesas 78KOR
        x78KOR: 199,
        ///  Freescale 56800EX DSC
        // 56800EX: 200,
        ///  Beyond BA1
        BA1: 201,
        ///  Beyond BA2
        BA2: 202,
        ///  XMOS xCORE
        xCORE: 203,
        ///  Microchip 8-bit PIC(r)
        MCHP_PIC: 204,
        /* reserved 205-209 */
        ///  KM211 KM32
        KM32: 210,
        ///  KM211 KMX32
        KMX32: 211,
        ///  KM211 KMX16
        EMX16: 212,
        ///  KM211 KMX8
        EMX8: 213,
        ///  KM211 KVARC
        KVARC: 214,
        ///  Paneve CDP
        CDP: 215,
        ///  Cognitive Smart Memory Processor
        COGE: 216,
        ///  Bluechip CoolEngine
        CoolEngine: 217,
        ///  Nanoradio Optimized RISC
        NORC: 218,
        ///  CSR Kalimba
        CSR_Kalimba: 219,
        ///  Zilog Z80
        Z80: 220,
        ///  Controls and Data Services VISIUMcore
        VISIUM: 221,
        ///  FTDI Chip FT32
        FT32: 222,
        ///  Moxie processor
        Moxie: 223,
        ///  AMD GPU
        AMDGPU: 224,
        /* reserved 225-242 */
        ///  RISC-V
        RISCV: 243,

        ///  Linux BPF -- in-kernel virtual machine
        BPF: 247,
        ///  C-SKY
        CSKY: 252
    ]
}

impl fmt::Debug for Machine {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.tag_str() {
            Some(s) => write!(f, "{}", s),
            None => write!(f, "Other({})", self.0),
        }
    }
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
