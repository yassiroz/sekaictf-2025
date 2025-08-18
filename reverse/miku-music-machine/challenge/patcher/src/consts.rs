use pelite::Pod;

// stolen from goblin :)
#[repr(C)]
#[derive(Debug, Clone)]
pub struct IMAGE_LOAD_CONFIG_DIRECTORY64 {
    pub Size: u32,
    pub TimeDateStamp: u32,
    pub MajorVersion: u16,
    pub MinorVersion: u16,
    pub GlobalFlagsClear: u32,
    pub GlobalFlagsSet: u32,
    pub CriticalSectionDefaultTimeout: u32,
    pub DeCommitFreeBlockThreshold: u64,
    pub DeCommitTotalFreeThreshold: u64,
    pub LockPrefixTable: u64,
    pub MaximumAllocationSize: u64,
    pub VirtualMemoryThreshold: u64,
    pub ProcessAffinityMask: u64,
    pub ProcessHeapFlags: u32,
    pub CSDVersion: u16,
    pub DependentLoadFlags: u16,
    pub EditList: u64,
    pub SecurityCookie: u64,
    pub SEHandlerTable: u64,
    pub SEHandlerCount: u64,
    pub GuardCFCheckFunctionPointer: u64,
    pub GuardCFDispatchFunctionPointer: u64,
    pub GuardCFFunctionTable: u64,
    pub GuardCFFunctionCount: u64,
    pub GuardFlags: u32,
    pub CodeIntegrity: IMAGE_LOAD_CONFIG_CODE_INTEGRITY,
    pub GuardAddressTakenIatEntryTable: u64,
    pub GuardAddressTakenIatEntryCount: u64,
    pub GuardLongJumpTargetTable: u64,
    pub GuardLongJumpTargetCount: u64,
    pub DynamicValueRelocTable: u64,
    pub CHPEMetadataPointer: u64,
    pub GuardRFFailureRoutine: u64,
    pub GuardRFFailureRoutineFunctionPointer: u64,
    pub DynamicValueRelocTableOffset: u32,
    pub DynamicValueRelocTableSection: u16,
    pub Reserved2: u16,
    pub GuardRFVerifyStackPointerFunctionPointer: u64,
    pub HotPatchTableOffset: u32,
    pub Reserved3: u32,
    pub EnclaveConfigurationPointer: u64,
    pub VolatileMetadataPointer: u64,
    pub GuardEHContinuationTable: u64,
    pub GuardEHContinuationCount: u64,
    pub GuardXFGCheckFunctionPointer: u64,
    pub GuardXFGDispatchFunctionPointer: u64,
    pub GuardXFGTableDispatchFunctionPointer: u64,
    pub CastGuardOsDeterminedFailureMode: u64,
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct IMAGE_LOAD_CONFIG_CODE_INTEGRITY {
    pub Flags: u16,
    pub Catalog: u16,
    pub CatalogOffset: u32,
    pub Reserved: u32,
}

pub const IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT: u32 = 1024u32;
pub const IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK: u32 = 4026531840u32;
pub const IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_SHIFT: u32 = 28u32;
pub const IMAGE_GUARD_XFG_ENABLED: u32 = 8388608u32;
pub const IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG: usize = 10usize;

unsafe impl Pod for IMAGE_LOAD_CONFIG_DIRECTORY64 {}
