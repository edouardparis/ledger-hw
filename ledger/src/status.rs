use std::convert::From;

#[derive(Debug, PartialEq)]
pub enum Status {
    AccessConditionNotFulfilled,
    AlgorithmNotSupported,
    CLANotSupported,
    CodeBlocked,
    CodeNotInitialized,
    CommandIncompatibleFileStructure,
    ConditionsOfUseNotSatisfied,
    ContradictionInvalidation,
    ContradictionSecretCodeStatus,
    FileAlreadyExists,
    FileNotFound,
    GPAuthFailed,
    Halted,
    InconsistentFile,
    IncorrectData,
    IncorrectLength,
    IncorrectP1P2,
    INSNotSupported,
    InvalidKCV,
    InvalidOffset,
    Licensing,
    MaxValueReached,
    MemoryProblem,
    NotEnoughMemorySpace,
    NoEFSelected,
    OK,
    PinRemainingAttempts,
    ReferencedDataNotFound,
    SecurityStatusNotSatisfied,
    TechnicalProblem,
    Unknown(u16),
}

impl From<u16> for Status {
    fn from(s: u16) -> Status {
        match s {
            ACCESS_CONDITION_NOT_FULFILLED => Status::AccessConditionNotFulfilled,
            ALGORITHM_NOT_SUPPORTED => Status::AlgorithmNotSupported,
            CLA_NOT_SUPPORTED => Status::CLANotSupported,
            CODE_BLOCKED => Status::CodeBlocked,
            CODE_NOT_INITIALIZED => Status::CodeNotInitialized,
            COMMAND_INCOMPATIBLE_FILE_STRUCTURE => Status::CommandIncompatibleFileStructure,
            CONDITIONS_OF_USE_NOT_SATISFIED => Status::ConditionsOfUseNotSatisfied,
            CONTRADICTION_INVALIDATION => Status::ContradictionInvalidation,
            CONTRADICTION_SECRET_CODE_STATUS => Status::ContradictionSecretCodeStatus,
            FILE_ALREADY_EXISTS => Status::FileAlreadyExists,
            FILE_NOT_FOUND => Status::FileNotFound,
            GP_AUTH_FAILED => Status::GPAuthFailed,
            HALTED => Status::Halted,
            INCONSISTENT_FILE => Status::InconsistentFile,
            INCORRECT_DATA => Status::IncorrectData,
            INCORRECT_LENGTH => Status::IncorrectLength,
            INCORRECT_P1_P2 => Status::IncorrectP1P2,
            INS_NOT_SUPPORTED => Status::INSNotSupported,
            INVALID_KCV => Status::InvalidKCV,
            INVALID_OFFSET => Status::InvalidOffset,
            LICENSING => Status::Licensing,
            MAX_VALUE_REACHED => Status::MaxValueReached,
            MEMORY_PROBLEM => Status::MemoryProblem,
            NOT_ENOUGH_MEMORY_SPACE => Status::NotEnoughMemorySpace,
            NO_EF_SELECTED => Status::NoEFSelected,
            OK => Status::OK,
            PIN_REMAINING_ATTEMPTS => Status::PinRemainingAttempts,
            REFERENCED_DATA_NOT_FOUND => Status::ReferencedDataNotFound,
            SECURITY_STATUS_NOT_SATISFIED => Status::SecurityStatusNotSatisfied,
            TECHNICAL_PROBLEM => Status::TechnicalProblem,
            _ => Status::Unknown(s),
        }
    }
}

pub const ACCESS_CONDITION_NOT_FULFILLED: u16 = 0x9804;
pub const ALGORITHM_NOT_SUPPORTED: u16 = 0x9484;
pub const CLA_NOT_SUPPORTED: u16 = 0x6e00;
pub const CODE_BLOCKED: u16 = 0x9840;
pub const CODE_NOT_INITIALIZED: u16 = 0x9802;
pub const COMMAND_INCOMPATIBLE_FILE_STRUCTURE: u16 = 0x6981;
pub const CONDITIONS_OF_USE_NOT_SATISFIED: u16 = 0x6985;
pub const CONTRADICTION_INVALIDATION: u16 = 0x9810;
pub const CONTRADICTION_SECRET_CODE_STATUS: u16 = 0x9808;
pub const FILE_ALREADY_EXISTS: u16 = 0x6a89;
pub const FILE_NOT_FOUND: u16 = 0x9404;
pub const GP_AUTH_FAILED: u16 = 0x6300;
pub const HALTED: u16 = 0x6faa;
pub const INCONSISTENT_FILE: u16 = 0x9408;
pub const INCORRECT_DATA: u16 = 0x6a80;
pub const INCORRECT_LENGTH: u16 = 0x6700;
pub const INCORRECT_P1_P2: u16 = 0x6b00;
pub const INS_NOT_SUPPORTED: u16 = 0x6d00;
pub const INVALID_KCV: u16 = 0x9485;
pub const INVALID_OFFSET: u16 = 0x9402;
pub const LICENSING: u16 = 0x6f42;
pub const MAX_VALUE_REACHED: u16 = 0x9850;
pub const MEMORY_PROBLEM: u16 = 0x9240;
pub const NOT_ENOUGH_MEMORY_SPACE: u16 = 0x6a84;
pub const NO_EF_SELECTED: u16 = 0x9400;
pub const OK: u16 = 0x9000;
pub const PIN_REMAINING_ATTEMPTS: u16 = 0x63c0;
pub const REFERENCED_DATA_NOT_FOUND: u16 = 0x6a88;
pub const SECURITY_STATUS_NOT_SATISFIED: u16 = 0x6982;
pub const TECHNICAL_PROBLEM: u16 = 0x6f00;
