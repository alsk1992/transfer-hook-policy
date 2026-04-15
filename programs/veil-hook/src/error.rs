use pinocchio::error::ProgramError;

/// Veil-specific error codes, packed into `ProgramError::Custom(u32)`.
///
/// Range 0x5600–0x560F is reserved for this program.
#[repr(u32)]
pub enum VeilError {
    RecipientNotWhitelisted = 0x5600,
    AmountExceedsTxCap      = 0x5601,
    DailyCapExceeded        = 0x5602,
    MonthlyCapExceeded      = 0x5603,
    VelocityLimitExceeded   = 0x5604,
    TimeWindowViolation     = 0x5605,
    DelegationUnauthorized  = 0x5606,
    InvalidZkProof          = 0x5607,
    PolicyNotFound          = 0x5608,
    InvalidPolicyData       = 0x5609,
    InvalidSpendTracker     = 0x560A,
    NotPolicyOwner          = 0x560B,
    InvalidOwner            = 0x560C,
    AlreadyInitialized      = 0x560D,
    InvalidMerkleProof      = 0x560E,
}

impl From<VeilError> for ProgramError {
    #[inline(always)]
    fn from(e: VeilError) -> Self {
        ProgramError::Custom(e as u32)
    }
}
