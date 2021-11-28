use crate::{
    AccessError, AddRuleError, AddRulesError, BitFlags, CompatError, CompatLevel, CompatState,
    Compatibility, HandleAccessError, HandleAccessesError, Ruleset, TryCompat, ABI,
};
use enumflags2::BitFlag;

#[cfg(test)]
use crate::{make_bitflags, AccessFs};

pub trait Access: PrivateAccess {
    /// Gets the access rights defined by a specific [`ABI`].
    fn from_all(abi: ABI) -> BitFlags<Self>;
}

pub trait PrivateAccess: BitFlag {
    fn ruleset_handle_access(
        ruleset: Ruleset,
        access: BitFlags<Self>,
    ) -> Result<Ruleset, HandleAccessesError>
    where
        Self: Access;

    fn into_add_rules_error(error: AddRuleError<Self>) -> AddRulesError
    where
        Self: Access;

    fn into_handle_accesses_error(error: HandleAccessError<Self>) -> HandleAccessesError
    where
        Self: Access;
}

// Creates an illegal/overflowed BitFlags<T> with all its bits toggled, including undefined ones.
fn full_negation<T>(flags: BitFlags<T>) -> BitFlags<T>
where
    T: Access,
{
    unsafe { BitFlags::<T>::from_bits_unchecked(!flags.bits()) }
}

#[test]
fn bit_flags_full_negation() {
    let scoped_negation = !BitFlags::<AccessFs>::all();
    assert_eq!(scoped_negation, BitFlags::<AccessFs>::empty());
    // !BitFlags::<AccessFs>::all() could be equal to full_negation(BitFlags::<AccessFs>::all()))
    // if all the 64-bits would be used, which is not currently the case.
    assert_ne!(scoped_negation, full_negation(BitFlags::<AccessFs>::all()));
}

impl<T> TryCompat<T> for BitFlags<T>
where
    T: Access,
{
    fn try_compat(self, compat: &mut Compatibility) -> Result<Option<Self>, CompatError<T>> {
        let (state, new_access) = if self.is_empty() {
            // Empty access-rights would result to a runtime error.
            return Err(AccessError::Empty.into());
        } else if !Self::all().contains(self) {
            // Unknown access-rights (at build time) would result to a runtime error.
            // This can only be reached by using the unsafe BitFlags::from_bits_unchecked().
            return Err(AccessError::Unknown {
                access: self,
                unknown: self & full_negation(Self::all()),
            }
            .into());
        } else {
            let compat_bits = self & T::from_all(compat.abi);
            if compat_bits.is_empty() {
                match compat.level {
                    // Empty access-rights are ignored to avoid an error when passing them to
                    // landlock_add_rule().
                    CompatLevel::BestEffort => (CompatState::No, None),
                    CompatLevel::SoftRequirement => (CompatState::Final, None),
                    CompatLevel::HardRequirement => {
                        return Err(AccessError::Incompatible { access: self }.into());
                    }
                }
            } else if compat_bits != self {
                match compat.level {
                    CompatLevel::BestEffort => (CompatState::Partial, Some(compat_bits)),
                    CompatLevel::SoftRequirement => (CompatState::Final, None),
                    CompatLevel::HardRequirement => {
                        return Err(AccessError::PartiallyCompatible {
                            access: self,
                            incompatible: self & full_negation(compat_bits),
                        }
                        .into());
                    }
                }
            } else {
                (CompatState::Full, Some(compat_bits))
            }
        };
        compat.update(state);
        Ok(new_access)
    }
}

#[test]
fn compat_bit_flags() {
    use crate::ABI;

    let mut compat: Compatibility = ABI::V1.into();
    assert!(!compat.is_mooted());

    let ro_access = make_bitflags!(AccessFs::{Execute | ReadFile | ReadDir});
    assert_eq!(
        ro_access,
        ro_access.try_compat(&mut compat).unwrap().unwrap()
    );

    let empty_access = BitFlags::<AccessFs>::empty();
    assert!(matches!(
        empty_access.try_compat(&mut compat).unwrap_err(),
        CompatError::Access(AccessError::Empty)
    ));

    let all_unknown_access = unsafe { BitFlags::<AccessFs>::from_bits_unchecked(1 << 63) };
    assert!(matches!(
        all_unknown_access.try_compat(&mut compat).unwrap_err(),
        CompatError::Access(AccessError::Unknown { access, unknown }) if access == all_unknown_access && unknown == all_unknown_access
    ));

    let some_unknown_access = unsafe { BitFlags::<AccessFs>::from_bits_unchecked(1 << 63 | 1) };
    assert!(matches!(
        some_unknown_access.try_compat(&mut compat).unwrap_err(),
        CompatError::Access(AccessError::Unknown { access, unknown }) if access == some_unknown_access && unknown == all_unknown_access
    ));

    assert!(!compat.is_mooted());

    compat.abi = ABI::Unsupported;
    assert!(!compat.is_mooted());

    // Access-rights are valid (but ignored) when they are not required for the current ABI.
    assert_eq!(None, ro_access.try_compat(&mut compat).unwrap());

    // Tests that a ruleset in an unsupported state doesn't get spuriously mooted.
    assert!(!compat.is_mooted());

    // Access-rights are not valid when they are required for the current ABI.
    compat.level = CompatLevel::HardRequirement;
    assert!(matches!(
        ro_access.try_compat(&mut compat).unwrap_err(),
        CompatError::Access(AccessError::Incompatible { access }) if access == ro_access
    ));
}
