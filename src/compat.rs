use crate::{uapi, Access, CompatError};

/// Version of the Landlock [ABI](https://en.wikipedia.org/wiki/Application_binary_interface).
///
/// `ABI` enables to get the features supported by a specific Landlock ABI.
/// For example, [`AccessFs::from_all(ABI::V1)`](Access::from_all)
/// gets all the file system access rights defined by the first version.
///
/// Without `ABI`, it would be hazardous to rely on the the full set of access flags
/// (e.g., `BitFlags::<AccessFs>::all()` or `BitFlags::ALL`),
/// a moving target that would change the semantics of your Landlock rule
/// when migrating to a newer version of this crate
/// (i.e. non-breaking change with new supported features).
/// This usage should then be considered indeterministic because requested features
/// (e.g., access rights)
/// could not be tied to the application source code.
///
/// Such `ABI` is also convenient to get the features supported by a specific Linux kernel
/// without relying on the kernel version (which may not be accessible or patched).
#[cfg_attr(test, derive(Debug, PartialEq))]
#[derive(Copy, Clone)]
#[non_exhaustive]
pub enum ABI {
    /// Kernel not supporting Landlock, either because it is not built with Landlock
    /// or Landlock is not enabled at boot.
    Unsupported = 0,
    /// First Landlock ABI,
    /// introduced with [Linux 5.13](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=62fb9874f5da54fdb243003b386128037319b219).
    V1 = 1,
}

impl ABI {
    // Must remain private to avoid inconsistent behavior by passing Ok(self) to a builder method,
    // e.g. to make it impossible to call ruleset.handle_fs(ABI::new_current()?)
    fn new_current() -> Self {
        ABI::from(unsafe {
            // Landlock ABI version starts at 1 but errno is only set for negative values.
            uapi::landlock_create_ruleset(
                std::ptr::null(),
                0,
                uapi::LANDLOCK_CREATE_RULESET_VERSION,
            )
        })
    }

    // There is no way to not publicly expose an implementation of an external trait such as
    // From<i32>.  See RFC https://github.com/rust-lang/rfcs/pull/2529
    fn from(value: i32) -> ABI {
        match value {
            // The only possible error values should be EOPNOTSUPP and ENOSYS, but let's interpret
            // all kind of errors as unsupported.
            n if n <= 0 => ABI::Unsupported,
            1 => ABI::V1,
            // Returns the greatest known ABI.
            _ => ABI::V1,
        }
    }
}

#[test]
fn abi_from() {
    // EOPNOTSUPP (-95), ENOSYS (-38)
    for n in &[-95, -38, -1, 0] {
        assert_eq!(ABI::from(*n), ABI::Unsupported);
    }

    assert_eq!(ABI::from(1), ABI::V1);
    assert_eq!(ABI::from(2), ABI::V1);
    assert_eq!(ABI::from(9), ABI::V1);
}

/// Returned by ruleset builder.
#[cfg_attr(test, derive(Debug))]
#[derive(Copy, Clone, PartialEq)]
pub(crate) enum CompatState {
    /// All requested restrictions are enforced.
    Full,
    /// Some requested restrictions are enforced, following a best-effort approach.
    Partial,
    /// The running system doesn't support Landlock.
    No,
    /// Final unsupported state.
    Final,
}

impl CompatState {
    fn update(&mut self, other: Self) {
        *self = match (*self, other) {
            (CompatState::Final, _) => CompatState::Final,
            (_, CompatState::Final) => CompatState::Final,
            (CompatState::No, CompatState::No) => CompatState::No,
            (CompatState::Full, CompatState::Full) => CompatState::Full,
            (_, _) => CompatState::Partial,
        }
    }
}

#[test]
fn compat_state_update_1() {
    let mut state = CompatState::Full;

    state.update(CompatState::Full);
    assert_eq!(state, CompatState::Full);

    state.update(CompatState::No);
    assert_eq!(state, CompatState::Partial);

    state.update(CompatState::Full);
    assert_eq!(state, CompatState::Partial);

    state.update(CompatState::Full);
    assert_eq!(state, CompatState::Partial);

    state.update(CompatState::No);
    assert_eq!(state, CompatState::Partial);

    state.update(CompatState::Final);
    assert_eq!(state, CompatState::Final);

    state.update(CompatState::Full);
    assert_eq!(state, CompatState::Final);
}

#[test]
fn compat_state_update_2() {
    let mut state = CompatState::Full;

    state.update(CompatState::Full);
    assert_eq!(state, CompatState::Full);

    state.update(CompatState::No);
    assert_eq!(state, CompatState::Partial);

    state.update(CompatState::Full);
    assert_eq!(state, CompatState::Partial);
}

#[cfg_attr(test, derive(Debug))]
#[derive(Clone)]
// Compatibility is not public outside this crate.
pub struct Compatibility {
    abi: ABI,
    pub(crate) level: CompatLevel,
    state: CompatState,
    // is_mooted is required to differenciate a kernel not supporting Landlock from an error that
    // occured with CompatLevel::SoftRequirement.  is_mooted is only changed with update() and only
    // used to not set no_new_privs in RulesetCreated::restrict_self().
    is_mooted: bool,
}

impl From<ABI> for Compatibility {
    fn from(abi: ABI) -> Self {
        Compatibility {
            abi,
            level: CompatLevel::BestEffort,
            state: match abi {
                // Forces the state as unsupported because all possible types will be useless.
                ABI::Unsupported => CompatState::Final,
                _ => CompatState::Full,
            },
            is_mooted: false,
        }
    }
}

impl Compatibility {
    // Compatibility is an opaque struct.
    #[allow(clippy::new_without_default)]
    pub(crate) fn new() -> Self {
        ABI::new_current().into()
    }

    pub(crate) fn update(&mut self, state: CompatState) {
        self.state.update(state);
        if state == CompatState::Final {
            self.abi = ABI::Unsupported;
            self.is_mooted = true;
        }
    }

    pub(crate) fn abi(&self) -> ABI {
        self.abi
    }

    pub(crate) fn state(&self) -> CompatState {
        self.state
    }

    pub(crate) fn is_mooted(&self) -> bool {
        self.is_mooted
    }
}

/// Properly handles runtime unsupported features.
///
/// This guarantees consistent behaviors across crate users
/// and runtime kernels even if this crate get new features.
/// It eases backward compatibility and enables future-proofness.
///
/// Landlock is a security feature designed to help improve security of a running system
/// thanks to application developers.
/// To protect users as much as possible,
/// compatibility with the running system should then be handled in a best-effort way,
/// contrary to common system features.
/// In some circumstances
/// (e.g. applications carefully designed to only be run with a specific set of kernel features),
/// it may be required to error out if some of these features are not available
/// and will then not be enforced.
pub trait Compatible {
    /// FIXME: integrate
    /// set_compatibility(CompatLevel::SoftRequirement) makes the ruleset moot
    /// if one of the following requests are not supported, but don't return a
    /// compatibility error.
    ///
    /// FIXME: update
    /// To enable a best-effort security approach,
    /// Landlock features that are not supported by the running system
    /// are silently ignored by default,
    /// which is a sane choice for most use cases.
    /// However, on some rare circumstances,
    /// developers may want to have some guarantees that their applications
    /// will not run if a certain level of sandboxing is not possible.
    /// If you really want to error out when not all your requested requirements are met,
    /// then you can configure it with `set_best_effort(false)`.
    ///
    /// The order of this call is important because
    /// it defines the behavior of the following method calls that return a [`Result`].
    /// If `set_best_effort(false)` is called on an object,
    /// then a [`CompatError`] may be returned for the next method calls,
    /// until the next call to `set_best_effort(true)`.
    /// This enables to change the behavior of a set of build calls,
    /// for instance to be sure that the sandbox will at least restrict some access rights.
    ///
    /// # Example
    ///
    /// Create a ruleset which will at least support execution constraints.
    ///
    /// ```
    /// use landlock::{
    ///     Access, AccessFs, CompatLevel, Compatible, PathBeneath, Ruleset, RulesetCreated, RulesetError,
    ///     ABI,
    /// };
    ///
    /// fn ruleset_fragile() -> Result<RulesetCreated, RulesetError> {
    ///     Ok(Ruleset::new()
    ///         // This ruleset must handle at least the execute access.
    ///         .set_compatibility(CompatLevel::HardRequirement)
    ///         // This handle_access() call will return
    ///         // a wrapped AccessError<AccessFs>::Incompatible error
    ///         // if the running kernel can't handle AccessFs::Execute.
    ///         .handle_access(AccessFs::Execute)?
    ///         // This ruleset may also handle other access rights
    ///         // if they are supported by the running kernel.
    ///         // Because handle_access() replaces the previously set value,
    ///         // the new value must be a superset of AccessFs::Execute.
    ///         .set_compatibility(CompatLevel::BestEffort)
    ///         .handle_access(AccessFs::from_all(ABI::V1))?
    ///         .create()?)
    /// }
    /// ```
    fn set_compatibility(self, level: CompatLevel) -> Self;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompatLevel {
    /// Takes into account the requests if they are supported by the running system,
    /// or silently ignores them otherwise.
    /// Never returns a compatibility error.
    BestEffort,
    /// Takes into account the requests if they are supported by the running system,
    /// or silently ignores all the following requests otherwise.
    /// Never returns a compatibility error.
    /// If not supported,
    /// the call to [`RulesetCreated::restrict_self()`](crate::RulesetCreated::restrict_self())
    /// will return a
    /// [`RestrictionStatus { ruleset: RulesetStatus::NotEnforced, no_new_privs: false, }`](crate::RestrictionStatus).
    SoftRequirement,
    /// Takes into account the requests if they are supported by the running system,
    /// or returns a compatibilty error otherwise.
    HardRequirement,
}

// TryCompat is not public outside this crate.
pub trait TryCompat<T> {
    fn try_compat(self, compat: &mut Compatibility) -> Result<Option<Self>, CompatError<T>>
    where
        Self: Sized,
        T: Access;
}
