//! # Role-based Access Control (RBAC) Pallet
//!
//! The RBAC Pallet implements role-based access control and permissions for Substrate extrinsic calls.

#![cfg_attr(not(feature = "std"), no_std)]

pub use pallet::*;

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;

#[cfg(feature = "runtime-benchmarks")]
mod benchmarks;
#[frame_support::pallet]
pub mod pallet {
    use codec::{Decode, Encode};
    use frame_support::{
        dispatch::{DispatchInfo, GetCallMetadata},
        pallet_prelude::*,
    };
    use sp_std::fmt::Debug;
    use sp_std::marker::PhantomData;
    use sp_std::prelude::*;

    use frame_system::pallet_prelude::*;

    use sp_runtime::{
        print,
        traits::{DispatchInfoOf, Dispatchable, SignedExtension},
        transaction_validity::{
            InvalidTransaction, TransactionLongevity, TransactionPriority, TransactionValidity,
            TransactionValidityError, ValidTransaction,
        },
        RuntimeDebug,
    };

    #[derive(PartialEq, Eq, Clone, RuntimeDebug, Encode, Decode)]
    #[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
    pub enum Permission {
        Execute,
        Manage,
    }

    impl Permission {
        fn as_bytes(&self) -> &[u8] {
            match self {
                Permission::Execute => b"Permission::Execute",
                Permission::Manage => b"Permission::Manage",
            }
        }
    }

    impl Default for Permission {
        fn default() -> Self {
            Permission::Execute
        }
    }

    #[derive(PartialEq, Eq, Clone, RuntimeDebug, Encode, Decode)]
    #[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
    pub struct Role {
        pub pallet: Vec<u8>,
        pub permission: Permission,
    }

    #[pallet::config]
    pub trait Config: frame_system::Config {
        type Event: From<Event<Self>> + IsType<<Self as frame_system::Config>::Event>;
        type CreateRoleOrigin: EnsureOrigin<Self::Origin>;
    }

    #[pallet::pallet]
    #[pallet::generate_store(pub(super) trait Store)]
    pub struct Pallet<T>(_);

    #[pallet::storage]
    #[pallet::getter(fn super_admins)]
    pub type SuperAdmins<T: Config> =
        StorageMap<_, Blake2_128Concat, T::AccountId, bool, ValueQuery>;

    #[pallet::storage]
    #[pallet::getter(fn permissions)]
    pub type Permissions<T: Config> =
        StorageMap<_, Blake2_128Concat, (T::AccountId, Role), bool, ValueQuery>;

    #[pallet::storage]
    #[pallet::getter(fn roles)]
    pub type Roles<T: Config> = StorageValue<_, Vec<Role>, ValueQuery>;

    #[pallet::genesis_config]
    pub struct GenesisConfig<T: Config> {
        pub super_admins: Vec<T::AccountId>,
        pub permissions: Vec<(Role, Vec<T::AccountId>)>,
    }

    #[cfg(feature = "std")]
    impl<T: Config> Default for GenesisConfig<T> {
        fn default() -> Self {
            GenesisConfig {
                super_admins: Default::default(),
                permissions: Default::default(),
            }
        }
    }

    #[pallet::genesis_build]
    impl<T: Config> GenesisBuild<T> for GenesisConfig<T> {
        fn build(&self) {
            for admin in self.super_admins.iter() {
                <SuperAdmins<T>>::insert(admin, true);
            }
            for (role, members) in self.permissions.iter() {
                if !Pallet::<T>::add_role(role) {
                    panic!("Can't add duplicate roles.");
                }
                for member in members.iter() {
                    <Permissions<T>>::insert((member, role), true);
                }
            }
        }
    }

    #[pallet::error]
    pub enum Error<T> {
        AccessDenied,
        RoleExisted,
    }

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    #[pallet::metadata(T::AccountId = "AccountId")]
    pub enum Event<T: Config> {
        RoleCreated(T::AccountId, Vec<u8>, Vec<u8>),
        AccessRevoked(T::AccountId, Vec<u8>),
        AccessGranted(T::AccountId, Vec<u8>),
        SuperAdminAdded(T::AccountId),
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        #[pallet::weight(0)]
        pub fn create_role(
            origin: OriginFor<T>,
            pallet_name: Vec<u8>,
            permission: Permission,
        ) -> DispatchResult {
            T::CreateRoleOrigin::ensure_origin(origin.clone())?;

            // TODO: This should be removed and the AccountId should be extracted from the above.
            let who = ensure_signed(origin)?;

            let role = Role {
                pallet: pallet_name.clone(),
                permission: permission.clone(),
            };

            if !Self::add_role(&role) {
                return Err(Error::<T>::RoleExisted.into());
            }

            <Permissions<T>>::insert((who.clone(), role.clone()), true);
            Self::deposit_event(Event::RoleCreated(
                who,
                pallet_name,
                permission.as_bytes().to_vec(),
            ));
            Ok(())
        }

        #[pallet::weight(0)]
        pub fn assign_role(
            origin: OriginFor<T>,
            account_id: T::AccountId,
            role: Role,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;

            if !Self::verify_manage_access(who.clone(), role.pallet.clone()) {
                return Err(Error::<T>::AccessDenied.into());
            }

            <Permissions<T>>::insert((account_id.clone(), role.clone()), true);
            Self::deposit_event(Event::AccessGranted(account_id, role.pallet));
            Ok(())
        }

        #[pallet::weight(0)]
        pub fn revoke_access(
            origin: OriginFor<T>,
            account_id: T::AccountId,
            role: Role,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;

            if Self::verify_manage_access(who, role.pallet.clone()) {
                Self::deposit_event(Event::AccessRevoked(
                    account_id.clone(),
                    role.pallet.clone(),
                ));
                <Permissions<T>>::remove((account_id, role));
            } else {
                return Err(Error::<T>::AccessDenied.into());
            }

            Ok(())
        }

        /// Add a new Super Admin.
        /// Super Admins have access to execute and manage all pallets.
        ///
        /// Only _root_ can add a Super Admin.
        #[pallet::weight(0)]
        pub fn add_super_admin(origin: OriginFor<T>, account_id: T::AccountId) -> DispatchResult {
            ensure_root(origin)?;
            <SuperAdmins<T>>::insert(&account_id, true);
            Self::deposit_event(Event::SuperAdminAdded(account_id));
            Ok(())
        }
    }

    impl<T: Config> Pallet<T> {
        fn add_role(role: &Role) -> bool {
            let roles = Self::roles();
            if roles.contains(role) {
                return false;
            }

            <Roles<T>>::append(role.clone());
            true
        }

        pub fn verify_access(account_id: T::AccountId, pallet: Vec<u8>) -> bool {
            let execute_role = Role {
                pallet: pallet.clone(),
                permission: Permission::Execute,
            };

            let manage_role = Role {
                pallet,
                permission: Permission::Manage,
            };

            let roles = Self::roles();
            if (roles.contains(&manage_role)
                && <Permissions<T>>::get((account_id.clone(), manage_role)))
                || (roles.contains(&execute_role)
                    && <Permissions<T>>::get((account_id, execute_role)))
            {
                return true;
            }
            false
        }

        fn verify_manage_access(account_id: T::AccountId, pallet: Vec<u8>) -> bool {
            let role = Role {
                pallet,
                permission: Permission::Manage,
            };

            let roles = Self::roles();
            if roles.contains(&role) && <Permissions<T>>::get((account_id, role)) {
                return true;
            }
            false
        }
    }

    /// The following section implements the `SignedExtension` trait
    /// for the `Authorize` type.
    /// `SignedExtension` is being used here to filter out the not authorized accounts
    /// when they try to send extrinsics to the runtime.
    /// Inside the `validate` function of the `SignedExtension` trait,
    /// we check if the sender (origin) of the extrinsic has the execute permission or not.
    /// The validation happens at the transaction queue level,
    ///  and the extrinsics are filtered out before they hit the pallet logic.

    /// The `Authorize` struct.
    #[derive(Encode, Decode, Clone, Eq, PartialEq)]
    pub struct Authorize<T: Config + Send + Sync>(PhantomData<T>);

    /// Debug impl for the `Authorize` struct.
    impl<T: Config + Send + Sync> Debug for Authorize<T> {
        #[cfg(feature = "std")]
        fn fmt(&self, f: &mut sp_std::fmt::Formatter) -> sp_std::fmt::Result {
            write!(f, "Authorize")
        }

        #[cfg(not(feature = "std"))]
        fn fmt(&self, _: &mut sp_std::fmt::Formatter) -> sp_std::fmt::Result {
            Ok(())
        }
    }

    impl<T: Config + Send + Sync> SignedExtension for Authorize<T>
    where
        T::Call: Dispatchable<Info = DispatchInfo> + GetCallMetadata,
    {
        type AccountId = T::AccountId;
        type Call = T::Call;
        type AdditionalSigned = ();
        type Pre = ();
        const IDENTIFIER: &'static str = "Authorize";

        fn additional_signed(&self) -> sp_std::result::Result<(), TransactionValidityError> {
            Ok(())
        }

        fn validate(
            &self,
            who: &Self::AccountId,
            call: &Self::Call,
            info: &DispatchInfoOf<Self::Call>,
            _len: usize,
        ) -> TransactionValidity {
            let md = call.get_call_metadata();

            if <SuperAdmins<T>>::contains_key(who.clone()) {
                print("Access Granted!");
                Ok(ValidTransaction {
                    priority: info.weight as TransactionPriority,
                    longevity: TransactionLongevity::max_value(),
                    propagate: true,
                    ..Default::default()
                })
            } else if <Pallet<T>>::verify_access(
                who.clone(),
                md.pallet_name.as_bytes().to_vec(),
            ) {
                print("Access Granted!");
                Ok(ValidTransaction {
                    priority: info.weight as TransactionPriority,
                    longevity: TransactionLongevity::max_value(),
                    propagate: true,
                    ..Default::default()
                })
            } else {
                print("Access Denied!");
                Err(InvalidTransaction::Call.into())
            }
        }
    }
}
