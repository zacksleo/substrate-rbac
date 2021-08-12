use std::marker::PhantomData;

use crate as pallet_rbac;
use frame_support::{parameter_types, traits::EnsureOrigin};
use frame_system as system;
use sp_core::{H256, sr25519, Pair};
use sp_runtime::{
	testing::Header,
	traits::{BlakeTwo256, IdentityLookup},
};
use system::RawOrigin;

pub type SignedExtra = (
	pallet_rbac::Authorize<Test>,
);

type UncheckedExtrinsic = frame_system::mocking::MockUncheckedExtrinsic<Test, (), SignedExtra>;
type Block = frame_system::mocking::MockBlock<Test>;

// Configure a mock runtime to test the pallet.
frame_support::construct_runtime!(
	pub enum Test where
		Block = Block,
		NodeBlock = Block,
		UncheckedExtrinsic = UncheckedExtrinsic,
	{
		System: frame_system::{Pallet, Call, Config, Storage, Event<T>},
		Rbac: pallet_rbac::{Pallet, Call, Storage, Event<T>, Config<T>},
	}
);

parameter_types! {
	pub const BlockHashCount: u64 = 250;
	pub const SS58Prefix: u8 = 42;
}

impl system::Config for Test {
	type BaseCallFilter = ();
	type BlockWeights = ();
	type BlockLength = ();
	type DbWeight = ();
	type Origin = Origin;
	type Call = Call;
	type Index = u64;
	type BlockNumber = u64;
	type Hash = H256;
	type Hashing = BlakeTwo256;
	type AccountId = sr25519::Public;
	type Lookup = IdentityLookup<Self::AccountId>;
	type Header = Header;
	type Event = Event;
	type BlockHashCount = BlockHashCount;
	type Version = ();
	type PalletInfo = PalletInfo;
	type AccountData = ();
	type OnNewAccount = ();
	type OnKilledAccount = ();
	type SystemWeightInfo = ();
	type SS58Prefix = SS58Prefix;
	type OnSetCode = ();
}

impl pallet_rbac::Config for Test {
	type Event = Event;
	type CreateRoleOrigin = MockOrigin<Test>;
}

pub fn account_key(s: &str) -> sr25519::Public {
	sr25519::Pair::from_string(&format!("//{}", s), None)
		.expect("static values are valid; qed")
		.public()
}

// Build genesis storage according to the mock runtime.
pub fn new_test_ext() -> sp_io::TestExternalities {
	let storage = system::GenesisConfig::default().build_storage::<Test>().unwrap();
	let mut ext = sp_io::TestExternalities::new(storage);
	// Events are not emitted on block 0 -> advance to block 1.
	// Any dispatchable calls made during genesis block will have no events emitted.
	ext.execute_with(|| System::set_block_number(1));
	ext
}

pub struct MockOrigin<T>(PhantomData<T>);

impl<T: pallet_rbac::Config> EnsureOrigin<T::Origin> for MockOrigin<T> {
	type Success = T::AccountId;
	fn try_origin(o: T::Origin) -> Result<Self::Success, T::Origin> {
		o.into().and_then(|o| match o {
			RawOrigin::Signed(ref who) => Ok(who.clone()),
			r => Err(T::Origin::from(r)),
		})
	}
}
