use super::*;
use crate::{mock::*, Error};
use frame_support::{assert_noop, assert_ok, dispatch};

const TEST_SENDER: &str = "Alice";
const PALLET_NAME: &str = "rbac";

#[test]
fn create_role_test() {
    new_test_ext().execute_with(|| {
        let origin = account_key(TEST_SENDER);
        let name = PALLET_NAME.as_bytes().to_owned();
        let result = Rbac::create_role(Origin::signed(origin), name, Permission::Execute);

        assert_ok!(result);
    });
}
