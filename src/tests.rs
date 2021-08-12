use super::*;

use crate::mock::{account_key, new_test_ext, Event as TestEvent, Origin, Rbac, System, Test};

use frame_support::{assert_noop, assert_ok};

const TEST_SENDER: &str = "Alice";
const TEST_ASSIGN: &str = "Bob";
const PALLET_NAME: &str = "rbac";

#[test]
fn create_role() {
    new_test_ext().execute_with(|| {
        let origin = account_key(TEST_SENDER);
        let name = PALLET_NAME.as_bytes().to_owned();
        let result = Rbac::create_role(Origin::signed(origin), name.clone(), Permission::Execute);

        assert_ok!(result);
        System::assert_has_event(TestEvent::Rbac(Event::RoleCreated(
            origin,
            name,
            b"Permission::Execute".to_vec(),
        )));
    });
}

#[test]
fn assign_role_access_denied() {
    new_test_ext().execute_with(|| {
        let origin = account_key(TEST_SENDER);
        let assign = account_key(TEST_ASSIGN);
        assert_noop!(
            Rbac::assign_role(
                Origin::signed(origin),
                assign,
                Role {
                    pallet: PALLET_NAME.as_bytes().to_owned(),
                    permission: Permission::Execute,
                },
            ),
            Error::<Test>::AccessDenied
        );
    });
}

#[test]
fn assign_role_with_access() {
    new_test_ext().execute_with(|| {
        let origin = account_key(TEST_SENDER);
        let assign = account_key(TEST_ASSIGN);
        let name = PALLET_NAME.as_bytes().to_owned();

        let result = Rbac::create_role(Origin::signed(origin), name.clone(), Permission::Manage);

        assert_ok!(result);

        let result = Rbac::assign_role(
            Origin::signed(origin),
            assign,
            Role {
                pallet: name.clone(),
                permission: Permission::Execute,
            },
        );
        assert_ok!(result);
        System::assert_has_event(TestEvent::Rbac(Event::AccessGranted(
            assign,
            name,
        )));
    });
}

#[test]
fn revoke_access_error(){
    new_test_ext().execute_with(|| {
        let origin = account_key(TEST_SENDER);
        let assign = account_key(TEST_ASSIGN);
        let name = PALLET_NAME.as_bytes().to_owned();
        assert_noop!(
            Rbac::revoke_access(
                Origin::signed(origin),
                assign,
                Role {
                    pallet: name,
                    permission: Permission::Execute,
                },
            ),
            Error::<Test>::AccessDenied
        );
    });
}

#[test]
fn revoke_access_ok(){
    new_test_ext().execute_with(|| {
        let origin = account_key(TEST_SENDER);
        let assign = account_key(TEST_ASSIGN);
        let name = PALLET_NAME.as_bytes().to_owned();

        let result = Rbac::create_role(Origin::signed(origin), name.clone(), Permission::Manage);

        assert_ok!(result);

        let result = Rbac::revoke_access(
            Origin::signed(origin),
            assign,
            Role {
                pallet: name.clone(),
                permission: Permission::Execute,
            },
        );
        assert_ok!(result);
        System::assert_has_event(TestEvent::Rbac(Event::AccessRevoked(
            assign,
            name,
        )));
    });
}