//! Test helper functions for vulnera-deps
use vulnera_deps::domain::version_constraint::VersionConstraint;
use vulnera_deps::domain::vulnerability::value_objects::Version;

/// Assert version constraints are satisfied
pub fn assert_version_satisfies(version: &str, constraint: &str, expected: bool) {
    let ver = Version::parse(version).expect("valid version in test");
    let con = VersionConstraint::parse(constraint).expect("valid constraint in test");
    assert_eq!(
        con.satisfies(&ver),
        expected,
        "Version {} should{} satisfy constraint '{}'",
        version,
        if expected { "" } else { " not" },
        constraint
    );
}
