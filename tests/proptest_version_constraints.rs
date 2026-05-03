//! Property-based tests for version constraints

use proptest::prelude::*;
use vulnera_deps::domain::version_constraint::VersionConstraint;

proptest! {
    #[test]
    fn test_version_constraint_parsing_doesnt_crash(
        major in 0u64..100u64,
        minor in 0u64..100u64,
        patch in 0u64..100u64
    ) {
        let version = format!("{}.{}.{}", major, minor, patch);
        let constraints = vec![
            format!("^{}", version),
            format!("~{}", version),
            format!(">={}", version),
            format!("<={}", version),
        ];

        for constraint in constraints {
            prop_assert!(VersionConstraint::parse(&constraint).is_ok(),
                "Failed to parse constraint: {}", constraint);
        }
    }
}
