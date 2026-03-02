//! Integration test verifying entropy API visibility from the crate root.

#[test]
fn shannon_entropy_is_public() {
    // Accessible via crate root re-export
    let e = gitleaks_rs::shannon_entropy("test");
    assert!(e > 0.0);
}

#[test]
fn shannon_entropy_via_module_path() {
    // Accessible via full module path
    let e = gitleaks_rs::entropy::shannon_entropy("test");
    assert!(e > 0.0);
}

#[test]
fn entropy_doc_example_works() {
    assert_eq!(gitleaks_rs::shannon_entropy(""), 0.0);
    assert!(gitleaks_rs::shannon_entropy("abcdefghij") > 3.0);
}
