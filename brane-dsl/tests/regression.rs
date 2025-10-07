use brane_dsl::{ParserOptions, parse};
use brane_shr::utilities::{create_package_index, test_on_dsl_files};


/// Tests BraneScript files.
#[test]
fn test_bscript() {
    // Simply pass to the compiler
    test_on_dsl_files("BraneScript", |path, code| {
        // Read the package index
        let pindex = create_package_index();

        // Create a compiler and compile it;
        let res = match parse(code, &pindex, &ParserOptions::bscript()) {
            Ok(res) => res,
            Err(err) => {
                panic!("Failed to parse BraneScript file '{}': {}", path.display(), err);
            },
        };

        insta::assert_debug_snapshot!(path.as_os_str().to_str().expect("Invalid test name"), res);
    });
}


/// Tests Bakery files.
#[test]
fn test_bakery() {
    // Simply pass to the compiler
    test_on_dsl_files("Bakery", |path, code| {
        // Read the package index
        let pindex = create_package_index();

        // Create a compiler and compile it;
        let res = match parse(code, &pindex, &ParserOptions::bakery()) {
            Ok(res) => res,
            Err(err) => {
                panic!("Failed to parse Bakery file '{}': {}", path.display(), err);
            },
        };

        insta::assert_debug_snapshot!(path.as_os_str().to_str().expect("Invalid test name"), res);
    });
}
