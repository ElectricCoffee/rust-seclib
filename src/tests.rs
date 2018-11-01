use super::Sec;
use super::security_level::*;
// The example from the paper of a tuple with a secured char and an int
fn f((cs, i): (Sec<High, char>, i32)) -> (Sec<High, char>, i32) {
    let lhs = cs.map(|c| ((c as u8) + 1) as char);
    let rhs = i + 3;
    (lhs, rhs)
}

#[test]
fn test_map() {
    let data: Sec<High, String> = Sec::new("I'm Safe".into());
    let result = data.map(|s| format!("{}!", s));

    let expected: Sec<High, String> = Sec::new("I'm Safe!".into());

    assert_eq!(result, expected);
}

#[test]
fn test_reveal_success() {
    // testing high <= high
    let data: Sec<High, i32> = 12.into();
    let result = data.reveal(High);

    assert_eq!(result, 12);

    // testing low <= high
    let data: Sec<Low, i32> = 13.into();
    let result = data.reveal(High);

    assert_eq!(result, 13);
}