use super::Sec;
use super::security_level::*;

#[test]
fn test_map() {
    let data: Sec<High, String> = Sec::new("I'm Safe".into());
    let result = data.map(|s| format!("{}!", s));

    let expected: Sec<High, String> = Sec::new("I'm Safe!".into());

    assert_eq!(result, expected);
}

#[test]
fn test_and_then() {
    fn f1(i: i32) -> Sec<High, i32> {
        (i + 2).into()
    }

    let data: Sec<High, i32> = 4.into();
    let result = data.and_then(f1);
    let expected: Sec<High, i32> = 6.into();

    assert_eq!(result, expected);

    fn f2(i: i32) -> Sec<Low, i32> {
        (i + 2).into()
    }

    let data: Sec<Low, i32> = 5.into();
    let result = data.and_then(f2);
    let expected: Sec<Low, i32> = 7.into();

    assert_eq!(result, expected);
}

#[test]
fn test_reveal() {
    // testing high <= high
    let data: Sec<High, i32> = 12.into();
    let result = data.reveal(High);

    assert_eq!(result, 12);

    // testing low <= high
    let data: Sec<Low, i32> = 13.into();
    let result = data.reveal(High);

    assert_eq!(result, 13);

    // testing low <= low
    let data: Sec<Low, i32> = 14.into();
    let result = data.reveal(Low);

    assert_eq!(result, 14);

    // NOTE: Last case cannot be tested, because it cannot compile. (which is the whole idea)
}

#[test]
fn test_lift() {
    // testing lifting from low to high
    let data: Sec<Low, String> = String::from("Attack at dawn").into();
    let result = data.lift(High);
    let expected: Sec<High, String> = String::from("Attack at dawn").into();

    assert_eq!(result, expected);

    // .. from low to low
    let data: Sec<Low, String> = String::from("Attack at noon").into();
    let result = data.lift(Low);
    let expected: Sec<Low, String> = String::from("Attack at noon").into();

    assert_eq!(result, expected);

    // .. from high to high
    let data: Sec<High, String> = String::from("Attack at night").into();
    let result = data.lift(High);
    let expected: Sec<High, String> = String::from("Attack at night").into();

    assert_eq!(result, expected);

    // Does not compile, as intended!
    // let data: Sec<High, String> = String::from("Attack now!").into();
    // let result = data.lift(Low);
    // let expected: Sec<Low, String> = String::from("Attack now!").into();

    // assert_eq!(result, expected);
}