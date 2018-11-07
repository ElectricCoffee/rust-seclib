use std::marker::PhantomData;

#[cfg(test)]
mod tests;

pub mod security_level;

pub mod prelude;

use security_level as sl;

/// The Sec monad which wraps any kind of data with a `SecurityLevel`.
/// It provides means of securely modifying the internal data via `map` and `and_then`, 
/// while also allowing the user to lift/promote the security level, or even discard it entirely.
#[derive(Debug, PartialEq, Clone)]
pub struct Sec<S, A>
where
    S: sl::SecurityLevel, // s must be a security level
{
    // these fields are public only within the library. Outsiders won't have access
    pub (crate) security_level: PhantomData<S>, // Rust's way of representing phantom types
    pub (crate) data: A,
}

impl<S, A> Sec<S, A> 
where 
    S: sl::SecurityLevel,
{
    /// Constructor. Note that it makes no mention of S.
    pub fn new(data: A) -> Self {
        Sec { data, security_level: PhantomData }
    }
    
    /// Maps a function over a `Sec` and returns a new `Sec` with the same security level.
    /// 
    /// # Example
    /// ```
    /// use seclib::prelude::*;
    /// 
    /// let data: Sec<High, String> = Sec::new("I'm Safe".into());
    /// let result = data.map(|s| format!("{}!", s));
    /// 
    /// let expected: Sec<High, String> = Sec::new("I'm Safe!".into());
    /// 
    /// assert_eq!(result, expected);
    /// ```
    pub fn map<B, F>(self, f: F) -> Sec<S, B> 
    where 
        F: FnOnce(A) -> B // F is a function A -> B that iterates once only
    {
        let Sec { data, security_level } = self;
        Sec {
            data: f(data),
            security_level,
        }
    }
    
    /// Flat maps a function over `Sec`, resulting in a new `Sec` of the same security level.
    /// 
    /// `and_then` represents monadic bind. It is also called `flatMap`, `SelectMany`, `bind`, and `>>=` in other programming languages.
    /// 
    /// # Example
    /// ```
    /// use seclib::prelude::*;
    /// 
    /// fn func(i: i32) -> Sec<High, i32> {
    ///     (i + 2).into()
    /// }
    /// 
    /// let data: Sec<High, i32> = 4.into();
    /// let result = data.and_then(func);
    /// let expected: Sec<High, i32> = 6.into();
    /// 
    /// assert_eq!(result, expected);
    /// ```
    pub fn and_then<B, F>(self, f: F) -> Sec<S, B> 
    where 
        F: FnOnce(A) -> Sec<S, B> 
    {
        let Sec { data, .. } = self;
        f(data)
    }
    
    /// Reveal returns the value from within a `Sec`.
    /// Note that in order to do so, it must be supplied with a security level &geq; the `Sec`'s
    /// 
    /// # Examples
    /// The following example shows how you'd get the value out:
    /// ```
    /// use seclib::prelude::*;
    /// 
    /// // Data safely stored within a Sec
    /// let data: Sec<High, String> = Sec::new("Attack at Dawn!".into());
    /// 
    /// let output = data.reveal(High); // `data` is now moved and no longer available
    /// assert_eq!(output, "Attack at Dawn!".to_string());
    /// ```
    /// The following example showcases what would happen if the wrong security level were to be used:
    /// ```compile_fail
    /// use seclib::prelude::*;
    /// 
    /// // Data safely stored within a Sec
    /// let data: Sec<High, String> = Sec::new("Attack at Dawn!".into());
    /// 
    /// let output = data.reveal(Low); // ERROR: the trait `SecurityLevel<High>` is not implemented for `Low`
    /// assert_eq!(output, "Attack at Dawn!".to_string());
    /// ```
    pub fn reveal<S2>(self, _: S2) -> A 
    where 
        S2: sl::SecurityLevel<S> + sl::SecurityLevel
    {
        self.data
    }

    /// Lifts the data to a higher security level within a `Sec`.
    /// 
    /// # Examples
    /// Converting from low to high works as expected:
    /// ```
    /// use seclib::prelude::*;
    /// 
    /// let data: Sec<Low, String> = Sec::new("Attack at midnight.".into());
    /// let result = data.lift(High); // `data` is now of type `Sec<High, String>`
    /// let expected: Sec<High, String> = Sec::new("Attack at midnight.".into());
    /// 
    /// assert_eq!(result, expected);
    /// ```
    /// However, trying to convert from high to low results in a compile error:
    /// ```compile_fail
    /// use seclib::prelude::*;
    /// 
    /// let data: Sec<High, String> = Sec::new("Attack at midnight.".into());
    /// let result = data.lift(Low); // ERROR: the trait `SecurityLevel<High>` is not implemented for `Low`
    /// let expected: Sec<Low, String> = Sec::new("Attack at midnight.".into());
    /// 
    /// assert_eq!(result, expected);
    /// ```
    pub fn lift<S2>(self, _: S2) -> Sec<S2, A>
    where
        S2: sl::SecurityLevel<S> + sl::SecurityLevel
    {
        let Sec { data, ..} = self;
        Sec::new(data)
    }
}

impl<S, A> From<A> for Sec<S, A> 
where
    S : sl::SecurityLevel
{
    fn from(data: A) -> Sec<S, A> {
        Sec::new(data)
    }
}
