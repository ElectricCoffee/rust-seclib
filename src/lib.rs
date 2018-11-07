use std::marker::PhantomData;

#[cfg(test)]
mod tests;

pub mod security_level;

use security_level as sl;

/// The Sec monad which wraps any kind of data with a `SecurityLevel`
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
    /// Constructor. Note that it makes no mention of S
    pub fn new(data: A) -> Self {
        Sec { data, security_level: PhantomData }
    }
    
    /// Maps a function over a `Sec` and returns a new `Sec` with the same security level.
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
    
    /// Flat maps a function over `Sec`, resulting in a new `Sec` of the same security level
    pub fn and_then<B, F>(self, f: F) -> Sec<S, B> 
    where 
        F: FnOnce(A) -> Sec<S, B> 
    {
        let Sec { data, .. } = self;
        f(data)
    }
    
    /// Reveal returns the value from within a `Sec`.
    /// Note that in order to do so, it must be supplied with a security level &geq; the `Sec`'s
    pub fn reveal<S2>(self, _: S2) -> A 
    where 
        S2: sl::SecurityLevel<S> + sl::SecurityLevel
    {
        self.data
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
