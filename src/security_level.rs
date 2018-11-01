//! Security levels are a way of tracking the level of security of a given object.
//! A security level can be anything, so long as it implements the `SecurityLevel` trait.
//! 
//! This library provides two example security levels: `Low` and `High`, though one could reasonably implement something like `User`, `Moderator`, and `Administrator`.
//! 
//! Note that the security levels are only really used for their types, and thus do not have any functionality.

use std::fmt::Debug;

/// SecurityLevel encodes both the relation (L &leq; H) and the fact that something can **be** a security level.
/// 
/// `LessThan` represents a security level lower than the current one.
pub trait SecurityLevel<LessThan = Self>: Debug
where
    LessThan: SecurityLevel,
{
}

/// Low security level (L in Haskell's SecLib)
#[derive(Debug)]
pub struct Low;

/// High Security level (H in Haskell's SecLib)
#[derive(Debug)]
pub struct High;

/// Implements L &leq; L at the type level
impl SecurityLevel for Low {}

/// Implements L &leq; H at the type level
impl SecurityLevel<Low> for High {}

/// Implements H &leq; H at the type level
impl SecurityLevel for High {}