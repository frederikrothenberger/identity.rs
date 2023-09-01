use core::fmt::Display;
use core::fmt::Formatter;
use core::fmt::Result;

/// Supported Elliptic Curves.
/// [IETF Draft](https://datatracker.ietf.org/doc/draft-ietf-cose-bls-key-representations/)
/// [More Info](https://www.iana.org/assignments/jose/jose.xhtml#web-key-elliptic-curve)
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub enum BlsCurve {
  /// BLS12-381 Curve.
  Bls12381G1,
}

impl BlsCurve {
  pub const fn name(self) -> &'static str {
    match self {
      Self::Bls12381G1 => "Bls12381G1",
    }
  }
}

impl Display for BlsCurve {
  fn fmt(&self, f: &mut Formatter<'_>) -> Result {
    f.write_str(self.name())
  }
}
