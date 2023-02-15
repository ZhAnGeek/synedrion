use core::marker::PhantomData;

use rand_core::{CryptoRng, RngCore};

use crate::paillier::{PaillierParams, PublicKeyPaillier, SecretKeyPaillier};
use crate::tools::hashing::{Chain, Hashable, XofHash};

#[derive(Clone)]
pub(crate) struct FacProof<P: PaillierParams>(PhantomData<P>);

impl<P: PaillierParams> FacProof<P> {
    pub fn random(
        _rng: &mut (impl RngCore + CryptoRng),
        _sk: &SecretKeyPaillier<P>,
        _aux: &impl Hashable,
    ) -> Self {
        Self(PhantomData)
    }

    pub fn verify(&self) -> bool {
        true
    }
}
