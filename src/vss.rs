pub trait VerifiableSecretSharing {
    fn keygen();
    fn derive();
    fn encrypt();
    fn decrypt();
    fn reencrypt();
    fn verify();
    fn unverify();
}