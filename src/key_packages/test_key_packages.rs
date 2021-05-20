use crate::config::*;
use crate::{extensions::*, key_packages::*};

#[test]
fn generate_key_package() {
    for ciphersuite in Config::supported_ciphersuites() {
        let credential_bundle = CredentialBundle::new(
            vec![1, 2, 3],
            CredentialType::Basic,
            ciphersuite.name().into(),
        )
        .unwrap();

        // Generate a valid KeyPackage.
        let lifetime_extension = Box::new(LifetimeExtension::new(60));
        let kpb = KeyPackageBundle::new(
            &[ciphersuite.name()],
            &credential_bundle,
            vec![lifetime_extension],
        )
        .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(1));
        assert!(kpb.key_package().verify().is_ok());

        // Now we add an invalid lifetime.
        let lifetime_extension = Box::new(LifetimeExtension::new(0));
        let kpb = KeyPackageBundle::new(
            &[ciphersuite.name()],
            &credential_bundle,
            vec![lifetime_extension],
        )
        .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(1));
        assert!(kpb.key_package().verify().is_err());

        // Now with two lifetime extensions, the key package should be invalid.
        let lifetime_extension = Box::new(LifetimeExtension::new(60));
        let kpb = KeyPackageBundle::new(
            &[ciphersuite.name()],
            &credential_bundle,
            vec![lifetime_extension.clone(), lifetime_extension],
        );
        assert!(kpb.is_err());
    }
}

#[test]
fn test_decode() {

    let x: Vec<u8> = vec![1, 0, 1, 0, 32, 233, 225, 45, 96, 50, 7, 75, 121, 28, 140, 89, 215, 111, 55, 166, 168, 164, 6, 124, 157, 37, 235, 99, 56, 42, 121, 148, 240, 33, 48, 238, 2, 0, 1, 0, 3, 1, 2, 3, 8, 7, 0, 32, 109, 219, 27, 159, 140, 45, 160, 211, 153, 120, 220, 8, 54, 171, 34, 201, 124, 38, 64, 72, 236, 54, 49, 213, 133, 183, 92, 160, 169, 36, 132, 124, 0, 0, 0, 36, 0, 1, 0, 12, 1, 1, 2, 0, 1, 6, 0, 1, 0, 2, 0, 3, 0, 2, 0, 16, 0, 0, 0, 0, 96, 163, 140, 89, 0, 0, 0, 0, 96, 163, 154, 165, 0, 64, 222, 208, 167, 161, 31, 219, 173, 162, 199, 7, 142, 53, 171, 17, 80, 57, 127, 84, 122, 167, 192, 111, 21, 191, 167, 144, 18, 126, 15, 93, 90, 207, 107, 254, 109, 0, 213, 244, 66, 247, 112, 13, 70, 248, 118, 211, 73, 53, 58, 245, 239, 89, 64, 252, 155, 211, 61, 44, 166, 244, 0, 242, 2, 11];

    let kp = KeyPackage::decode_detached(&x).unwrap();

    println!("Key Package: {:?}", kp);
}

#[test]
fn test_codec() {
    for ciphersuite in Config::supported_ciphersuites() {
        let id = vec![1, 2, 3];
        let credential_bundle =
            CredentialBundle::new(id, CredentialType::Basic, ciphersuite.name().into()).unwrap();
        let mut kpb =
            KeyPackageBundle::new(&[ciphersuite.name()], &credential_bundle, Vec::new()).unwrap();

        let kp = kpb.key_package_mut();
        kp.add_extension(Box::new(LifetimeExtension::new(600)));
        kp.sign(&credential_bundle);
        let enc = kpb.key_package().encode_detached().unwrap();

        println!("Encoded Key: {:?}", &enc);
        // Now it's valid.
        // let kp = KeyPackage::decode(&mut Cursor::new(&enc)).unwrap();
        let kp = KeyPackage::decode_detached(&enc).unwrap();
        println!("KEY_PACKAGE: {:?}", &kp);
        assert_eq!(kpb.key_package, kp);
    }
}

#[test]
fn key_package_id_extension() {
    for ciphersuite in Config::supported_ciphersuites() {
        let id = vec![1, 2, 3];
        let credential_bundle =
            CredentialBundle::new(id, CredentialType::Basic, ciphersuite.name().into()).unwrap();
        let mut kpb = KeyPackageBundle::new(
            &[ciphersuite.name()],
            &credential_bundle,
            vec![Box::new(LifetimeExtension::new(60))],
        )
        .unwrap();
        assert!(kpb.key_package().verify().is_ok());

        // Add an ID to the key package.
        let id = [1, 2, 3, 4];
        kpb.key_package_mut()
            .add_extension(Box::new(KeyIDExtension::new(&id)));

        // This is invalid now.
        assert!(kpb.key_package().verify().is_err());

        // Sign it to make it valid.
        kpb.key_package_mut().sign(&credential_bundle);
        assert!(kpb.key_package().verify().is_ok());

        // Check ID
        assert_eq!(&id[..], &kpb.key_package().key_id().expect("No key ID")[..]);
    }
}

#[test]
fn test_mismatch() {
    // === KeyPackageBundle negative test ===

    let ciphersuite_name = CiphersuiteName::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let signature_scheme = SignatureScheme::ECDSA_SECP256R1_SHA256;

    let credential_bundle =
        CredentialBundle::new(vec![1, 2, 3], CredentialType::Basic, signature_scheme)
            .expect("Could not create credential bundle");

    assert_eq!(
        KeyPackageBundle::new(&[ciphersuite_name], &credential_bundle, vec![],),
        Err(KeyPackageError::CiphersuiteSignatureSchemeMismatch)
    );

    // === KeyPackageBundle positive test ===

    let ciphersuite_name = CiphersuiteName::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let signature_scheme = SignatureScheme::ED25519;

    let credential_bundle =
        CredentialBundle::new(vec![1, 2, 3], CredentialType::Basic, signature_scheme)
            .expect("Could not create credential bundle");

    assert!(KeyPackageBundle::new(&[ciphersuite_name], &credential_bundle, vec![]).is_ok());
}
