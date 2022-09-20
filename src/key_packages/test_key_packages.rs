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
fn test_codec() {
    for ciphersuite in Config::supported_ciphersuites() {
        println!("Cipher {:?}", ciphersuite);
        let id = vec![1, 2, 3];
        let credential_bundle =
            CredentialBundle::new(id, CredentialType::Basic, ciphersuite.name().into()).unwrap();
        let mut kpb =
            KeyPackageBundle::new(&[ciphersuite.name()], &credential_bundle, Vec::new()).unwrap();

        let kp = kpb.key_package_mut();
        kp.add_extension(Box::new(LifetimeExtension::new(216000)));
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

#[test]
fn test_kp_p521_decode() {
    let kp:Vec<u8> = vec![1,0,5,0,133,4,0,253,37,88,251,93,189,177,68,36,124,243,144,74,31,127,136,253,198,232,151,18,144,145,106,40,105,90,235,4,254,15,137,29,167,168,46,15,142,56,41,36,22,12,237,94,45,118,64,18,48,57,87,219,130,222,195,96,183,13,129,198,161,118,35,60,0,113,26,239,215,86,37,44,97,109,92,110,239,89,161,111,28,223,247,124,6,207,178,245,186,43,199,30,119,73,25,82,148,84,116,162,64,147,72,117,216,116,151,108,213,179,253,75,203,104,216,191,217,174,199,47,207,205,179,129,255,120,211,3,92,240,0,1,0,10,105,115,105,109,49,50,109,105,110,105,6,3,0,133,4,1,61,6,184,213,52,218,250,211,183,94,241,159,236,214,125,13,119,126,110,89,194,55,94,209,9,0,248,105,130,58,231,28,50,105,37,27,216,37,102,90,30,29,52,16,70,196,41,67,168,104,71,205,114,92,129,11,38,229,215,92,122,24,228,26,132,0,52,187,98,97,8,144,103,126,20,169,102,200,248,74,94,91,53,210,200,201,56,22,241,9,157,19,81,184,137,75,10,244,74,248,11,165,28,246,78,109,165,167,6,59,9,11,210,165,42,39,57,148,178,145,70,246,70,41,225,83,146,160,68,13,5,0,0,0,36,0,1,0,12,1,1,2,0,5,6,0,1,0,2,0,3,0,2,0,16,0,0,0,0,99,41,177,132,0,0,0,0,99,152,125,148,0,132,1,161,98,32,184,209,31,71,189,216,189,143,241,26,15,73,0,68,132,86,81,185,246,97,35,182,215,208,28,186,207,83,255,212,175,69,132,167,23,202,10,222,109,75,134,53,235,144,88,196,231,19,167,181,231,165,192,34,239,246,31,26,246,17,158,50,1,95,149,217,56,222,128,202,174,26,185,241,14,171,68,74,90,50,102,15,68,24,187,214,149,183,219,1,88,35,58,31,151,136,52,118,161,249,136,233,2,214,168,138,201,3,156,177,216,21,207,114,196,196,178,38,73,234,201,52,179,43,1,67,161,82];

    let decoded = KeyPackage::decode(&mut Cursor::new(&kp));
    assert!(decoded.is_ok());
}
#[test]

fn test_kp_p256_decode() {
    let kp:Vec<u8> = vec![1,0,2,0,65,4,128,117,189,223,227,220,126,202,94,181,166,35,172,246,124,110,255,152,197,245,50,175,166,136,150,91,7,19,221,134,13,110,236,81,1,134,121,196,123,84,224,158,106,111,220,54,207,101,231,154,81,28,40,13,235,255,169,70,217,54,206,62,214,98,0,1,0,10,105,115,105,109,49,50,109,105,110,105,4,3,0,65,4,6,195,142,227,130,54,13,97,141,10,208,109,249,150,26,164,186,60,120,108,97,123,157,75,250,212,177,76,116,58,134,13,77,32,108,83,33,172,118,70,244,213,34,220,171,206,228,48,6,244,25,70,79,208,38,193,187,98,131,78,150,98,56,228,0,0,0,36,0,1,0,12,1,1,2,0,2,6,0,1,0,2,0,3,0,2,0,16,0,0,0,0,99,41,176,211,0,0,0,0,99,152,124,227,0,64,139,15,239,76,3,30,128,135,213,244,202,120,18,164,231,90,207,150,162,221,57,242,122,93,184,218,101,136,248,72,113,72,91,129,65,246,35,54,132,208,227,140,122,59,114,178,52,161,250,4,7,107,58,52,47,244,53,184,208,109,80,22,198,86];

    let decoded = KeyPackage::decode(&mut Cursor::new(&kp));
    assert!(decoded.is_ok());
}