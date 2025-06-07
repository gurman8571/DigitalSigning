package com.cloudmaveninc.Document.Signing.service;
import com.azure.identity.DefaultAzureCredentialBuilder;
import com.azure.security.keyvault.certificates.CertificateClient;
import com.azure.security.keyvault.certificates.CertificateClientBuilder;
import com.azure.security.keyvault.keys.cryptography.CryptographyClient;
import com.azure.security.keyvault.keys.cryptography.CryptographyClientBuilder;
import com.azure.security.keyvault.keys.cryptography.models.SignResult;
//Base interface for objects that can be ASN.1 encoded.
import org.bouncycastle.asn1.ASN1Encodable;
//Mutable list for assembling ASN.1 sequences or sets.
import org.bouncycastle.asn1.ASN1EncodableVector;
//Encodes raw bytes as a DER-compliant ASN.1 OCTET STRING
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERUTCTime;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerIdentifier;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.util.encoders.Hex;

import org.slf4j.LoggerFactory;
import org.slf4j.Logger;
import org.springframework.stereotype.Service;
import org.springframework.core.env.Environment;

import java.io.ByteArrayInputStream;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

@Service
public class AzureSigner {
    private static final Logger logger = LoggerFactory.getLogger(AzureSigner.class);
    private   final Environment env;

    public AzureSigner(Environment env) {
        this.env = env;
    }



    public byte[] signWithAzure(String base64Input) throws Exception {

        String vaultUrl = env.getProperty("app.keyvault.URL");
        String certName = env.getProperty("app.certificate.name");
        //--Client sends the  ByteRange, base64 encoded
        byte[] byteRangeData = Base64.getDecoder().decode(base64Input);

        //---Fetch certificate from Azure Key Vault
        CertificateClient certClient = new CertificateClientBuilder()
                .vaultUrl(vaultUrl)
                .credential(new DefaultAzureCredentialBuilder().build())
                .buildClient();

        //---typecast to  X509Certificate
        X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(certClient.getCertificate(certName).getCer()));

        //--- wrapper for an X.509 certificate in ASN.1 forma
        X509CertificateHolder certHolder = new X509CertificateHolder(cert.getEncoded());

        // 2. Hash ByteRange content ---- byte range which will be signed
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] byteRangeDigest = sha256.digest(byteRangeData);

        // 3. Create signedAttrs --- Holds the list of signed attributes to be included in the SignerInfo
        ASN1EncodableVector signedAttrs = new ASN1EncodableVector();

        //--- Adds an attribute indicating the type of content being signed
        signedAttrs.add(new Attribute(
                PKCSObjectIdentifiers.pkcs_9_at_contentType,
                new DERSet(PKCSObjectIdentifiers.data)
        ));
        //--- Embeds the SHA-256 hash of the ByteRange (i.e., the content that was signed).
        signedAttrs.add(new Attribute(
                PKCSObjectIdentifiers.pkcs_9_at_messageDigest,
                new DERSet(new DEROctetString(byteRangeDigest))
        ));

        // signingTime attribute
        ASN1Encodable signingTime = new DERUTCTime(new java.util.Date());
        signedAttrs.add(new Attribute(
                PKCSObjectIdentifiers.pkcs_9_at_signingTime,
                new DERSet(signingTime)
        ));

        DERSet signedAttrSet = new DERSet(signedAttrs);
        byte[] encodedSignedAttrs = signedAttrSet.getEncoded("DER");

        // 4. Sign SHA-256 of encoded signed attributes using azure
        byte[] signedAttrDigest = sha256.digest(encodedSignedAttrs);
        logger.info("Digest being signed: {}", Hex.toHexString(signedAttrDigest));

        String keyId = certClient.getCertificate(certName).getKeyId();
        CryptographyClient cryptoClient = new CryptographyClientBuilder()
                .keyIdentifier(keyId)
                .credential(new DefaultAzureCredentialBuilder().build())
                .buildClient();

        SignResult signature = cryptoClient.sign(
                com.azure.security.keyvault.keys.cryptography.models.SignatureAlgorithm.RS256,
                signedAttrDigest
        );

        // 5. Build CMS structure
        SignerIdentifier signerId = new SignerIdentifier(
                new IssuerAndSerialNumber(certHolder.getIssuer(), certHolder.getSerialNumber())
        );

        AlgorithmIdentifier digestAlgId = new DefaultDigestAlgorithmIdentifierFinder().find("SHA-256");
        AlgorithmIdentifier sigAlgId = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha256WithRSAEncryption);

        SignerInfo signerInfo = new SignerInfo(
                signerId,
                digestAlgId,
                signedAttrSet,
                sigAlgId,
                new DEROctetString(signature.getSignature()),
                null
        );

        DERSet certs = new DERSet(certHolder.toASN1Structure());
        DERSet signers = new DERSet(signerInfo);
        DERSet digests = new DERSet(digestAlgId);

        SignedData signedData = new SignedData(
                digests,
                new ContentInfo(PKCSObjectIdentifiers.data, null),
                certs,
                null,
                signers
        );

        ContentInfo pkcs7 = new ContentInfo(PKCSObjectIdentifiers.signedData, signedData);


        // Return binary PKCS#7
        return pkcs7.getEncoded();
    }
}

