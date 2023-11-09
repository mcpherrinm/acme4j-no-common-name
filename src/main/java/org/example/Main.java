package org.example;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.shredzone.acme4j.AccountBuilder;
import org.shredzone.acme4j.Session;
import org.shredzone.acme4j.Status;
import org.shredzone.acme4j.challenge.Dns01Challenge;
import org.shredzone.acme4j.util.KeyPairUtils;

import java.io.IOException;
import java.security.KeyPair;
import java.security.Security;
import java.util.Arrays;

// Press Shift twice to open the Search Everywhere dialog and type `show whitespaces`,
// then press Enter. You can now see whitespace characters in your code.
public class Main {
    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        var session = new Session(args[0]);
        // TODO: You usually want to save and reuse this.
        // https://shredzone.org/maven/acme4j/usage/account.html
        var accountKeyPair = KeyPairUtils.createECKeyPair("secp256r1");
        var account = new AccountBuilder().agreeToTermsOfService().useKeyPair(accountKeyPair).create(session);

        var domains = Arrays.copyOfRange(args, 1, args.length);
        var order = account.newOrder().domains(domains).create();

        for (var auth : order.getAuthorizations()) {
            if (auth.getStatus() == Status.PENDING) {
                var dnsChallenge = auth.findChallenge(Dns01Challenge.class).orElseThrow();
                var rr = Dns01Challenge.toRRName(auth.getIdentifier());
                var digest = dnsChallenge.getDigest();
                System.out.printf("Set %s to %s\n", rr, digest);
                System.in.read();
            }
        }
        System.out.println("triggering challenges");

        for(var auth : order.getAuthorizations()) {
            if(auth.getStatus() == Status.PENDING) {
                var dnsChallenge = auth.findChallenge(Dns01Challenge.class).orElseThrow();
                dnsChallenge.trigger();
            }
        }

        do {
            Thread.sleep(5000L);
            order.update();
        } while(order.getStatus() == Status.PENDING);
        System.out.printf("Status1: %s\n", order.getStatus());


        var certKeyPair = KeyPairUtils.createECKeyPair("secp256r1");
        var csr = makeCSR(domains, certKeyPair);

        order.execute(csr);

        do {
            Thread.sleep(1000L);
            order.update();
        } while(order.getStatus() == Status.PROCESSING);
        System.out.printf("Status2: %s\n", order.getStatus());
        if(order.getStatus() == Status.READY) {
            System.out.print(order.getCertificate().getCertificate());
        }
        System.out.print("done\n");
    }

    private static PKCS10CertificationRequest makeCSR(String[] domains, KeyPair keyPair) throws IOException, OperatorCreationException {
        var subjectAltNames = new GeneralNames(Arrays.stream(domains).map(
                f -> new GeneralName(GeneralName.dNSName, f)
        ).toArray(GeneralName[]::new));

        var egen = new ExtensionsGenerator();
        egen.addExtension(Extension.subjectAlternativeName, false, subjectAltNames);

        var emptySubject = new X500NameBuilder().build();

        var csr = new JcaPKCS10CertificationRequestBuilder(emptySubject, keyPair.getPublic())
                .addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, egen.generate())
                .build(new JcaContentSignerBuilder("SHA256withECDSA").build(keyPair.getPrivate()));
        return csr;
    }
}