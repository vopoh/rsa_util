package com.company;

import java.security.KeyPair;

import static com.company.EncryptionUtils.decrypt;
import static com.company.EncryptionUtils.encrypt;
import static com.company.KeyPairGenerationUtils.generateKeyPair;
import static com.company.SignatureUtils.sign;
import static com.company.SignatureUtils.verify;

public class RsaExample {

    public static void main(String... argv) throws Exception {
        //First generate a public/private key pair
        KeyPair pair = generateKeyPair();
        //KeyPairGenerationUtils pair = getKeyPairFromKeyStore();

        //Our secret message
        String message = "меня зовут Антон";

        //Encrypt the message
        String cipherText = encrypt(message, pair.getPublic());

        //Now decrypt it
        String decipheredMessage = decrypt(cipherText, pair.getPrivate());

        System.out.println(decipheredMessage);

        //Let's sign our message
        String signature = sign("12345", pair.getPrivate());

        //Let's check the signature
        boolean isCorrect = verify("12345", signature, pair.getPublic());
        System.out.println("Подпись правильная: " + isCorrect);

    }

}
