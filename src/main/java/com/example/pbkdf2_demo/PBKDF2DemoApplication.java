package com.example.pbkdf2_demo;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

public class PBKDF2DemoApplication {
    static Logger logger = LoggerFactory.getLogger(PBKDF2DemoApplication.class);
    private static final String CRYPTOGRAPHIC_ALGORITHM = "PBKDF2WithHmacSHA512";
    private static final String RANDOM_NUMBER_GENERATOR_ALGORITHM = "SHA1PRNG";
    private static String SPLIT_CHAR = ":";
    private static int RADIX = 16;
    private static int KEY_LENGTH = 64;
    private static int KEY_LENGTH_MULTIPLIER = 8;

    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException {
        String originalPassword = "password";
        String securedPassword = generateSecuredPassword(originalPassword);
        logger.info(securedPassword);

        boolean matched = validatePassword(originalPassword, securedPassword);
        logger.info("Should be true: {}", String.valueOf(matched));

        matched = validatePassword("wr0ngPassw0rd", securedPassword);
        logger.info("Should be false: {}", String.valueOf(matched));
    }

    // The secured password can be obtained from the DB. IF we save it during generateStrongPasswordHash()
    private static boolean validatePassword(String evaluatedPassword, String securedPassword)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        String[] securedPasswordParts = securedPassword.split(SPLIT_CHAR);
        int iterations = Integer.parseInt(securedPasswordParts[0]);
        byte[] securedPasswordSalt = fromHex(securedPasswordParts[1]);
        byte[] securedPasswordHash = fromHex(securedPasswordParts[2]);

        PBEKeySpec spec = new PBEKeySpec(evaluatedPassword.toCharArray(), securedPasswordSalt, iterations,
                securedPasswordHash.length * KEY_LENGTH_MULTIPLIER);
        SecretKeyFactory skf = SecretKeyFactory.getInstance(CRYPTOGRAPHIC_ALGORITHM);
        byte[] testHash = skf.generateSecret(spec).getEncoded();
        int diff = securedPasswordHash.length ^ testHash.length;
        for (int i = 0; i < securedPasswordHash.length && i < testHash.length; i++) {
            diff |= securedPasswordHash[i] ^ testHash[i];
        }
        return diff == 0;
    }

    private static String generateSecuredPassword(String password)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        int iterations = 1000;
        char[] chars = password.toCharArray();
        byte[] salt = getSalt();

        PBEKeySpec spec = new PBEKeySpec(chars, salt, iterations, KEY_LENGTH * KEY_LENGTH_MULTIPLIER);
        SecretKeyFactory skf = SecretKeyFactory.getInstance(CRYPTOGRAPHIC_ALGORITHM);
        byte[] hash = skf.generateSecret(spec).getEncoded();

        //It can be stored in a DB
        return iterations + SPLIT_CHAR + toHex(salt) + SPLIT_CHAR + toHex(hash);
    }

    private static byte[] getSalt() throws NoSuchAlgorithmException {
        SecureRandom sr = SecureRandom.getInstance(RANDOM_NUMBER_GENERATOR_ALGORITHM);
        byte[] salt = new byte[RADIX];
        sr.nextBytes(salt);
        return salt;
    }

    private static String toHex(byte[] array) {
        BigInteger bi = new BigInteger(1, array);
        String hex = bi.toString(RADIX);
        int paddingLength = (array.length * 2) - hex.length();
        if (paddingLength > 0) {
            return String.format("%0" + paddingLength + "d", 0) + hex;
        } else {
            return hex;
        }
    }

    private static byte[] fromHex(String hex) {
        byte[] bytes = new byte[hex.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) Integer.parseInt(hex.substring(2 * i, 2 * i + 2), RADIX);
        }
        return bytes;
    }
}
