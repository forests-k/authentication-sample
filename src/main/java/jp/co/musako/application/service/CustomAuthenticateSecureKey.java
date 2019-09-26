package jp.co.musako.application.service;

import org.springframework.stereotype.Service;

import javax.xml.bind.DatatypeConverter;
import java.security.SecureRandom;

@Service
public class CustomAuthenticateSecureKey {

    public String createSecureKey() {
        var random = new SecureRandom();
        var bytes = new byte[256];
        random.nextBytes(bytes);
        return DatatypeConverter.printHexBinary(bytes);
    }
}
