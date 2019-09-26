package jp.co.musako.application.repository;

import jp.co.musako.domain.model.Account;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class AccountRepository {

    @Autowired
    private PasswordEncoder passwordEncoder;

    public Optional<Account> findByUserName(String username) {
        var account = new Account();
        account.setId(1);
        account.setUserName(username);
        account.setPassword(passwordEncoder.encode("password"));
        return Optional.ofNullable(account);
    }

    public Optional<Account> findByAuthenticationKey(String authenticationKey) {
        var account = new Account();
        account.setId(1);
        account.setUserName("testUser");
        account.setPassword(passwordEncoder.encode("password"));
        return Optional.ofNullable(account);
    }
}
