package jp.co.musako.application.service;

import jp.co.musako.application.repository.AccountRepository;
import jp.co.musako.domain.model.Account;
import jp.co.musako.domain.model.AccountUserDetails;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Arrays;

@Slf4j
@Service("customUserDetailsService")
public class CustomUserDetailsService implements UserDetailsService {

    @Autowired
    private AccountRepository accountRepository;

    @Autowired
    private CustomAuthenticateSecureKey customAuthenticateSecureKey;

    @Override
    public AccountUserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        try {
            var account = accountRepository.findByUserName(username);
            return account
                    .map((Account a) ->
                            new AccountUserDetails(
                                    a.getUserName(),
                                    a.getPassword(),
                                    customAuthenticateSecureKey.createSecureKey(),
                                    Arrays.asList(new SimpleGrantedAuthority("USER_ROLE")))
                    )
                    .orElseThrow(() -> new UsernameNotFoundException("not found username"));
        } catch (Exception e) {
            log.error("username not found error", e);
            throw e;
        }
    }
}
