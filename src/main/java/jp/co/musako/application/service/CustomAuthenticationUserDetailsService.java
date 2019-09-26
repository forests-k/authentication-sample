package jp.co.musako.application.service;


import jp.co.musako.application.repository.AccountRepository;
import jp.co.musako.domain.model.Account;
import jp.co.musako.domain.model.AccountUserDetails;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.stereotype.Service;

import java.util.Arrays;

@Service
public class CustomAuthenticationUserDetailsService implements AuthenticationUserDetailsService<PreAuthenticatedAuthenticationToken> {

    @Autowired
    private AccountRepository accountRepository;

    @Override
    public UserDetails loadUserDetails(PreAuthenticatedAuthenticationToken token) throws UsernameNotFoundException {

        var credential = token.getCredentials();

        if (credential == null || "".equals(credential.toString())) {
            throw new UsernameNotFoundException("Invalid API Key");
        }

        var account = accountRepository.findByAuthenticationKey(credential.toString());
        return account
                .map((Account a) ->
                        new AccountUserDetails(
                                a.getUserName(),
                                a.getPassword(),
                                credential.toString(),
                                Arrays.asList(new SimpleGrantedAuthority("USER_ROLE")))
                )
                .orElseThrow(() -> new UsernameNotFoundException("not found username"));
    }
}
