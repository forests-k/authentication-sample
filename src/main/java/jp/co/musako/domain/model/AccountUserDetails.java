package jp.co.musako.domain.model;

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.ToString;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.List;

@Data
@EqualsAndHashCode(callSuper = true)
@ToString(callSuper = true)
public class AccountUserDetails extends User {

    public AccountUserDetails(String username, String password, String authenticationKey, List<GrantedAuthority> authorities) {
        super(username, password, authorities);
        this.authenticationKey = authenticationKey;
    }

    private String authenticationKey;
}
