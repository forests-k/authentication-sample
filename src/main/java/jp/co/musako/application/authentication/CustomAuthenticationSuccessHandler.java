package jp.co.musako.application.authentication;

import jp.co.musako.domain.model.AccountUserDetails;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.WebAttributes;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

@Component
@Slf4j
public class CustomAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private static final String API_KEY_NAME = "X-AUTH-TOKEN";

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response, Authentication authentication)
            throws IOException, ServletException {

        if (response.isCommitted()) {
            return;
        }

        addAuthenticationKey(response, authentication);
        response.setStatus(HttpStatus.OK.value());
        clearAuthenticationAttribute(request);
    }

    private void clearAuthenticationAttribute(HttpServletRequest request) {
        HttpSession session = request.getSession(false);

        if (session == null) return;

        session.removeAttribute(WebAttributes.AUTHENTICATION_EXCEPTION);
    }

    private void addAuthenticationKey(HttpServletResponse response, Authentication authentication) {
        // 認証成功時に、認証キーをリクエストヘッダーに付与
        if (authentication.getPrincipal() != null && authentication.getPrincipal() instanceof AccountUserDetails) {
            AccountUserDetails userDetails = (AccountUserDetails) authentication.getPrincipal();
            response.addHeader(API_KEY_NAME, userDetails.getAuthenticationKey());
        }
    }
}
