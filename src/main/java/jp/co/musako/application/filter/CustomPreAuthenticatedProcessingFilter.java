package jp.co.musako.application.filter;

import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;

import javax.servlet.http.HttpServletRequest;

public class CustomPreAuthenticatedProcessingFilter extends AbstractPreAuthenticatedProcessingFilter {

    private static final String API_KEY_NAME = "X-AUTH-TOKEN";

    @Override
    public String getPreAuthenticatedCredentials(HttpServletRequest request) {

        return request.getHeader(API_KEY_NAME) == null ? "" : request.getHeader(API_KEY_NAME);
    }

    @Override
    public Object getPreAuthenticatedPrincipal(HttpServletRequest request) {
        return "";
    }
}
