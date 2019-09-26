package jp.co.musako.application.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import jp.co.musako.domain.model.Credential;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class CustomUsernamePasswordAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) {
        if (!HttpMethod.POST.name().equals(request.getMethod())) {
            throw new AuthenticationServiceException("Authentication method not supported: " + request.getMethod());
        }

        UsernamePasswordAuthenticationToken authRequest = null;
        try {
            var sb = new StringBuffer();
            String line = null;

            var reader = request.getReader();
            while ((line = reader.readLine()) != null) {
                sb.append(line);
            }

            var mapper = new ObjectMapper();
            var credential = mapper.readValue(sb.toString(), Credential.class);

            authRequest = new UsernamePasswordAuthenticationToken(credential.getUsername(), credential.getPassword());

            setDetails(request, authRequest);
        } catch (Exception e) {
            setDetails(request, new UsernamePasswordAuthenticationToken("anymouse", ""));
        }

        return super.getAuthenticationManager().authenticate(authRequest);
    }
}
