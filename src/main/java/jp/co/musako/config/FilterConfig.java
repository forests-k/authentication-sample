package jp.co.musako.config;

import jp.co.musako.application.filter.LoggingFilter;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class FilterConfig {

    @Bean
    public FilterRegistrationBean loggingFilter() {
        var bean = new FilterRegistrationBean(new LoggingFilter());
        bean.addUrlPatterns("*");
        return bean;
    }
}
