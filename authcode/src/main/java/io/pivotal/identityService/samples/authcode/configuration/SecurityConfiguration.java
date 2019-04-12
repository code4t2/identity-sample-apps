package io.pivotal.identityService.samples.authcode.configuration;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {
    @Value("${ssoServiceUrl:placeholder}")
    String ssoServiceUrl;

    @Value("${spring.security.oauth2.client.registration.sso.client-id:placeholder}")
    String clientId;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                    .antMatchers("/").permitAll()
                    .anyRequest().authenticated()
                .and()
                .oauth2Login()
                .and()
                .logout()
//                    .logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET"))
                    .logoutSuccessUrl(getLogoutUrl())
        ;
    }

    // TODO: Add redirect, also
    private String getLogoutUrl() {
        return String.format("%s/logout.do?client_id=%s", ssoServiceUrl, clientId);
    }
}
