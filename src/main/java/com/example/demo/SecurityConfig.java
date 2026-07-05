package com.example.demo;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import java.io.IOException;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Bean
    SecurityFilterChain filterChain(HttpSecurity http, ClientRegistrationRepository clients) throws Exception {
        PkceAuthorizationRequestResolver resolver =
                new PkceAuthorizationRequestResolver(clients, "/oauth2/authorization");

        CustomAuthorizationCodeTokenResponseClient tokenResponseClient =
                new CustomAuthorizationCodeTokenResponseClient();

        http
                .authorizeHttpRequests(a -> a
                        .requestMatchers("/", "/home").authenticated()
                        .anyRequest().permitAll()
                )
                .oauth2Login(oauth2 -> oauth2
                        .successHandler(authenticationSuccessHandler())
                        .redirectionEndpoint(redir ->
                                redir.baseUri("/authorization-code/callback"))
                        .authorizationEndpoint(auth -> auth
                                .authorizationRequestResolver(resolver)
                        )
                        .tokenEndpoint(token -> token
                                .accessTokenResponseClient(tokenResponseClient)
                        )
                )
                .logout(logout -> logout
                        .logoutSuccessUrl("/")
                        .invalidateHttpSession(true)
                        .clearAuthentication(true)
                );

//        http
//                .authorizeHttpRequests(a -> a
//                        .requestMatchers("/").authenticated()   // protect /
//                        .anyRequest().permitAll()
//                )
//                .oauth2Login(oauth2 -> oauth2
//                        // tell Spring which base URI to expect for callbacks
//                        .redirectionEndpoint(redir -> redir.baseUri("/authorization-code/callback"))
//                );
        return http.build();

    }

    @Bean
    public AuthenticationSuccessHandler authenticationSuccessHandler() {
        return new AuthenticationSuccessHandler() {
            @Override
            public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                                Authentication authentication) throws IOException, ServletException {
                response.sendRedirect("/");
            }
        };
    }
}