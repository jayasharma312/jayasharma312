package com.example.demo;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

import org.springframework.http.RequestEntity;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequestEntityConverter;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import java.util.Arrays;

public class CustomAuthorizationCodeTokenResponseClient implements OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> {

    private static final String PKCE_SESSION_KEY_PREFIX = "PKCE_CODE_VERIFIER_";
    private final OAuth2AuthorizationCodeGrantRequestEntityConverter requestEntityConverter;
    private final RestTemplate restTemplate;

    public CustomAuthorizationCodeTokenResponseClient() {
        this.requestEntityConverter = new OAuth2AuthorizationCodeGrantRequestEntityConverter();
        this.restTemplate = new RestTemplate();
        this.restTemplate.setMessageConverters(Arrays.asList(
                new FormHttpMessageConverter(),
                new OAuth2AccessTokenResponseHttpMessageConverter()
        ));
    }

    @Override
    public OAuth2AccessTokenResponse getTokenResponse(OAuth2AuthorizationCodeGrantRequest authorizationGrantRequest) {
        // Get the state to look up the stored code_verifier
        String state = authorizationGrantRequest.getAuthorizationExchange()
                .getAuthorizationRequest().getState();

        // Retrieve code_verifier from session
        String codeVerifier = null;
        ServletRequestAttributes attr = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        if (attr != null) {
            HttpServletRequest request = attr.getRequest();
            HttpSession session = request.getSession(false);
            if (session != null) {
                Object val = session.getAttribute(PKCE_SESSION_KEY_PREFIX + state);
                if (val != null) {
                    codeVerifier = val.toString();
                    // Remove it after reading
                    session.removeAttribute(PKCE_SESSION_KEY_PREFIX + state);
                }
            }
        }

        // Convert the grant request to a RequestEntity
        RequestEntity<?> requestEntity = this.requestEntityConverter.convert(authorizationGrantRequest);

        if (requestEntity == null) {
            throw new IllegalStateException("Unable to create token request");
        }

        // If we have a code_verifier, add it to the request body
        if (codeVerifier != null) {
            MultiValueMap<String, String> body = (MultiValueMap<String, String>) requestEntity.getBody();
            if (body != null) {
                body = new org.springframework.util.LinkedMultiValueMap<>(body);
                body.add("code_verifier", codeVerifier);

                requestEntity = RequestEntity
                        .method(requestEntity.getMethod(), requestEntity.getUrl())
                        .headers(requestEntity.getHeaders())
                        .body(body);
            }
        }

        // Execute the token request
        return this.restTemplate.exchange(requestEntity, OAuth2AccessTokenResponse.class).getBody();
    }
}