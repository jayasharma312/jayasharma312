package com.example.demo;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

public class PkceAuthorizationRequestResolver implements OAuth2AuthorizationRequestResolver {

    public static final String PKCE_CODE_VERIFIER_SESSION_ATTR = "PKCE_CODE_VERIFIER";
    private final DefaultOAuth2AuthorizationRequestResolver defaultResolver;
    private final SecureRandom secureRandom = new SecureRandom();
    public PkceAuthorizationRequestResolver(ClientRegistrationRepository clientRegistrationRepository, String authorizationRequestBaseUri) {
        this.defaultResolver = new DefaultOAuth2AuthorizationRequestResolver(clientRegistrationRepository, authorizationRequestBaseUri);
    }

    @Override
    public OAuth2AuthorizationRequest resolve(HttpServletRequest request) {
        OAuth2AuthorizationRequest authrequest = defaultResolver.resolve(request);
        return customize(authrequest, request);
    }

    @Override
    public OAuth2AuthorizationRequest resolve(HttpServletRequest request, String clientRegistrationId) {
        OAuth2AuthorizationRequest authrequest = defaultResolver.resolve(request, clientRegistrationId);
        return customize(authrequest, request);
    }

    private OAuth2AuthorizationRequest customize(OAuth2AuthorizationRequest authrequest, HttpServletRequest request) {
        if(Objects.isNull(authrequest)) {
            return null;
        }
        if (authrequest.getAdditionalParameters().containsKey("code_challenge")) {
            return authrequest;
        }
        String codeVerifier = generateCodeVerifier();
        String codeChallenge = createCodeChallenge(codeVerifier);

        // Store code_verifier in session using state as key
        String state = authrequest.getState();
        request.getSession().setAttribute("PKCE_CODE_VERIFIER_" + state, codeVerifier);

        Map<String, Object> extraParams = new HashMap<String, Object>(authrequest.getAdditionalParameters());
        extraParams.put("code_challenge", codeChallenge);
        extraParams.put("code_challenge_method", "S256");

        return OAuth2AuthorizationRequest.from(authrequest)
                .additionalParameters(extraParams)
                .build();
    }

    private String generateCodeVerifier() {
        byte[] randomBytes = new byte[64];
        secureRandom.nextBytes(randomBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    }

    private String createCodeChallenge(String codeVerifier) {
        try {
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
            byte[] digest = messageDigest.digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 required for PKCE code challenge", e);
        }
    }
}
