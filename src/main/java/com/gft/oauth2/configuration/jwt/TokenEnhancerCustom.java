package com.gft.oauth2.configuration.jwt;

import com.gft.oauth2.configuration.saml.SAMLUser;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;

import java.util.HashMap;
import java.util.Map;

public class TokenEnhancerCustom implements TokenEnhancer {

    @Override
    public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
        // Get Principal from Spring
        SAMLUser user = (SAMLUser) authentication.getUserAuthentication()
                .getPrincipal();
        // Add first and last name to the token's additional information
        Map<String, Object> additionalInfo = new HashMap<>();
        additionalInfo.put("first_name",
                user.getFirstName());
        additionalInfo.put("last_name",
                user.getLastName());
        ((DefaultOAuth2AccessToken) accessToken).setAdditionalInformation(additionalInfo);
        return accessToken;
    }
}
