package com.gft.oauth2.configuration;

import com.gft.oauth2.configuration.jwt.TokenEnhancerCustom;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;

import java.util.Arrays;

/**
 * OAuth2 Server Configuration. Includes JWT configuration and clients
 * available.
 * <p>
 * This link was helpful during the configuration of this class:
 * - http://www.baeldung.com/spring-security-oauth-jwt
 *
 * @author Ruben Jimenez
 * @author Manuel Yepez
 * @Author Riccardo Bove
 */
@Configuration
public class OAuth2Configuration extends AuthorizationServerConfigurerAdapter {

    // Keystore password
    @Value("${gft.oauth2.keystore.password}")
    private String keystorePassword;

    // Authentication Manager bean
    @Autowired
    @Qualifier("authenticationManagerBean")
    private AuthenticationManager authenticationManager;

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.inMemory()
                .withClient("app")
                .secret("app-secret-password")
                // TODO Determine if scopes are needed or if we could just go
                // with authorities.
                .scopes(
                        "EMPLOYEE",
                        "APPRAISAL")
                .autoApprove(true)
                .authorities(
                        "EMPLOYEE_READ",
                        "EMPLOYEE_WRITE",
                        "EMPLOYEE_ADMIN",
                        "APPRAISAL_READ",
                        "APPRAISAL_WRITE",
                        "APPRAISAL_ADMIN")
                .authorizedGrantTypes("authorization_code", "refresh_token");
    }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        TokenEnhancerChain tokenEnhancerChain = new TokenEnhancerChain();
        tokenEnhancerChain.setTokenEnhancers(
                Arrays.asList(
                        customTokenEnhancer(),
                        accessTokenConverter()));

        endpoints.tokenStore(tokenStore())
                .tokenEnhancer(tokenEnhancerChain)
                .authenticationManager(authenticationManager);
    }

    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        security.tokenKeyAccess("permitAll()")
                .checkTokenAccess("isAuthenticated()");
    }

    /**
     * TODO Document this!!
     *
     * @return
     */
    @Bean
    public TokenEnhancer customTokenEnhancer() {
        return new TokenEnhancerCustom();
    }

    /**
     * TODO Document this!
     *
     * @return
     */
    @Bean
    public TokenStore tokenStore() {
        return new JwtTokenStore(accessTokenConverter());
    }

    /**
     * TODO Document this!
     *
     * @return
     */
    @Bean
    protected JwtAccessTokenConverter accessTokenConverter() {
        KeyStoreKeyFactory keyStoreKeyFactory = new KeyStoreKeyFactory(
                new ClassPathResource("jwt.jks"),
                keystorePassword.toCharArray());
        JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
        converter.setKeyPair(keyStoreKeyFactory.getKeyPair("jwt"));
        return converter;
    }

    /**
     * TODO Document this!
     *
     * @return
     */
    @Bean
    @Primary
    public DefaultTokenServices tokenServices() {
        DefaultTokenServices defaultTokenServices = new DefaultTokenServices();
        defaultTokenServices.setTokenStore(tokenStore());
        defaultTokenServices.setSupportRefreshToken(true);
        return defaultTokenServices;
    }
}
