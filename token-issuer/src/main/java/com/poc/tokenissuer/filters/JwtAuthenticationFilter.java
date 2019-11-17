package com.poc.tokenissuer.filters;

import com.poc.tokenissuer.constants.SecurityConstants;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private static final Logger log = LoggerFactory.getLogger(JwtAuthenticationFilter.class);

    private final AuthenticationManager authenticationManager;

    public JwtAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;

        /*
        * AbstractAuthenticationProcessingFilter.setFilterProcessesUrl
        * Sets the URL that determines if authentication is required
        * */
        setFilterProcessesUrl(SecurityConstants.AUTH_LOGIN_URL);
    }

    /*
    Checks for username and password parameters from URL and calls Spring’s authentication manager to verify them.
    Performs actual authentication.
    The implementation should do one of the following:
    - Return a populated authentication token for the authenticated user, indicating successful authentication
    - Return null, indicating that the authentication process is still in progress. Before returning, the implementation should perform any additional work required to complete the process.
    - Throw an AuthenticationException if the authentication process fails
     */
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) {
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username, password);

        return authenticationManager.authenticate(authenticationToken);
    }

    /*
    If username and password are correct, then the filter will create a JWT token and returns it in HTTP Authorization header.
    Default behaviour for successful authentication.
    1. Sets the successful Authentication object on the SecurityContextHolder
    2. Informs the configured RememberMeServices of the successful login
    3. Fires an InteractiveAuthenticationSuccessEvent via the configured ApplicationEventPublisher
    4. Delegates additional behaviour to the AuthenticationSuccessHandler.
    Subclasses can override this method to continue the FilterChain after successful authentication.
     */
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                            FilterChain filterChain, Authentication authentication) {
        User user = ((User) authentication.getPrincipal());

        List<String> roles = user.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());

        byte[] signingKey = SecurityConstants.JWT_SECRET.getBytes();

        String token = Jwts.builder()
                .signWith(Keys.hmacShaKeyFor(signingKey), SignatureAlgorithm.HS512)
                .setHeaderParam("typ", SecurityConstants.TOKEN_TYPE)
                .setIssuer(SecurityConstants.TOKEN_ISSUER)
                .setAudience(SecurityConstants.TOKEN_AUDIENCE)
                .setSubject(user.getUsername())
                .setExpiration(new Date(System.currentTimeMillis() + 864000000))
                .claim("rol", roles)
                .compact();

        response.addHeader(SecurityConstants.TOKEN_HEADER, SecurityConstants.TOKEN_PREFIX + token);
    }

}
