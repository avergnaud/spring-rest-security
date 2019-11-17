package com.poc.tokenissuer.constants;

public final class SecurityConstants {

    /*
     * http://localhost:8080/api/authenticate?username=avergnaud&password=myPassword
     * */
    public static final String AUTH_LOGIN_URL = "/api/authenticate";

    /* Signing key for HS512 algorithm http://www.allkeysgenerator.com/ */
    public static final String JWT_SECRET = System.getenv().get("JWT_SECRET");
    static {
        if (JWT_SECRET == null) {
            throw new IllegalStateException("JWT_SECRET env variable not set");
        }
    }

    /* JWT token defaults */
    public static final String TOKEN_HEADER = "Authorization";
    public static final String TOKEN_PREFIX = "Bearer ";
    public static final String TOKEN_TYPE = "JWT";
    public static final String TOKEN_ISSUER = "poc.com.token-issuer";
    public static final String TOKEN_AUDIENCE = "poc.com";

    private SecurityConstants() {
        throw new IllegalStateException("Cannot create instance of static util class");
    }
}

