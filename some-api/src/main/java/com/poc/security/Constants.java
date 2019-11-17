package com.poc.security;

public class Constants {

    /*
    Signing key for HS512 algorithm http://www.allkeysgenerator.com/
    same env variable as token issuer (authorization server)
    */
    public static final String JWT_SECRET = System.getenv().get("JWT_SECRET");
    static {
        if (JWT_SECRET == null || JWT_SECRET.equals("")) {
            throw new IllegalStateException("JWT_SECRET env variable not set");
        }
    }
}
