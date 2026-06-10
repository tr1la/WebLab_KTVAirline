package org.example.security;

public interface Constants {
    public static final String SECRET = "ThisISAVeryStrongandSecretKeyThisISAVeryStrongandSecretKey";
    public static final long EXPIRATION_TIME = 1800000; // 15 mins
    public static final String TOKEN_PREFIX = "Bearer ";
    public static final String HEADER_STRING = "Authorization";
    public static final String SIGN_UP_URL = "/user";
}
