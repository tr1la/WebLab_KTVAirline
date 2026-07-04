package org.example.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

@Configuration
@EnableMethodSecurity
@EnableWebSecurity
public class WebSecurityConfig {
    @Autowired
    UserDetailsServiceImpl userDetailsService;

    @Autowired
    private AuthEntryPointJwt unauthorizedHandler;

    @Bean
    public AuthTokenFilter authenticationJwtTokenFilter() {
        return new AuthTokenFilter();
    }

    @Bean
    public DaoAuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
        return authConfig.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOriginPatterns(Arrays.asList(
                "http://localhost:*",
                "http://127.0.0.1:*"
        ));
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(Arrays.asList("Authorization", "Content-Type", "X-Requested-With"));
        configuration.setAllowCredentials(true);
        configuration.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            .csrf(csrf -> csrf.disable())
            .exceptionHandling(exception -> exception.authenticationEntryPoint(unauthorizedHandler))
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth ->
                auth.requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                    .requestMatchers("/v3/**", "/swagger-ui/**", "/swagger-ui", "/swagger-ui.html", "/uploads/**").permitAll()
                    .requestMatchers(HttpMethod.GET, "/api/v1/profile/basic-info").hasAnyRole("USER", "ADMIN")
                    .requestMatchers(HttpMethod.POST, "/api/v1/auth/login", "/api/v1/auth/signup", "/api/v1/auth/forgetP").permitAll()
                    .requestMatchers(HttpMethod.GET,
                            "/api/v1/news/**",
                            "/api/v1/promotion/**",
                            "/api/v1/flight/**",
                            "/api/v1/plane/**",
                            "/api/v1/seat/**",
                            "/api/v1/transaction/flight/availability").permitAll()
                    .requestMatchers(HttpMethod.PUT, "/api/v1/auth/changeP").hasAnyRole("USER", "ADMIN")
                    .requestMatchers(HttpMethod.GET, "/api/v1/user/email", "/api/v1/user/id").hasAnyRole("USER", "ADMIN")
                    .requestMatchers(HttpMethod.POST, "/api/v1/user/*/avatar").hasAnyRole("USER", "ADMIN")
                    .requestMatchers(HttpMethod.PUT, "/api/v1/user").hasAnyRole("USER", "ADMIN")
                    .requestMatchers(HttpMethod.GET, "/api/v1/user/all").hasRole("ADMIN")
                    .requestMatchers(HttpMethod.DELETE, "/api/v1/user").hasRole("ADMIN")
                    .requestMatchers(HttpMethod.GET, "/api/v1/transaction/all", "/api/v1/transaction/status").hasRole("ADMIN")
                    .requestMatchers(HttpMethod.GET,
                            "/api/v1/transaction/conditions",
                            "/api/v1/transaction/id",
                            "/api/v1/transaction/flight",
                            "/api/v1/transaction/flight/availability").hasAnyRole("USER", "ADMIN")
                    .requestMatchers(HttpMethod.PUT, "/api/v1/transaction", "/api/v1/transaction/list").hasAnyRole("USER", "ADMIN")
                    .requestMatchers(HttpMethod.POST, "/api/v1/transaction").hasRole("ADMIN")
                    .requestMatchers(HttpMethod.DELETE, "/api/v1/transaction").hasRole("ADMIN")
                    .requestMatchers(HttpMethod.POST,
                            "/api/v1/booking/quote",
                            "/api/v1/booking/hold",
                            "/api/v1/booking/apply-promotion",
                            "/api/v1/booking/confirm",
                            "/api/v1/booking/draft/save",
                            "/api/v1/booking/draft/import").hasAnyRole("USER", "ADMIN")
                    .requestMatchers(HttpMethod.POST, "/api/v1/promotion/import-xml").hasRole("ADMIN")
                    .requestMatchers(HttpMethod.POST, "/api/v1/news", "/api/v1/promotion", "/api/v1/flight", "/api/v1/plane", "/api/v1/seat").hasRole("ADMIN")
                    .requestMatchers(HttpMethod.PUT, "/api/v1/news", "/api/v1/news/list", "/api/v1/promotion", "/api/v1/promotion/list", "/api/v1/flight", "/api/v1/flight/list", "/api/v1/plane", "/api/v1/seat").hasRole("ADMIN")
                    .requestMatchers(HttpMethod.DELETE, "/api/v1/news", "/api/v1/promotion", "/api/v1/flight", "/api/v1/plane", "/api/v1/seat").hasRole("ADMIN")
                    .anyRequest().authenticated()
            );

        http.authenticationProvider(authenticationProvider());
        http.addFilterBefore(authenticationJwtTokenFilter(), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}
