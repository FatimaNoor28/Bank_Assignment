 package com.redmath.config;


 import org.springframework.beans.factory.annotation.Autowired;
 import org.springframework.beans.factory.annotation.Value;
 import org.springframework.context.annotation.Bean;
 import org.springframework.context.annotation.Configuration;
 import org.springframework.http.HttpMethod;
 import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
 import org.springframework.security.config.annotation.web.builders.HttpSecurity;
 import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
 import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
 import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
 import org.springframework.security.crypto.password.PasswordEncoder;
 import org.springframework.security.web.SecurityFilterChain;
 import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
 import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
 import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
 import org.springframework.web.cors.CorsConfiguration;
 import org.springframework.web.cors.CorsConfigurationSource;
 import org.springframework.web.cors.UrlBasedCorsConfigurationSource;


 @Configuration
 @EnableMethodSecurity
 @EnableWebSecurity
 public class WebSecurityConfiguration {
     @Bean
     public PasswordEncoder passwordEncoder() {
         return new BCryptPasswordEncoder();
     }


     @Value("${spring.web.security.ignored:/error,/ui/**,/favicon.ico,/api/v1/,/api/v1/login}")
     private String[] ignored = { "/error", "/ui/**", "/favicon.ico", "/swagger-ui/**", "/v3/api-docs",
             "/v3/api-docs/**" };
//     @Value("${spring.web.security.ignored.get:/api/v1/account}")
//     private String[] ignoredGet = { "/api/v1/account" };

//     private String[] ignored = { "/error", "/ui/**", "/favicon.ico", "/api/v1/", "/api/bank/login" };

     @Bean
     public WebSecurityCustomizer webSecurityCustomizer() {
         return web -> {
             for(String ignore:ignored )
                 web.ignoring().requestMatchers(AntPathRequestMatcher.antMatcher(ignore));
//             for (String ignore : ignoredGet) {
//                 web.ignoring().requestMatchers(AntPathRequestMatcher.antMatcher(HttpMethod.GET, ignore));
//             }
         };
     }
     @Bean
     public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
         http.formLogin(config -> {
             config.successHandler((request, response, auth) -> {
                         // Your success handler logic here
             });//.defaultSuccessUrl("http://localhost:8081/ ").permitAll();
         });http.logout(config -> config.logoutSuccessHandler((request, response, auth) -> {
         }));

//         http.authorizeHttpRequests(config -> config.anyRequest().authenticated());
         CookieCsrfTokenRepository csrfRepository = CookieCsrfTokenRepository.withHttpOnlyFalse();
         csrfRepository.setCookiePath("/");
         http.csrf(config -> config.csrfTokenRepository(csrfRepository)
                 .csrfTokenRequestHandler(new CsrfTokenRequestAttributeHandler()));

         http.authorizeRequests()
                 .requestMatchers(AntPathRequestMatcher.antMatcher("/actuator/**")).hasAnyAuthority("ACTUATOR")
                 .requestMatchers(AntPathRequestMatcher.antMatcher(HttpMethod.OPTIONS, "/api/v1/login")).permitAll()
//                 .requestMatchers(AntPathRequestMatcher.antMatcher(HttpMethod.POST, "/api/v1/account")).hasRole("ADMIN")
                 .anyRequest().authenticated()
                 .and().cors();
         http.csrf().disable();
         return http.build();
     }
     // CORS Configuration
     @Bean
     public CorsConfigurationSource corsConfigurationSource() {
         CorsConfiguration configuration = new CorsConfiguration();
         configuration.addAllowedOrigin("http://localhost:8081"); // Allow requests from your frontend
         configuration.addAllowedMethod("*"); // Allow all HTTP methods
         configuration.addAllowedHeader("*"); // Allow all headers

         UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
         source.registerCorsConfiguration("/**", configuration);
         return source;
     }


 }

// import org.springframework.beans.factory.annotation.Value;
// import org.springframework.context.annotation.Bean;
// import org.springframework.context.annotation.Configuration;
// import org.springframework.core.annotation.Order;
// import org.springframework.http.HttpMethod;
// import org.springframework.security.config.Customizer;
// import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
// import org.springframework.security.config.annotation.web.builders.HttpSecurity;
// import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
// import org.springframework.security.web.SecurityFilterChain;
// import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
// import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
// import org.springframework.web.cors.CorsConfigurationSource;
// import org.springframework.web.filter.CorsFilter;
// import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
// import org.springframework.web.cors.CorsConfiguration;

// import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

// import java.util.Arrays;

// @Configuration
// @EnableMethodSecurity
// public class WebSecurityConfiguration {

//     @Value("${spring.web.security.ignored:/error,/ui/**,/favicon.ico,/api/v1/account}")
//     private String[] ignored = { "/error", "/ui/**", "/favicon.ico", "/api/v1/account" };
//     @Bean
//     public WebSecurityCustomizer webSecurityCustomizer() {
//         return web -> {
//             for(String ignore:ignored )
//                 web.ignoring().requestMatchers(AntPathRequestMatcher.antMatcher(ignore));
//         };
//     }

//     @Bean
//     public CorsConfigurationSource corsConfigurationSource() {
//         CorsConfiguration configuration = new CorsConfiguration();
//         configuration.setAllowedOrigins(Arrays.asList(""));
//         configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
//         configuration.setAllowedHeaders(Arrays.asList(""));
//         configuration.setAllowCredentials(true);
//         configuration.setMaxAge(3600L);

//         UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
//         source.registerCorsConfiguration("/**", configuration);

//         return source;
//     }
//     @Bean
//     public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

//         http.csrf().disable();
//         http.formLogin(Customizer.withDefaults());
//         http.authorizeHttpRequests(config -> config.anyRequest().authenticated());
//         return http.build();
//     }
// }
