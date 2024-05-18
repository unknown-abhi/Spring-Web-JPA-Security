package com.abhi.springwebjpasecurity.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

// In This class we are fetching data from the database
@Configuration
@EnableWebSecurity
public class AppSecurityConfig {

    @Autowired
    private UserDetailsService userDetailsService;

    @Bean
    public AuthenticationProvider authProvider() {

        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userDetailsService);
        provider.setPasswordEncoder(new BCryptPasswordEncoder());
//        provider.setPasswordEncoder(NoOpPasswordEncoder.getInstance());
        return provider;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        return http.csrf(AbstractHttpConfigurer::disable)
                .cors(AbstractHttpConfigurer::disable)
                .exceptionHandling(exceptions -> exceptions
                        .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login")))
                .authorizeHttpRequests(requests -> requests.requestMatchers("/WEB-INF/**").permitAll()
                        .anyRequest().authenticated())
                .formLogin(form -> form
                        .loginPage("/login")
                        .permitAll()
                        .successForwardUrl("/")  // Use successForwardUrl for a server-side redirect
                        .failureUrl("/login?error=true"))  // Specify a URL for failed logins
                .logout(logout -> logout.invalidateHttpSession(true)
                        .clearAuthentication(true)
                        .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
                        .logoutSuccessUrl("/logout-success").permitAll()
                        .logoutSuccessHandler((request, response, authentication) -> {
                            // Redirect to home after successful logout
                            response.sendRedirect("/");
                        }))
                .build();
    }

//    // This way we can override the default configuration
//    @Bean
//    public UserDetailsService userDetailsService() {
//        UserDetails user = User.builder()
//                .username("Abhishek")
//                .password("{bcrypt}$2a$12$f8EL6WLlXpc1lj496lbPieCxDRliKtOm.xXuNe1PbptouyGcejnxO") // password = 12345
//                .roles("USER") // Add any necessary roles
//                .build();
//
//        // You can add more users if needed
//        // UserDetails admin = User.builder()
//        //         .username("admin")
//        //         .password("{bcrypt}$2a$10$GRLdNijSQMUvl/au9ofL.eDwmoohzzS7.rmNSJZ.0FxO/BTk76klW")
//        //         .roles("USER", "ADMIN")
//        //         .build();
//
//        return new InMemoryUserDetailsManager(user);
//    }
}
