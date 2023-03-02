package med.voll.api.infra.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfigurations {

    @Autowired
    private SecurityFilter securityFilter;

    // Configurando o padrão do filtro do Spring Security:
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http.csrf().disable() // desabilitando contra ataques cross site porque o token já protege
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) // mudando política para Stateless porque é uma API Rest
                .and().authorizeHttpRequests()
                .requestMatchers(HttpMethod.POST, "/login").permitAll() // libera requisições post para o login
                .anyRequest().authenticated() // qualquer outra é barrada
                .and().addFilterBefore(securityFilter, UsernamePasswordAuthenticationFilter.class) // nosso filtro antes do filtro do Spring
                .build();
    }

    //Configuração para injeção do AuthenticationManager no controller
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    // Configurando o tipo de Encoder
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
