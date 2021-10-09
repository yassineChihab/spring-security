package com.chihab.spring.security.security;

import com.chihab.spring.security.auth.ApplicationUserService;
import com.chihab.spring.security.jwt.JwtConfig;
import com.chihab.spring.security.jwt.JwtTokenVerefier;
import com.chihab.spring.security.jwt.JwtUsernameAndPasswordAuthentificationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;

import javax.crypto.SecretKey;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {



    private final PasswordEncoder passwordEncoder;
    private final ApplicationUserService applicationUserService;
    private final SecretKey jwtSecretKey;
    private final JwtConfig jwtConfig;

    @Autowired
    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder, ApplicationUserService applicationUserService, SecretKey jwtSecretKey, JwtConfig jwtConfig) {
        this.passwordEncoder = passwordEncoder;
        this.applicationUserService = applicationUserService;
        this.jwtSecretKey = jwtSecretKey;
        this.jwtConfig = jwtConfig;
    }


    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.
                csrf().disable()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)

                .and()
                .addFilter(new JwtUsernameAndPasswordAuthentificationFilter(authenticationManager(), jwtConfig, jwtSecretKey))
                .addFilterAfter(new JwtTokenVerefier(jwtSecretKey, jwtConfig),JwtUsernameAndPasswordAuthentificationFilter.class)
                .authorizeRequests()
                .antMatchers("/","index").permitAll()
                .antMatchers("/api/**").hasRole(ApplicationUserRole.STUDENT.name())
              /*  .antMatchers(HttpMethod.DELETE,"/management/api/**").hasAuthority(ApplicaionUserPermission.COURSE_WRITE.getPermission())
                .antMatchers(HttpMethod.POST,"/management/api/**").hasAuthority(ApplicaionUserPermission.COURSE_WRITE.getPermission())
                .antMatchers(HttpMethod.PUT,"/management/api/**").hasAuthority(ApplicaionUserPermission.COURSE_WRITE.getPermission())
                .antMatchers(HttpMethod.GET,"/management/api/**").hasAnyRole(ApplicationUserRole.ADMIN.name(),ApplicationUserRole.ADMINTRAINEE.name())
               */
                .anyRequest()
                .authenticated();
                //formLogin
          /*      .and()
                .formLogin()
                .loginPage("/login").permitAll()
                .defaultSuccessUrl("/courses",true)
                .passwordParameter("password")
                .usernameParameter("username")

                .and()
                .rememberMe()
                .tokenValiditySeconds((int)TimeUnit.DAYS.toSeconds(21))
                .key("somethingverysecured")
                .rememberMeParameter("remember-me")
                .and()
                .logout()
                    .logoutUrl("/logout")
                  //  .logoutRequestMatcher(new AntPathRequestMatcher("/logout","GET"))
                    .clearAuthentication(true)
                    .invalidateHttpSession(true)
                    .deleteCookies("JSESSIONID","remember-me");
                   // .logoutUrl("/login");
*/
    }

  /*  @Override
    @Bean
    protected UserDetailsService userDetailsService() {
       UserDetails user= User.builder()
                .username("yassine")
                .password(passwordEncoder.encode("yassine123"))
//              .roles(ApplicationUserRole.STUDENT.name())//ROLES_STUDENT
               .authorities(ApplicationUserRole.STUDENT.getGrantedAuthorities())

               .build();
      UserDetails  admin= User.builder()
               .username("chihab")
               .password(passwordEncoder.encode("chihab123"))
//               .roles(ApplicationUserRole.ADMIN.name())//ROLES_ADMIN
              .authorities(ApplicationUserRole.ADMIN.getGrantedAuthorities())
               .build();
        UserDetails  adminTrainee= User.builder()
                .username("yassineChihab")
                .password(passwordEncoder.encode("chihab123"))
//                .roles(ApplicationUserRole.ADMINTRAINEE.name())//ROLES_ADMIN
                .authorities(ApplicationUserRole.ADMINTRAINEE.getGrantedAuthorities())
                .build();
       return new InMemoryUserDetailsManager(user,admin,adminTrainee);

    }*/

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(daoAuthenticationProvider());

    }

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider()
  {
      DaoAuthenticationProvider provider=new DaoAuthenticationProvider();
      provider.setPasswordEncoder(passwordEncoder);
      provider.setUserDetailsService(applicationUserService);
      return  provider;
  }

}
