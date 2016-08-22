package demo;

import java.io.IOException;
import java.security.Principal;
import java.util.Collections;
import java.util.Map;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.security.oauth2.client.EnableOAuth2Sso;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.logout.CookieClearingLogoutHandler;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.csrf.CsrfLogoutHandler;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.filter.OncePerRequestFilter;

@Configuration
@ComponentScan
@EnableAutoConfiguration
@RestController
@RequestMapping("/dashboard")
public class SsoApplication {

	@Component
	@EnableOAuth2Sso
	public static class LoginConfigurer extends WebSecurityConfigurerAdapter {

		private final CsrfTokenRepository repo;

		public LoginConfigurer() {
			this.repo = this.csrfTokenRepository();
		}

		@Override
		public void configure(HttpSecurity http) throws Exception {
			http.authorizeRequests().anyRequest()
					.authenticated().and().csrf().csrfTokenRepository(repo)
					.and().addFilterAfter(csrfHeaderFilter(), CsrfFilter.class)
					.logout()
					.logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
					.invalidateHttpSession(true)
					.deleteCookies("XSRF-TOKEN","JSESSIONID")
					.logoutSuccessUrl("/");
		}

		private Filter csrfHeaderFilter() {
			return new OncePerRequestFilter() {
				@Override
				protected void doFilterInternal(HttpServletRequest request,
						HttpServletResponse response, FilterChain filterChain)
						throws ServletException, IOException {
					CsrfToken csrf = (CsrfToken) request
							.getAttribute(CsrfToken.class.getName());
					if (csrf != null) {
						Cookie cookie = new Cookie("XSRF-TOKEN",
								csrf.getToken());
						cookie.setPath("/");
						response.addCookie(cookie);
					}
					filterChain.doFilter(request, response);
				}
			};
		}

		private CsrfTokenRepository csrfTokenRepository() {
			HttpSessionCsrfTokenRepository repository = new HttpSessionCsrfTokenRepository();
			repository.setHeaderName("X-XSRF-TOKEN");
			return repository;
		}
	}

	@Controller
	public static class LoginErrors {

		@RequestMapping("/dashboard/login")
		public String dashboard() {
			return "redirect:/#/";
		}

	}

	public static void main(String[] args) {
		SpringApplication.run(SsoApplication.class, args);
	}

	@RequestMapping("/message")
	public Map<String, Object> dashboard() {
		return Collections.<String, Object> singletonMap("message", "Yay!");
	}

	@RequestMapping("/user")
	public Principal user(Principal user) {
		return user;
	}
}
