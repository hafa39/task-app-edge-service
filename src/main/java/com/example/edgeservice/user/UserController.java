package com.example.edgeservice.user;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

//@RestController
public class UserController {

	public Mono<User> getUser(@AuthenticationPrincipal OidcUser oidcUser) {
		System.out.println(oidcUser);
		var user = new User(
				oidcUser.getName(),
				oidcUser.getPreferredUsername(),
				oidcUser.getGivenName(),
				oidcUser.getFamilyName(),
				oidcUser.getClaimAsStringList("roles")
		);
		return Mono.just(user);
	}

}
