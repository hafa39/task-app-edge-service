package com.example.edgeservice.user;

import java.util.List;

public record User(
		String id,
		String username,
		String firstName,
		String lastName,
		List<String> roles
) {
}
