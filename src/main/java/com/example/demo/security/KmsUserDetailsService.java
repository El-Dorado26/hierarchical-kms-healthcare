package com.example.demo.security;

import org.springframework.security.core.userdetails.User; //new user details
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.example.demo.entity.KmsUser;
import com.example.demo.repository.KmsUserRepository;

@Service
public class KmsUserDetailsService implements UserDetailsService {

    private final KmsUserRepository userRepository;
    private final UsernameHasher usernameHasher;

    public KmsUserDetailsService(
            KmsUserRepository userRepository,
            UsernameHasher usernameHasher) {

        this.userRepository = userRepository;
        this.usernameHasher = usernameHasher;
    }

    @Override
    public UserDetails loadUserByUsername(String username)
            throws UsernameNotFoundException {

        try {

            // Convert the username entered by the user
            // into its deterministic HMAC-SHA-256 representation.
            String usernameHash = usernameHasher.hash(username);

            // Search PostgreSQL using the username hash.
            KmsUser user = userRepository
                    .findByUsernameHash(usernameHash)
                    .orElseThrow(() ->
                            new UsernameNotFoundException(
                                    "User not found"));

            // Spring keeps the original username in memory
            // for authentication, permissions and auditing.
            return User.builder()
                    .username(user.getUsername())
                    .password(user.getPasswordHash())
                    .roles("USER")
                    .disabled(!user.isEnabled())
                    .build();

        } catch (UsernameNotFoundException e) {

            throw e;

        } catch (Exception e) {

            throw new UsernameNotFoundException(
                    "Unable to authenticate user",
                    e);
        }
    }
}