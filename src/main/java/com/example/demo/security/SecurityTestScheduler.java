package com.example.demo.security;

import java.net.URI;




import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.Random;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import jakarta.annotation.PreDestroy;

import com.example.demo.entity.KmsUser;
import com.example.demo.repository.KmsUserRepository;
import com.example.demo.service.AuditService;
import com.example.demo.service.KeyService;
import java.time.Instant;
import com.example.demo.entity.Department;
import com.example.demo.repository.DepartmentRepository;

/*This class automatically runs fake users and random security checks against 
 *the live application to make sure authentication and authorization is working.
 */ 

@Component // Spring will auto create this class at startup.
public class SecurityTestScheduler {

    private static final String PRIMARY_USERNAME = "_systest_primary"; // user 1 (primary)
    private static final String SECONDARY_USERNAME = "_systest_secondary"; // user 2 (secondary)
    private static final String BASE_URL = "http://localhost:8080";

    private final KmsUserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final KeyService keyService;
    private final AuditService auditService;
    private final DepartmentRepository departmentRepository;
    private final UsernameHasher usernameHasher; //new edition for hashed usernames 


    private final SecureRandom secureRandom = new SecureRandom();
    private final ScheduledExecutorService scheduler =
            Executors.newSingleThreadScheduledExecutor();
    private final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .build();

    private String primaryPassword;
    private String disabledKeyId;
    private String secondaryKeyId;

    public SecurityTestScheduler(
            KmsUserRepository userRepository,
            DepartmentRepository departmentRepository,
            PasswordEncoder passwordEncoder,  UsernameHasher usernameHasher,
            
            KeyService keyService,
            AuditService auditService) {
        this.userRepository = userRepository;
        this.departmentRepository = departmentRepository;
        this.passwordEncoder = passwordEncoder;
        this.keyService = keyService;
        this.auditService = auditService;
        this.usernameHasher = usernameHasher;
    }

    @EventListener(ApplicationReadyEvent.class)
    public void onReady() {
        setUpFixtures(); //creates test users, departments, and keys
        scheduleNextTest();//to run the tests in order
    }

    @PreDestroy
    public void shutdown() {
        scheduler.shutdownNow();
    }

    // runs once, after Tomcat is actually accepting connections
   
// Creates those 2 users with random passwords    
    private void setUpFixtures() {

        primaryPassword = randomPassword();
        String secondaryPassword = randomPassword();

        Department systemDepartment = ensureSystemDepartment();

        ensureTestUser(PRIMARY_USERNAME, primaryPassword, systemDepartment);
        ensureTestUser(SECONDARY_USERNAME, secondaryPassword, systemDepartment);

        disabledKeyId = createKeyAs(PRIMARY_USERNAME);
        secondaryKeyId = createKeyAs(SECONDARY_USERNAME);

        runAs(PRIMARY_USERNAME, () -> {
            try {
                keyService.disableKey(disabledKeyId, PRIMARY_USERNAME);
            } catch (Exception e) {
               
            }
        });
    }

    private Department ensureSystemDepartment() {
        return departmentRepository.findByName("System")
                .orElseGet(() -> {
                    Department department = new Department();
                    department.setName("System");
                    department.setCreatedAt(Instant.now());
                    return departmentRepository.save(department);
                });
    }
/*
    private void ensureTestUser(
            String username,
            String rawPassword,
            Department department) {

        KmsUser user = userRepository
                .findByUsername(username)
                .orElseGet(KmsUser::new);

        user.setUsername(username);

        // Always update the password because the scheduler
        // generates a new random password for every test run.
        user.setPasswordHash(
                passwordEncoder.encode(rawPassword));

        user.setEnabled(true);
        user.setDepartment(department);

        userRepository.save(user);
    }
*/
    private void ensureTestUser(
            String username,
            String rawPassword,
            Department department) {

        System.out.println("========================================");
        System.out.println("ensureTestUser() called");
        System.out.println("Plaintext username: " + username);

        KmsUser user = userRepository
                .findByUsername(username)
                .orElseGet(KmsUser::new);

        user.setUsername(username);

        try {
            String hash = usernameHasher.hash(username);

            System.out.println("Hashed username: " + hash);

            user.setUsernameHash(hash);

        } catch (Exception e) {
            throw new RuntimeException(
                    "Failed to hash username",
                    e);
        }

        System.out.println("Username hash assigned to KmsUser");
        System.out.println("========================================");

        user.setPasswordHash(
                passwordEncoder.encode(rawPassword));

        user.setEnabled(true);
        user.setDepartment(department);

        userRepository.save(user);
    }
    
    private String createKeyAs(String username) {

        final String[] result = new String[1];

        runAs(username, () -> {
            try {
                result[0] = keyService.createKey();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });

        return result[0];
    }

    /**
     * Installs a SecurityContext for this thread so service methods
     * that read SecurityContextHolder (like KeyService.createKey)
     * work outside a real HTTP request.
     */
    private void runAs(String username, Runnable action) {
        try {
            SecurityContextHolder.getContext().setAuthentication(
                    new UsernamePasswordAuthenticationToken(username, null, List.of()));
            action.run();
        } finally {
            SecurityContextHolder.clearContext();
        }
    }

    private String randomPassword() {
        byte[] bytes = new byte[24];
        secureRandom.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

//Scheduler, it runs a random test every 5-15 mins   
//After each test, it reschedules itself.
    private void scheduleNextTest() {

        long delaySeconds = 300 + secureRandom.nextInt(601);
    	//long delaySeconds = 10; for testing

        scheduler.schedule(() -> {
            try {
                runRandomSecurityTest();
            } catch (Exception e) {
                recordResult("ERROR", "FAIL", e.getMessage());
            } finally {
                scheduleNextTest();
            }
        }, delaySeconds, TimeUnit.SECONDS);
    }

    private void runRandomSecurityTest() throws Exception {
        switch (new Random().nextInt(4)) {
            case 0 -> testUnauthenticatedAccess();
            case 1 -> testInvalidCredentials();
            case 2 -> testUnauthorizedKeyAccess();
            case 3 -> testDisabledKeyRejected();
        }
    }

    // --------------------------------------------------
    // Individual tests: real HTTP calls to the live app,
    // scoped to localhost only
    // --------------------------------------------------

    // Calls /api/keys with no credentials. It expects a 401 Unauthorized

    private void testUnauthenticatedAccess() throws Exception {
        HttpResponse<String> response = httpClient.send(
                HttpRequest.newBuilder()
                        .uri(URI.create(BASE_URL + "/api/keys"))
                        .POST(HttpRequest.BodyPublishers.noBody())
                        .build(),
                HttpResponse.BodyHandlers.ofString());

        recordResult("AUTH_REQUIRED",
                response.statusCode() == 401 ? "PASS" : "FAIL",
                "Unauthenticated request returned " + response.statusCode());
    }

    // Calls /api/keys with wrong password. Also expects a 401 Unauthorized


    private void testInvalidCredentials() throws Exception {
        HttpResponse<String> response = httpClient.send(
                HttpRequest.newBuilder()
                        .uri(URI.create(BASE_URL + "/api/keys"))
                        .header("Authorization", basicAuthHeader(PRIMARY_USERNAME, "wrong-password"))
                        .POST(HttpRequest.BodyPublishers.noBody())
                        .build(),
                HttpResponse.BodyHandlers.ofString());

        recordResult("INVALID_CREDENTIALS",
                response.statusCode() == 401 ? "PASS" : "FAIL",
                "Bad password returned " + response.statusCode());
    }

    // Primary user tries to encrypt with secondary’s key. Expects 403 Forbidden
    
    private void testUnauthorizedKeyAccess() throws Exception {
        String body = String.format(
                "{\"keyId\":\"%s\",\"text\":\"security-self-test\"}", secondaryKeyId);

        HttpResponse<String> response = httpClient.send(
                HttpRequest.newBuilder()
                        .uri(URI.create(BASE_URL + "/api/crypto/encrypt"))
                        .header("Authorization", basicAuthHeader(PRIMARY_USERNAME, primaryPassword))
                        .header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(body))
                        .build(),
                HttpResponse.BodyHandlers.ofString());

        recordResult("UNAUTHORIZED_KEY_ACCESS",
                response.statusCode() == 403 ? "PASS" : "FAIL",
                "Primary encrypting with secondary's key returned " + response.statusCode());
    }

    // Primary user tries to encrypt with a disabled key. Expects failure (not 200 OK).

    private void testDisabledKeyRejected() throws Exception {
        String body = String.format(
                "{\"keyId\":\"%s\",\"text\":\"security-self-test\"}", disabledKeyId);

        HttpResponse<String> response = httpClient.send(
                HttpRequest.newBuilder()
                        .uri(URI.create(BASE_URL + "/api/crypto/encrypt"))
                        .header("Authorization", basicAuthHeader(PRIMARY_USERNAME, primaryPassword))
                        .header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(body))
                        .build(),
                HttpResponse.BodyHandlers.ofString());

        recordResult("DISABLED_KEY_REJECTED",
                response.statusCode() != 200 ? "PASS" : "FAIL",
                "Encrypt on disabled key returned " + response.statusCode());
    }

    private String basicAuthHeader(String username, String password) {
        String creds = username + ":" + password;
        return "Basic " + Base64.getEncoder().encodeToString(creds.getBytes(StandardCharsets.UTF_8));
    }

    // Audit Logging
    
    private void recordResult(String testName, String result, String details) {
        auditService.log("SYSTEM", "SECURITY_TEST_" + testName, null, result, details);
    }
}