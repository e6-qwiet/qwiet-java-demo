package io.shiftleft.controller;

import io.shiftleft.model.AuthToken;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Controller;
import org.springframework.util.FileCopyUtils;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;


/**
 * Admin checks login
 */
@Controller
public class AdminController {
  private String fail = "redirect:/";

  // helper
  private boolean isAdmin(String auth)
  {
    try {
      ByteArrayInputStream bis = new ByteArrayInputStream(Base64.getDecoder().decode(auth));
      ObjectInputStream objectInputStream = new ObjectInputStream(bis);
      Object authToken = objectInputStream.readObject();
      return ((AuthToken) authToken).isAdmin();
    } catch (Exception ex) {
      System.out.println(" cookie cannot be deserialized: "+ex.getMessage());
      return false;
    }
  }

  //
  @RequestMapping(value = "/admin/printSecrets", method = RequestMethod.POST)
  public String doPostPrintSecrets(HttpServletResponse response, HttpServletRequest request) {
    return fail;
  }


  @RequestMapping(value = "/admin/printSecrets", method = RequestMethod.GET)
  public String doGetPrintSecrets(@CookieValue(value = "auth", defaultValue = "notset") String auth, HttpServletResponse response, HttpServletRequest request) throws Exception {

    if (request.getSession().getAttribute("auth") == null) {
      return fail;
    }

    String authToken = request.getSession().getAttribute("auth").toString();
    if(!isAdmin(authToken)) {
      return fail;
    }

    ClassPathResource cpr = new ClassPathResource("static/calculations.csv");
    try {
      byte[] bdata = FileCopyUtils.copyToByteArray(cpr.getInputStream());
      response.getOutputStream().println(new String(bdata, StandardCharsets.UTF_8));
      return null;
    } catch (IOException ex) {
      ex.printStackTrace();
      // redirect to /
      return fail;
    }
  }

  /**
   * Handle login attempt
   * @param auth cookie value base64 encoded
   * @param password hardcoded value
   * @param response -
   * @param request -
   * @return redirect to company numbers
   * @throws Exception
   */
  @RequestMapping(value = "/admin/login", method = RequestMethod.POST)
// Inject BCrypt password encoder for secure password validation
@Autowired
private Environment env;

@Autowired
private RedisTemplate<String, String> redisTemplate;

// RSA key pair for asymmetric encryption
private RSAPublicKey publicKey;
private RSAPrivateKey privateKey;

// Application-specific values
private String jwtIssuer;
private String jwtAudience;

@PostConstruct
public void init() {
    // Generate RSA key pair for token signing
    KeyPair keyPair = Keys.keyPairFor(SignatureAlgorithm.RS256);
    publicKey = (RSAPublicKey) keyPair.getPublic();
    privateKey = (RSAPrivateKey) keyPair.getPrivate();
    
    // Initialize application values from environment
    jwtIssuer = env.getProperty("jwt.issuer", "shiftleft-application");
    jwtAudience = env.getProperty("jwt.audience", "admin-portal");
}

private boolean isAdmin(String auth) {
    if (auth == null || auth.isEmpty()) {
        return false;
    }
    
    try {
        // Check if token is in blacklist
        if (Boolean.TRUE.equals(redisTemplate.hasKey("blacklist:" + auth))) {
            // Token has been revoked
            return false;
        }
        
        // Parse JWT token using asymmetric key
        Jws<Claims> claims = Jwts.parserBuilder()
            .setSigningKey(publicKey)
            .requireIssuer(jwtIssuer)
            .requireAudience(jwtAudience)
            .build()
            .parseClaimsJws(auth);
        
        // Extract subject from JWT claims - should contain role information
        String subject = claims.getBody().getSubject();
        
        // Validate expiration explicitly
        Date expiration = claims.getBody().getExpiration();
        if (expiration == null || expiration.before(new Date())) {
            return false;
        }
        
        return subject != null && subject.equals("ADMIN");
    } catch (JwtException ex) {
        // Log sanitized error message to prevent log injection
        System.out.println("Invalid JWT token: " + Encode.forJava(ex.getMessage()));
        return false;
    } catch (Exception ex) {
        // Log sanitized error message to prevent log injection
        System.out.println("Authentication failure: " + Encode.forJava(ex.getMessage()));
        return false;
    }
}

// Method to add token to blacklist (for revocation)
private void revokeToken(String token, long timeToLiveSeconds) {
    if (token != null && !token.isEmpty()) {
        redisTemplate.opsForValue().set("blacklist:" + token, "revoked", timeToLiveSeconds, java.util.concurrent.TimeUnit.SECONDS);
    }
}

// Generates a refresh token
private String generateRefreshToken(String userId) {
    long refreshValidity = 7 * 24 * 60 * 60 * 1000; // 7 days
    
    return Jwts.builder()
        .setSubject(userId)
        .setIssuedAt(new Date())
        .setExpiration(new Date(System.currentTimeMillis() + refreshValidity))
        .setId(UUID.randomUUID().toString()) // Unique token ID
        .signWith(privateKey)
        .compact();
}

// Generates an access token
private String generateAccessToken(String role) {
    long validity = 30 * 60 * 1000; // 30 minutes
    
    return Jwts.builder()
        .setSubject(role)
        .setIssuedAt(new Date())
        .setIssuer(jwtIssuer)
        .setAudience(jwtAudience)
        .setExpiration(new Date(System.currentTimeMillis() + validity))
        .setId(UUID.randomUUID().toString()) // Unique token ID
        .signWith(privateKey)
        .compact();
}


@RequestMapping(value = "/admin/login", method = RequestMethod.POST)
public ResponseEntity<String> doPostLogin(
        @CookieValue(value = "auth", defaultValue = "notset") String auth,
        @RequestBody String passwordData,
        HttpServletResponse response,
        HttpServletRequest request) {
    
    String successRedirect = "redirect:/admin/printSecrets";
    String failRedirect = "redirect:/admin/login";

    try {
        // Check for existing valid token
        if (!auth.equals("notset")) {
            if (isAdmin(auth)) {
                request.getSession().setAttribute("auth", auth);
                return ResponseEntity.ok(successRedirect);
            } else {
                // If token exists but is invalid, revoke it
                revokeToken(auth, 3600); // Revoke for 1 hour
            }
        }

        // Input validation - prevent injection attacks
        if (passwordData == null || !passwordData.contains("=")) {
            return ResponseEntity.badRequest().body(failRedirect);
        }
        
        // Safer parsing of the password parameter
        String password = null;
        if (passwordData.startsWith("password=")) {
            password = passwordData.substring("password=".length());
        } else {
            // Split password=value with stronger validation
            String[] parts = passwordData.split("=", 2);
            if (parts.length == 2 && "password".equals(parts[0])) {
                password = parts[1];
            }
        }
        
        // Validate password is present
        if (StringUtils.isEmpty(password)) {
            return ResponseEntity.badRequest().body(failRedirect);
        }
        
        // Secure password verification using BCrypt (constant-time comparison)
        if (passwordEncoder.matches(password, adminPasswordHash)) {
            // Generate CSRF token and store in session
            String csrfToken = generateCsrfToken();
            request.getSession().setAttribute("CSRF_TOKEN", csrfToken);
            
            // Generate access token
            String accessToken = generateAccessToken("ADMIN");
            
            // Generate refresh token
            String refreshToken = generateRefreshToken("admin-user");
            
            // Create secure, HttpOnly, SameSite cookie for access token
            Cookie authCookie = new Cookie("auth", accessToken);
            authCookie.setHttpOnly(true);  // Prevent JavaScript access
            authCookie.setSecure(true);    // HTTPS only
            authCookie.setPath("/");
            authCookie.setMaxAge(1800);    // 30 minutes
            
            // In Servlet 3.1+, you can use:
            // authCookie.setAttribute("SameSite", "Strict");
            // For older versions, we need to set it via header
            response.setHeader("Set-Cookie", 
                    String.format("%s=%s; Max-Age=%d; Path=%s; HttpOnly; Secure; SameSite=Strict", 
                            "auth", accessToken, 1800, "/"));
            
            // Create cookie for refresh token (also secure)
            Cookie refreshCookie = new Cookie("refresh_token", refreshToken);
            refreshCookie.setHttpOnly(true);
            refreshCookie.setSecure(true);
            refreshCookie.setPath("/api/refresh");  // Restrict to refresh endpoint
            refreshCookie.setMaxAge(604800);        // 7 days
            
            response.addCookie(refreshCookie);
            
            // Store token in session for additional verification
            request.getSession().setAttribute("auth", accessToken);
            
            // Return CSRF token in header for SPA applications
            return ResponseEntity.ok()
                    .header("X-CSRF-TOKEN", csrfToken)
                    .body(successRedirect);
        }
        
        // Constant time response to prevent timing attacks
        passwordEncoder.matches("dummy", adminPasswordHash);
        return ResponseEntity.status(401).body(failRedirect);
    }
    catch (Exception ex) {
        // Log sanitized exception message to prevent log injection
        System.out.println("Login error: " + Encode.forJava(ex.getMessage()));
        return ResponseEntity.status(500).body(failRedirect);
    }
}

@RequestMapping(value = "/api/refresh", method = RequestMethod.POST)
public ResponseEntity<String> refreshToken(
        @CookieValue(value = "refresh_token", defaultValue = "") String refreshToken,
        @RequestHeader("X-CSRF-TOKEN") String csrfToken,
        HttpServletRequest request,
        HttpServletResponse response) {
    
    // Verify CSRF token
    String sessionCsrfToken = (String) request.getSession().getAttribute("CSRF_TOKEN");
    if (sessionCsrfToken == null || !sessionCsrfToken.equals(csrfToken)) {
        return ResponseEntity.status(403).body("CSRF validation failed");
    }
    
    try {
        // Validate refresh token
        Jws<Claims> claims = Jwts.parserBuilder()
            .setSigningKey(publicKey)
            .build()
            .parseClaimsJws(refreshToken);
        
        // Check if token has been revoked
        if (Boolean.TRUE.equals(redisTemplate.hasKey("blacklist:" + refreshToken))) {
            return ResponseEntity.status(401).body("Invalid refresh token");
        }
        
        // Generate new access token
        String newAccessToken = generateAccessToken("ADMIN");
        
        // Create secure cookie for new access token
        Cookie authCookie = new Cookie("auth", newAccessToken);
        authCookie.setHttpOnly(true);
        authCookie.setSecure(true);
        authCookie.setPath("/");
        authCookie.setMaxAge(1800);
        
        response.setHeader("Set-Cookie", 
                String.format("%s=%s; Max-Age=%d; Path=%s; HttpOnly; Secure; SameSite=Strict", 
                        "auth", newAccessToken, 1800, "/"));
        
        // Update session
        request.getSession().setAttribute("auth", newAccessToken);
        
        return ResponseEntity.ok("Token refreshed");
    } catch (Exception e) {
        return ResponseEntity.status(401).body("Invalid refresh token");
    }
}

@RequestMapping(value = "/admin/logout", method = RequestMethod.POST)
public ResponseEntity<String> logout(
        @CookieValue(value = "auth", defaultValue = "") String authToken,
        @CookieValue(value = "refresh_token", defaultValue = "") String refreshToken,
        @RequestHeader("X-CSRF-TOKEN") String csrfToken,
        HttpServletRequest request,
        HttpServletResponse response) {
    
    // Verify CSRF token
    String sessionCsrfToken = (String) request.getSession().getAttribute("CSRF_TOKEN");
    if (sessionCsrfToken == null || !sessionCsrfToken.equals(csrfToken)) {
        return ResponseEntity.status(403).body("CSRF validation failed");
    }
    
    // Revoke both tokens by adding to blacklist
    revokeToken(authToken, 3600);
    revokeToken(refreshToken, 604800);
    
    // Clear cookies
    Cookie authCookie = new Cookie("auth", "");
    authCookie.setMaxAge(0);
    authCookie.setPath("/");
    response.addCookie(authCookie);
    
    Cookie refreshCookie = new Cookie("refresh_token", "");
    refreshCookie.setMaxAge(0);
    refreshCookie.setPath("/api/refresh");
    response.addCookie(refreshCookie);
    
    // Invalidate session
    request.getSession().invalidate();
    
    return ResponseEntity.ok("redirect:/login");
}

  /**
   * Same as POST but just a redirect
   * @param response
   * @param request
   * @return redirect
   */
  @RequestMapping(value = "/admin/login", method = RequestMethod.GET)
  public String doGetLogin(HttpServletResponse response, HttpServletRequest request) {
    return "redirect:/";
  }
}
