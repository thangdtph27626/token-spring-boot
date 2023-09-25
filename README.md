# Kết hợp token vào trong Spring Security để bảo mật cho project microservice

Trong các ứng dụng microservice, việc bảo mật là vô cùng quan trọng. Một trong những cách bảo mật phổ biến là sử dụng token. Token là một chuỗi ký tự được sử dụng để xác thực người dùng và cấp quyền truy cập vào các tài nguyên.

Spring Security là một framework bảo mật mạnh mẽ cho các ứng dụng Java. Spring Security cung cấp nhiều tính năng bảo mật, bao gồm xác thực, ủy quyền và bảo mật truy cập.

Trong bài viết này, chúng ta sẽ tìm hiểu cách kết hợp token vào trong Spring Security để bảo mật cho project microservice.

## 1. Cài đặt các dependency cần thiết

Trước tiên, chúng ta cần cài đặt các dependency cần thiết cho project của mình. Các dependency cần thiết bao gồm:

- spring-boot-starter-security: Đây là dependency cơ bản cho Spring Security.
- spring-boot-starter-web: Đây là dependency cơ bản cho Spring Boot.
- jjwt: Đây là thư viện giúp tạo và xác thực token JWT.

## 2. Tạo project Spring Boot

Sau khi đã cài đặt các dependency cần thiết, chúng ta có thể tạo project Spring Boot.

```
dependencies {
    implementation 'org.springframework.boot:spring-boot-starter-web'
    compileOnly 'org.projectlombok:lombok'
    developmentOnly 'org.springframework.boot:spring-boot-devtools'
    runtimeOnly 'org.postgresql:postgresql'
    annotationProcessor 'org.projectlombok:lombok'
    testImplementation 'org.springframework.boot:spring-boot-starter-test'
    implementation 'org.springframework.boot:spring-boot-starter-data-jpa:3.1.1'
    implementation group: 'javax.persistence', name: 'persistence-api', version: '1.0.2'
    implementation group: 'org.springframework.boot', name: 'spring-boot-starter-validation', version: '3.1.1'
    implementation group: 'org.springframework.boot', name: 'spring-boot-starter-security', version: '3.1.1'
    implementation group: 'org.springframework.security', name: 'spring-security-oauth2-client', version: '6.1.1'
    implementation group: 'io.jsonwebtoken', name: 'jjwt-api', version: '0.11.5'
    runtimeOnly group: 'io.jsonwebtoken', name: 'jjwt-impl', version: '0.11.5'
    runtimeOnly group: 'io.jsonwebtoken', name: 'jjwt-jackson', version: '0.11.5'
    implementation group: 'io.github.cdimascio', name: 'dotenv-java', version: '3.0.0'
    implementation group: 'org.springframework.security', name: 'spring-security-oauth2-jose', version: '6.1.1'
    implementation 'com.google.api-client:google-api-client:1.32.1'

}

```

### 3. Khởi tạo các jwt 

### JwtTokenProvider 

```
@Component
@Slf4j
@Transactional
public class JwtTokenProvider {
    // Đoạn JWT_SECRET này là bí mật, chỉ có phía server biết hoặc Keys.secretKeyFor(SignatureAlgorithm.HS512);
    @Value("${jwt.secret}")
    private String JWT_SECRET;

    //Thời gian có hiệu lực của chuỗi jwt
    private final long JWT_EXPIRATION = 604800000L;

    @Autowired
    private UserRepository userRepository;

    // Tạo ra jwt từ thông tin user
    public String generateToken(UserDetailCustom user) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + JWT_EXPIRATION);
        Users user1 = userRepository.findByEmail(user.getUsername()).get();
        Map<String, Object> claims = new HashMap<>();
        claims.put("id", user1.getId());
        claims.put("email", user1.getEmail());
        claims.put("roles", user1.getRole());
        // Tạo chuỗi json web token từ id của user.
        return Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(now)
                .setExpiration(expiryDate)
                .signWith(SignatureAlgorithm.HS256, JWT_SECRET)
                .compact();
    }


    // Lấy thông tin user từ jwt
    public String getUserIdFromJWT(String token) {
        Claims claims = Jwts.parser().setSigningKey(JWT_SECRET).parseClaimsJws(token).getBody();
        return String.valueOf(claims.get("id"));
    }

    public boolean validateToken(String authToken) {
        try {
            Jwts.parser().setSigningKey(JWT_SECRET).parseClaimsJws(authToken);
            return true;
        } catch (MalformedJwtException ex) {
            log.error("Invalid JWT token");
        } catch (ExpiredJwtException ex) {
            log.error("Expired JWT token");
        } catch (UnsupportedJwtException ex) {
            log.error("Unsupported JWT token");
        } catch (IllegalArgumentException ex) {
            log.error("JWT claims string is empty.");
        }
        return false;
    }
}
```

### JwtAuthenticationFilter 

```
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    @Autowired
    private JwtTokenProvider tokenProvider;

    @Autowired
    private UserService customUserDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        try {
//             Lấy jwt từ request
            String jwt = getJwtFromRequest(request);
            System.out.println(jwt);
            if (StringUtils.hasText(jwt) && tokenProvider.validateToken(jwt)) {
                // Lấy id user từ chuỗi jwt
//                String userId = tokenProvider.getUserIdFromJWT(jwt);
//                System.out.println(userId);
                // Lấy thông tin người dùng từ id
                UserDetails userDetails = customUserDetailsService.loadCustomsUserById("81ca46f1-9dbb-4f1e-85d4-3e16a2cb5f4e");
                if (userDetails != null) {
                    // Nếu người dùng hợp lệ, set thông tin cho Seturity Context
                    UsernamePasswordAuthenticationToken
                            authentication = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                    authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                    SecurityContextHolder.getContext().setAuthentication(authentication);
                }
            }
        } catch (Exception ex) {
            log.error("failed on set user authentication", ex);
        }

        filterChain.doFilter(request, response);
    }

    private String getJwtFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        // Kiểm tra xem header Authorization có chứa thông tin jwt không
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }
}
```

### 4: Tạo cấu hình Spring Security

```
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    private  String ADMIN = "MANAGE";
    private String USER = "USER";

    @Autowired
    public JwtTokenProvider jwtTokenProvider;

    @Autowired
    private JwtAuthenticationFilter jwtAuthenticationFilter(){
        return  new JwtAuthenticationFilter();
    }

//    @Autowired
//    private CustomOAuth2UserService oauthUserService;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        return new UserDetailServiceImpl();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http.cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/users", "/api/users/**").hasAnyAuthority(ADMIN, USER)
                        .requestMatchers(HttpMethod.DELETE, "/api/users/**").hasAnyAuthority(ADMIN)
                        .requestMatchers("/api/auth/**").permitAll()
                        .anyRequest().authenticated())
                .oauth2Login(withDefaults())
                .formLogin(withDefaults())
                .logout(l -> l.logoutSuccessUrl("/").permitAll())
                .addFilterBefore(jwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class)
//                .sessionManagement(sessionManagement -> sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
//                .exceptionHandling(exceptionHandling -> exceptionHandling.authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)))
                .authenticationProvider(authenticationProvider())
                .httpBasic(withDefaults())
                .build();

    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setUserDetailsService(userDetailsService());
        authenticationProvider.setPasswordEncoder(passwordEncoder());
        return authenticationProvider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedMethods(Arrays.asList("HEAD", "GET", "PUT", "POST", "DELETE", "PATCH"));
        configuration.addAllowedOrigin("*");
        configuration.addAllowedHeader("*");
        configuration.addAllowedMethod("*");
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

}
```

Trong cấu hình trên, chúng ta đã chỉ định rằng tất cả các request đến endpoint /api/auth/** sẽ được phép truy cập mà không cần xác thực. Tất cả các request khác sẽ yêu cầu người dùng phải được xác thực.

Chúng ta cũng đã tạo một bean JwtAuthenticationFilter để xác thực token JWT.

### 5. Tạo endpoint xác thực


Cuối cùng, chúng ta cần tạo endpoint xác thực để người dùng có thể nhận được token JWT.

```
@RestController
@RequestMapping("/api/auth")
@CrossOrigin("*")
public class AuthResController {

    @Autowired
    private JwtTokenProvider tokenProvider;

    @Autowired
    private GoogleTokenVerifier googleTokenVerifier;

    @Autowired
    private AuthenticationManager authenticationManager;


    @PostMapping("/sign-in")
    public JwtResponse signIn(@RequestBody SignInRequest request) {
        Users user = authenticateAndGetUser(request.getEmail(), request.getPassword()).getUser();
        String token = tokenProvider.generateToken(authenticateAndGetUser(request.getEmail(), request.getPassword()));
        return new JwtResponse(token, user);
    }

    private UserDetailCustom authenticateAndGetUser(String email, String password) {
        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(email, password));
        SecurityContextHolder.getContext().setAuthentication(authentication);
        return (UserDetailCustom) authentication.getPrincipal();
    }

}
```

Endpoint này sẽ nhận username và password của người dùng từ request. Nếu username và password hợp lệ, endpoint sẽ trả về token JWT.

## 6. Sử dụng token JWT

Sau khi đã tạo token JWT, chúng ta có thể sử dụng token này để xác thực người dùng và cấp quyền truy cập vào các tài nguyên.

Để xác thực người dùng, chúng ta có thể sử dụng filter JwtAuthenticationFilter để kiểm tra token JWT trong request.

Để cấp quyền truy cập vào các tài nguyên, chúng ta có thể sử dụng annotation @PreAuthorize để kiểm tra quyền của người dùng.

```
@RestController
@RequestMapping("/api/users")
public class UserController {

    @Autowired
    private UserRepository userRepository;

    @GetMapping("/")
    @PreAuthorize("hasRole('ADMIN')")
    public List<User> getAllUsers() {
        return userRepository.findAll();
    }

}
```
Endpoint này chỉ cho phép người dùng có vai trò ADMIN truy cập.

## Kết luận

Trong bài viết này, chúng ta đã tìm hiểu cách kết hợp token vào trong Spring Security để bảo mật cho project microservice.

Với cách này, chúng ta có thể đảm bảo rằng chỉ những người dùng được xác thực mới có thể truy cập vào các tài nguyên.

Dưới đây là một số lưu ý khi sử dụng token JWT:

- Token JWT phải được mã hóa bằng thuật toán mạnh để tránh bị giả mạo.
- Token JWT có thời hạn sử dụng để tránh bị sử dụng sau khi hết hạn.
- Token JWT phải được lưu trữ an toàn để tránh bị đánh cắp.
Hy vọng bài viết này sẽ giúp ích cho bạn.
