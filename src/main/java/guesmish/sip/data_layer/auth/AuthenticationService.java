package guesmish.sip.data_layer.auth;

import com.fasterxml.jackson.databind.ObjectMapper;
import guesmish.sip.data_layer.configu.JwtService;
import guesmish.sip.data_layer.refreshToken.RefreshToken;
import guesmish.sip.data_layer.refreshToken.RefreshTokenRepository;
import guesmish.sip.data_layer.token.Token;
import guesmish.sip.data_layer.token.TokenRepository;
import guesmish.sip.data_layer.token.TokenType;
import guesmish.sip.data_layer.users.Role;
import guesmish.sip.data_layer.users.User;
import guesmish.sip.data_layer.users.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

;import java.io.IOException;
import java.util.Date;

@Service
@RequiredArgsConstructor
public class AuthenticationService {



    private final UserRepository repository;
    private  final UserDetailsService userDetailsService;

    private final TokenRepository tokenrepository;

    private final RefreshTokenRepository refreshtokenrepository;

    private final PasswordEncoder passwordEncoder;

    private final JwtService jwtService;

    private final AuthenticationManager authenticationManager;



    public AuthenticationResponse register(RegisterRequest request) {
        String email = request.getEmail();

        // Check if the email already exists in the database
        if (repository.existsByEmail(email)) {
            throw new EmailAlreadyExistsException(email);
        }

        var user= User.builder()
                .name(request.getName())
                .address(request.getAddress())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .confirmPassword(passwordEncoder.encode(request.getConfirmPassword()))
                .role(Role.USER)
                .build();
        var savedUser= repository.save(user);
        var jwtToken= jwtService.generateToken((User) user);
        var refreshToken = jwtService.generaterefreshToken(user);
        //revokeAllUserTokens(user);
        savedUserToken(savedUser, jwtToken);
        savedUserRefreshToken(savedUser, refreshToken);
        Role role = user.getRole();
        String name= user.getName();
        String address = user.getAddress();
        Integer id = user.getId();
        String message="Register Success";
        return AuthenticationResponse.builder()
                .accesstoken(jwtToken)
                .refreshtoken(refreshToken)
                .role(role)
                .id(id)
                .address(address)
                .name(name)
                .message(message)
                .build();

    }

    private void savedUserToken(User user, String jwtToken) {
        var token= Token.builder()
                .user(user)
                .token(jwtToken)
                .tokenType(TokenType.BEARER)
                .expired(false)
                .revoked(false)
                .build();
        tokenrepository.save(token);
    }
    private void savedUserRefreshToken(User user, String jwtToken) {
        var refreshToken= RefreshToken.builder()
                .user(user)
                .refreshToken(jwtToken)
                .tokenType(TokenType.BEARER)
                .expired(false)
                .revoked(false)
                .build();
        refreshtokenrepository.save(refreshToken);
    }
    private void revokeAllUserTokens(User user){
        var validUserTokens= tokenrepository.findValidTokensByUser(user.getId());
        if (validUserTokens.isEmpty()) {
            return;
        }
        validUserTokens.forEach(t->{
            t.setExpired(true);
            t.setRevoked(true);
        });

        tokenrepository.saveAll(validUserTokens);
    }
    private void revokeAllUserRefreshTokens(User user){
        var validUserRefreshTokens= refreshtokenrepository.findValidRefreshTokensByUser(user.getId());
        if (validUserRefreshTokens.isEmpty()) {
            return;
        }
        validUserRefreshTokens.forEach(t->{
            t.setExpired(true);
            t.setRevoked(true);
        });

        refreshtokenrepository.saveAll(validUserRefreshTokens);
    }



    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );
        var user = repository.findByEmail(request.getEmail())
                .orElseThrow();
        if (user == null) {
            AuthenticationResponse response = AuthenticationResponse.builder()
                    .message("invalid email/password")
                    .build();
            return response;
        } else {
            var jwtToken = jwtService.generateToken(user);
            var refreshToken = jwtService.generaterefreshToken(user);
            revokeAllUserTokens(user);
            revokeAllUserRefreshTokens(user);
            savedUserToken(user,jwtToken);
            savedUserRefreshToken(user,refreshToken);
            String username = jwtService.extractUsername(jwtToken);
            Date accessTokenExpiration = jwtService.extractExpiration(jwtToken);
            Date refreshTokenExpiration = jwtService.extractExpiration(refreshToken);
            Role role = user.getRole();
            String name= user.getName();
            String address = user.getAddress();
            Integer id = user.getId();
            String message="Login Success";
            AuthenticationResponse response = AuthenticationResponse.builder()

                    .accesstoken(jwtToken)
                    .refreshtoken(refreshToken)
                    .accessTokenExpiration(accessTokenExpiration)
                    .refreshTokenExpiration(refreshTokenExpiration)
                    .role(role)
                    .id(id)
                    .address(address)
                    .name(name)
                    .message(message)
                    .build();
            return response;
        }
    }

    public void refreshToken(
            HttpServletRequest request,
            HttpServletResponse response
    ) throws IOException {
        final String authHeader= request.getHeader("Authorization");
        final String refreshToken;
        final String userEmail;

        if (authHeader == null ||!authHeader.startsWith("Bearer ")) {
            return;
        }
        System.out.println("Authorization header: " + authHeader);

        refreshToken = authHeader.substring(7);
        userEmail= jwtService.extractUsername(refreshToken);
        System.out.println(refreshToken);
        System.out.println("Extracted email from refresh token: " + userEmail);
        if (userEmail != null) {
            var user = this.repository.findByEmail(userEmail)
                    .orElseThrow();

            UserDetails userDetails =  this.userDetailsService.loadUserByUsername(userEmail);
            if (jwtService.isTokenValid(refreshToken,userDetails)){
                var accessToken = jwtService.generateToken(user);
                revokeAllUserTokens(user);
                savedUserToken(user,accessToken);
                var authResponse = AuthenticationResponse.builder()
                        .accesstoken(accessToken)
                        .refreshtoken(refreshToken)
                        .build();
                new ObjectMapper().writeValue(response.getOutputStream(), authResponse);
            }
        }
    }
}

