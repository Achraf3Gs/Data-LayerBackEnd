package guesmish.sip.data_layer.auth;

import guesmish.sip.data_layer.configu.JwtService;
import guesmish.sip.data_layer.users.Role;
import guesmish.sip.data_layer.users.User;
import guesmish.sip.data_layer.users.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {


    private final UserRepository repository;

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
        repository.save(user);
        var jwtToken= jwtService.generateToken((User) user);


        Role role = user.getRole();
        String name= user.getName();
        String address = user.getAddress();
        Integer id = user.getId();
        return AuthenticationResponse.builder()
                .token(jwtToken)
                .role(role)
                .id(id)
                .address(address)
                .name(name)
                .build();

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
            String username = jwtService.extractUsername(jwtToken);
            Role role = user.getRole();
            String name= user.getName();
            String address = user.getAddress();
            Integer id = user.getId();
            AuthenticationResponse response = AuthenticationResponse.builder()

                    .token(jwtToken)
                    .role(role)
                    .id(id)
                    .address(address)
                    .name(name)
                    .build();
            return response;
        }
    }
}


