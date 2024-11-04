package guesmish.sip.data_layer.configu;

import guesmish.sip.data_layer.refreshToken.RefreshTokenRepository;
import guesmish.sip.data_layer.token.TokenRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class LogOutService implements LogoutHandler {

    private final TokenRepository tokenrepository;

    private final RefreshTokenRepository refreshTokenrepository;

    @Override
    public void logout(HttpServletRequest request,
                       HttpServletResponse response,
                       Authentication authentication
    ) {
        final String authHeader= request.getHeader("Authorization");
        final String jwt;
        if(authHeader==null || !authHeader.startsWith("Bearer ")) {
            return;
        }
        jwt= authHeader.substring(7);
        var storedRefreshToken = refreshTokenrepository.findByRefreshToken(jwt)
                .orElse(null);
        // Check if token is valid (not expired and not revoked) in the database
        boolean isTokenValid = refreshTokenrepository.findByRefreshToken(jwt)
                .map(t -> !t.isExpired() && !t.isRevoked())
                .orElse(false);

        if (storedRefreshToken != null && isTokenValid) {
            storedRefreshToken.setExpired(true);
            storedRefreshToken.setRevoked(true);
            refreshTokenrepository.save(storedRefreshToken);
        } else {
            // Set response status to 403 Forbidden if token is invalid
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        }
    }
}
