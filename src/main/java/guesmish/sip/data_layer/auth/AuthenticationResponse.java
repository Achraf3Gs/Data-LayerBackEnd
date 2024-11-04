package guesmish.sip.data_layer.auth;

import com.fasterxml.jackson.annotation.JsonProperty;
import guesmish.sip.data_layer.users.Role;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Date;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class AuthenticationResponse {

    private String message;

    @JsonProperty("access_Token")
    private String accesstoken;

    @JsonProperty("refresh_Token")
    private String refreshtoken;

    private String name;

    private String address;

    private Role role;

    private Integer id;

    private Date accessTokenExpiration;
    private Date refreshTokenExpiration;


}