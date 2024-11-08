package guesmish.sip.data_layer.token;


import guesmish.sip.data_layer.users.User;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor // Add this annotation
@Entity
public class Token {
    @Id
    @GeneratedValue
    private Integer id;

    private String token;

    @Enumerated(EnumType.STRING)
    private TokenType tokenType;

    @Column(columnDefinition = "BIT")
    private boolean expired;

    @Column(columnDefinition = "BIT")
    private boolean revoked;


    @ManyToOne
   @JoinColumn(name="user_id")
    private User user;
}
