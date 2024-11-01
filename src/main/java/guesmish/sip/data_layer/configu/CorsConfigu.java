package guesmish.sip.data_layer.configu;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class CorsConfigu {

    private static final Logger logger = LoggerFactory.getLogger(CorsConfigu.class);

    @Bean
    public WebMvcConfigurer corsConfigurer() {
        return new WebMvcConfigurer() {
            @Override
            public void addCorsMappings(CorsRegistry registry) {
                logger.info("Configuring CORS mappings");

                registry.addMapping("/**")
                        .allowedOrigins("http://localhost:4200")// Exact origin with no wildcard
                        .allowedMethods("GET", "POST", "PUT", "DELETE", "PATCH")
                        .allowedHeaders("Authorization", "Content-Type");
                         // Enable credentials support
            }
        };
    }
}

