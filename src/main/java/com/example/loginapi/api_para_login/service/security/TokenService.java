package com.example.loginapi.api_para_login.service.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.example.loginapi.api_para_login.entities.user.User;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import java.time.Instant;

import java.time.LocalDateTime;
import java.time.ZoneOffset;

// Para indicar que é uma classe de serviço vamos usar
// E o Spring fazer a injeção de dependencia corretamente dessa classe

@Service
public class TokenService {

    @Value("${api.security.token.secret}")
    private String secret;

    // E aqui vamos criar um metodo de geração de token

    // Vamos receber por parametro um usuário - que vem da entidade User que criamos
    public String generateToken(User user) {
        try {

            // Algoritmo para geração e criptografia do token
            // Vamos utilizar esse algoritmo de hash aqui: HMAC256()

            Algorithm algorithm = Algorithm.HMAC256(secret);

            // withIssuer() - diz quem ta emitindo o token (nesse caso é nossa API)
            // withSubject() - quem esta sendo sujeito
            String token = JWT.create().
                               withIssuer("api-para-login").
                               withSubject(user.getEmail()).
                               withExpiresAt(generateExpirationDate()).
                               sign(algorithm);

            return token;

        } catch (JWTCreationException e) {
            throw new RuntimeException("Error while authenticating");
        }
    }


    // metodo para validar o token - Decodificando
    public String validateToken(String token){
        try{

            // Se o token for válido vamos retornar o email do usuário
            Algorithm algorithm = Algorithm.HMAC256(secret);
            return JWT.require(algorithm)
                      .withIssuer("api-para-login")
                      .build()
                      .verify(token)
                      .getSubject();

        } catch (JWTVerificationException e) {
            // Caso de erro de validação de token vamos retornar null
            return null;
        }
    }


    // metodo para gerar o tempo de expiração do token
    // O token vai ter 2 horas de validade
    private Instant generateExpirationDate() {
        return LocalDateTime.now().plusHours(2).toInstant(ZoneOffset.of("-03:00"));
    }
}
