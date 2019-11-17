package com.poc.security;

import java.io.IOException;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
public class JwtRequestFilter extends OncePerRequestFilter {

    /*
     * The doFilter method of the Filter is called by the container each time a request/response pair is passed through the chain due to a client request for a resource at the end of the chain. The FilterChain passed in to this method allows the Filter to pass on the request and response to the next entity in the chain.
     *
     * A typical implementation of this method would follow the following pattern:
     *
     *     Examine the request
     *     Optionally wrap the request object with a custom implementation to filter content or headers for input filtering
     *     Optionally wrap the response object with a custom implementation to filter content or headers for output filtering
     *         Either invoke the next entity in the chain using the FilterChain object (chain.doFilter()),
     *         or not pass on the request/response pair to the next entity in the filter chain to block the request processing
     *     Directly set headers on the response after invocation of the next entity in the filter chain.
     * @param request
     * @param response
     * @param chain
     * @throws ServletException
     * @throws IOException
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {


        String header = request.getHeader("Authorization");
        if (header == null || !header.startsWith("Bearer ")) {
            forbidden(response);
            return;
        }

        String token = header.replace("Bearer ", "");

        try {
            // exceptions might be thrown in creating the claims if for example the token is expired
            Claims claims = Jwts.parser()
                    .setSigningKey(Constants.JWT_SECRET.getBytes())
                    .parseClaimsJws(token)
                    .getBody();

            // ici vérifier par exemple ROLE_USER

            System.out.println(claims);

        } catch (Exception e) {
            forbidden(response);
            return;
        }
        chain.doFilter(request, response);
    }

    private void forbidden(HttpServletResponse response) {
        // In case of failure. Make sure it's clear; so guarantee user won't be authenticated
        SecurityContextHolder.clearContext();
        response.setStatus(403);
    }

}
