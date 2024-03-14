package com.abhi.springwebjpasecurity.service;

import com.abhi.springwebjpasecurity.UserPrinciple;
import com.abhi.springwebjpasecurity.model.Users;
import com.abhi.springwebjpasecurity.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class MyUserDetailsService implements UserDetailsService {

    @Autowired
    private UserRepository repository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        Users user = repository.findByUsername(username);
        if (user==null) {
            throw new UsernameNotFoundException("User 404");
        }
        return new UserPrinciple(user);
    }
}
