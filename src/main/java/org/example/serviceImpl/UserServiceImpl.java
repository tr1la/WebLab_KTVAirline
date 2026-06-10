package org.example.serviceImpl;

import org.example.entity.User;
import org.example.repository.UserRepository;
import org.example.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Pageable;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class UserServiceImpl implements UserService {
    @Autowired
    UserRepository userRepository;

    @Autowired
    PasswordEncoder encoder;

    @Override
    public Integer saveUser(User user) {
        user.setPassword(encoder.encode(user.getPassword()));
        return userRepository.save(user).getId();
    }

    @Override
    public Integer save(User user) {
        return userRepository.save(user).getId();
    }

    @Override
    public User findByEmail(String email) {
        return userRepository.findByEmailAndIsDeletedFalse(email);
    }

    @Override
    public User findById(Integer id) {
        return userRepository.findById(String.valueOf(id)).get();
    }

    @Override
    public List<User> findAll(Pageable pageable) {
        return userRepository.findByIsDeletedFalse(pageable).getContent();
    }

    @Override
    public boolean existsByEmail(String email) {
        return userRepository.existsByEmailAndIsDeletedFalse(email);
    }

    @Override
    public boolean existsById(Integer id) {
        return userRepository.existsByIdAndIsDeletedFalse(id);
    }

    @Override
    public void deletesById(Integer id) {
        User user = userRepository.findByIdAndIsDeletedFalse(id);
        user.setDeleted(true);
        userRepository.save(user);
    }
}
