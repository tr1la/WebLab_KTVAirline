package org.example.controller;

import org.example.entity.User;
import org.example.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.http.ResponseEntity;
import org.springframework.util.ObjectUtils;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/v1/user")
public class UserController {
    @Autowired
    UserService userService;

    @GetMapping(value = "/email")
    public ResponseEntity<?> getByEmail(@RequestParam String email){
        try {
            User user = userService.findByEmail(email);
            if(ObjectUtils.isEmpty(user)){
                return ResponseEntity.notFound().build();
            } else {
                return ResponseEntity.ok().body(user);
            }
        } catch (Exception e){
            return ResponseEntity.internalServerError()
                    .body("Server Error");
        }
    }

    @GetMapping(value = "/id")
    public ResponseEntity<?> getById(@RequestParam Integer id){
        try {
            User user = userService.findById(id);
            if(ObjectUtils.isEmpty(user)){
                return ResponseEntity.badRequest()
                        .body("Error: Id is not exist!");
            } else {
                return ResponseEntity.ok().body(user);
            }
        } catch (Exception e){
            return ResponseEntity.internalServerError()
                    .body("Server Error");
        }
    }

    @GetMapping(value = "/all")
    public ResponseEntity<?> getAll(@RequestParam Integer pageNum
            , @RequestParam Integer pageSize) {
        try {
            Pageable pageable = PageRequest.of(pageNum, pageSize);
            List<User> userList = userService.findAll(pageable);
            if(userList.isEmpty()){
                return ResponseEntity.badRequest()
                        .body("Not found");
            } else {
                return ResponseEntity.ok().body(userList);
            }
        } catch (Exception e){
            return ResponseEntity.internalServerError()
                    .body("Server Error");
        }
    }

    @DeleteMapping
    public ResponseEntity<?> deleteById(@RequestParam Integer id){
        try {
            if(userService.existsById(id)){
                userService.deletesById(id);
                return ResponseEntity.ok()
                        .body("Deleted");
            } else {
                return ResponseEntity.badRequest()
                        .body("Not found");
            }
        } catch (Exception e){
            return ResponseEntity.internalServerError()
                    .body("Server Error");
        }
    }

    @PutMapping
    public ResponseEntity<?> editUser(@RequestBody User user){
        try {
            if(userService.existsById(user.getId())){
                user.setPassword(userService.findById(user.getId()).getPassword());
                userService.save(user);
                return ResponseEntity.ok()
                        .body("Edited");
            } else {
                return ResponseEntity.badRequest()
                        .body("Not found");
            }
        } catch (Exception e){
            return ResponseEntity.internalServerError()
                    .body("Server Error");
        }
    }
}
