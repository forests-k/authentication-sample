package jp.co.musako.presentation.controller.error;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
public class AccessDeniedController {

    @RequestMapping("/access-denied")
    public ResponseEntity<?> invoke() {

        Map<String, Object> bodies = new HashMap<>();
        bodies.put("message", "access denied");

        return new ResponseEntity<>(bodies, HttpStatus.FORBIDDEN);
    }
}
