package jp.co.musako.presentation.controller.error;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.HashMap;
import java.util.Map;

@RestControllerAdvice
@Slf4j
public class ErrorContoller {

    @ExceptionHandler(Exception.class)
    public ResponseEntity<?> invoke(Exception e) {

        log.error("error", e);

        Map<String, Object> body = new HashMap<>();
        body.put("exception", e.getMessage());
        body.put("trace", e.getStackTrace());
        return new ResponseEntity<>(body, HttpStatus.INTERNAL_SERVER_ERROR);
    }
}
