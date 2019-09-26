package jp.co.musako.domain.model;

import lombok.Data;

import java.io.Serializable;

@Data
public class Account implements Serializable {

    private Integer id;

    private String userName;

    private String password;
}
