package com.pki.example.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Date;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class CAWithValidityDTO {
    private String alias;
    private Date startDate;
    private Date endDate;
}


