package com.pki.example.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Date;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class CsrResponseDTO {
    private Long id;
    private Long userId;
    private String csrPem;  // CSR u PEM formatu
    private String status;
    private String issuerAlias;
    private Date startDate;
    private Date endDate;
    private String certificatePath;
}


