package com.pki.example.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class CsrUploadResponse {
    private String status;
    private Long csrId;
    private String filename;
    private long size;
}
