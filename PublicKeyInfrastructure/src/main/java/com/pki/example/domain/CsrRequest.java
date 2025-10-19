package com.pki.example.domain;

import javax.persistence.*;

@Entity
@Table(name = "csr_requests")
public class CsrRequest {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private Integer userId;
    private Long certificateId;

    private String csrPath;

    private String status;  // npr. "PENDING", "APPROVED", "REJECTED"

    private String certificatePath;

    public CsrRequest() {}

    public CsrRequest(Integer userId, Long certificateId, String csrPath, String status) {
        this.certificateId = certificateId;
        this.userId = userId;
        this.csrPath = csrPath;
        this.status = status;
    }
    public Long getId() { return id; }
    public Integer getUserId() { return userId; }
    public void setUserId(Integer userId) { this.userId = userId; }

    public Long getCertificateId() { return certificateId; }
    public void setCertificateId(Long certificateId) { this.certificateId = certificateId; }

    public String getCsrPath() { return csrPath; }
    public void setCsrPath(String csrPath) { this.csrPath = csrPath; }

    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }

    public String getCertificatePath() { return certificatePath; }
    public void setCertificatePath(String certificatePath) { this.certificatePath = certificatePath; }

}
