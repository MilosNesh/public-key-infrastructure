package com.pki.example.domain;

import javax.persistence.*;
import java.util.Date;

@Entity
@Table(name = "csr_requests")
public class CsrRequest {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private Long userId;
    private Long certificateId;

    private String csrPath;

    private String status;  // npr. "PENDING", "APPROVED", "REJECTED"

    private String certificatePath;
    
    private String issuerAlias;
    
    @Temporal(TemporalType.TIMESTAMP)
    private Date startDate;
    
    @Temporal(TemporalType.TIMESTAMP)
    private Date endDate;

    public CsrRequest() {}

    public CsrRequest(Long userId, Long certificateId, String csrPath, String status) {
        this.certificateId = certificateId;
        this.userId = userId;
        this.csrPath = csrPath;
        this.status = status;
    }
    
    public CsrRequest(Long userId, String csrPath, String status, String issuerAlias, Date startDate, Date endDate) {
        this.userId = userId;
        this.csrPath = csrPath;
        this.status = status;
        this.issuerAlias = issuerAlias;
        this.startDate = startDate;
        this.endDate = endDate;
    }
    public Long getId() { return id; }
    public Long getUserId() { return userId; }
    public void setUserId(Long userId) { this.userId = userId; }

    public Long getCertificateId() { return certificateId; }
    public void setCertificateId(Long certificateId) { this.certificateId = certificateId; }

    public String getCsrPath() { return csrPath; }
    public void setCsrPath(String csrPath) { this.csrPath = csrPath; }

    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }

    public String getCertificatePath() { return certificatePath; }
    public void setCertificatePath(String certificatePath) { this.certificatePath = certificatePath; }

    public String getIssuerAlias() { return issuerAlias; }
    public void setIssuerAlias(String issuerAlias) { this.issuerAlias = issuerAlias; }

    public Date getStartDate() { return startDate; }
    public void setStartDate(Date startDate) { this.startDate = startDate; }

    public Date getEndDate() { return endDate; }
    public void setEndDate(Date endDate) { this.endDate = endDate; }

}
