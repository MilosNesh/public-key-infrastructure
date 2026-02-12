package com.pki.example.data;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.Date;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class IntermediateCARequest {
    private String issuerAlias;

    private String commonName;
    private String organization;
    private String organizationalUnit;

    private String country;

    private String email;

    private Date startDate;
    private Date endDate;
    private String serialNumber;

    private Integer pathLength;
}
