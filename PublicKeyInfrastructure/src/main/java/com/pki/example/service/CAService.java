package com.pki.example.service;

import com.pki.example.data.CARequest;
import com.pki.example.data.CertificateResponse;
import com.pki.example.data.IntermediateCARequest;

import java.util.List;


public interface CAService {

    CertificateResponse createRootCA(CARequest request) throws Exception;

    CertificateResponse createIntermediateCA(IntermediateCARequest request) throws Exception;

    List<CertificateResponse> getAll();
}
