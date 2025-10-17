package com.pki.example.service;

import com.pki.example.data.User;
import org.springframework.mail.MailException;

import javax.mail.MessagingException;

public interface MailService {
    void sendNotificaitionAsync(User user) throws MailException, MessagingException;
}
