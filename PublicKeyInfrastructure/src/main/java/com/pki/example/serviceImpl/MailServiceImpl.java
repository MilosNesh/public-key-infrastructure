package com.pki.example.serviceImpl;

import com.pki.example.data.User;
import com.pki.example.service.MailService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.mail.MailException;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import javax.mail.MessagingException;
import javax.mail.internet.MimeMessage;
import java.util.Random;

@Service
public class MailServiceImpl implements MailService {
    @Autowired
    private JavaMailSender javaMailSender;

    @Autowired
    private Environment env;

    @Async
    public void sendNotificaitionAsync(User user) throws MailException, MessagingException {
        MimeMessage message = javaMailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message, true); // true = HTML

        helper.setTo(user.getEmail());
        helper.setFrom(env.getProperty("spring.mail.username"));
        helper.setSubject("Public Key Infrastructure - Activate Account");

        String activationLink = "https://localhost:8084/auth/activate?token=" + user.getActivationToken();

        String htmlContent = "<html>" +
                "<body style='font-family: Arial, sans-serif;'>" +
                "<div style='max-width: 600px; margin: auto; padding: 20px; border: 1px solid #ddd; border-radius: 8px;'>" +

                "<div style='text-align: center; margin-bottom: 20px;'>" +
                "<img src='https://marvel-b1-cdn.bc0a.com/f00000000100045/www.elmhurst.edu/wp-content/uploads/2020/03/cybersecurity-vs-information-security-illustration.jpg' alt='Security Logo' width='100' height='100'>" +
                "</div>" +

                "<h2 style='color: #2c3e50;'>Hi " + user.getName() + " " + user.getSurname() + ",</h2>" +
                "<p style='font-size: 16px;'>Thank you for registration.</p>" +
                "<p style='font-size: 16px;'>Please click the button below to activate your account:</p>" +

                "<div style='text-align: center; margin: 30px 0;'>" +
                "<a href='" + activationLink + "' style='background-color: #28a745; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; font-size: 16px;'>Activate Account</a>" +
                "</div>" +

                "<p style='margin-top: 40px; font-size: 12px; color: #999;'>This link will expire in 30 minutes.</p>" +

                "</div>" +
                "</body>" +
                "</html>";

        helper.setText(htmlContent, true);

        javaMailSender.send(message);
        System.out.println("HTML Email poslat!");
    }


//    private static final String CHARACTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
//    private static final Random RANDOM = new Random();
//
//    public static String generateRandomString(int length) {
//        StringBuilder stringBuilder = new StringBuilder(length);
//        for (int i = 0; i < length; i++) {
//            int index = RANDOM.nextInt(CHARACTERS.length());
//            stringBuilder.append(CHARACTERS.charAt(index));
//        }
//        return stringBuilder.toString();
//    }
}
