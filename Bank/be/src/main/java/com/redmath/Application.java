package com.redmath;
import java.util.Locale;
import java.util.TimeZone;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.transaction.annotation.EnableTransactionManagement;

//@SpringBootApplication(exclude = SecurityAutoConfiguration.class)
@SpringBootApplication
@EnableTransactionManagement
public class Application {

    static {
        init();
    }

    public static void init() {
        TimeZone.setDefault(TimeZone.getTimeZone("UTC"));
        Locale.setDefault(Locale.US);
    }
    public static void main(String[] args) {

        SpringApplication.run(Application.class, args);
    }
}
