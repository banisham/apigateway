package com.sc.hcv.gw;

import com.sc.hcv.gw.filters.MutualTlsAuthFilter;
import com.sc.hcv.gw.filters.ThrottlingFilter;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.netflix.zuul.EnableZuulProxy;
import org.springframework.context.annotation.Bean;

@EnableZuulProxy
@SpringBootApplication
public class GatewayApplication {

    public static void main(String[] args) {
        SpringApplication.run(GatewayApplication.class, args);
    }

    @Bean
    public MutualTlsAuthFilter mutualTlsAuthFilter(){
        return new MutualTlsAuthFilter();
    }

    @Bean
    public ThrottlingFilter throttlingFilter() {
        return new ThrottlingFilter();
    }
}
