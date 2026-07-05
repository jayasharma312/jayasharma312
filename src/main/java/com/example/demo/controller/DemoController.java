package com.example.demo.controller;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.servlet.ModelAndView;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Controller
public class DemoController {

    private static final Logger logger = LoggerFactory.getLogger(DemoController.class);

    @GetMapping("/")
    public ModelAndView getUser(@AuthenticationPrincipal OidcUser user) {
        logger.info("Controller called for user: {}", user.getFullName());

        ModelAndView mav = new ModelAndView("welcome");
        mav.addObject("username", user.getFullName());
        mav.addObject("email", user.getEmail());
        mav.addObject("picture", user.getPicture());

        logger.info("Returning view name: welcome");
        return mav;
    }
}
