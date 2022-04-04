package com.example.cve_2020_27223.controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.text.NumberFormat;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("")
public class SampleController {

    @RequestMapping(value = "", method = RequestMethod.GET)
    public Map index(HttpServletRequest request) {
        long startTime = System.nanoTime();
        String acceptLanguage = request.getLocale().getLanguage();
        long endTime = System.nanoTime();

        HashMap<String, String> map = new HashMap<>();
        map.put("time_ns", NumberFormat.getNumberInstance().format(endTime - startTime));
        map.put("accept_language", acceptLanguage);
        return map;
    }

}
