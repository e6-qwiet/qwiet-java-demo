package io.shiftleft.controller;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.expression.Expression;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;


/**
 * Search login
 */
@Controller
public class SearchController {

@RequestMapping(value = "/search/user", method = RequestMethod.GET)
public String doGetSearch(@RequestParam(required = false) String foo, HttpServletResponse response, HttpServletRequest request) {
    if (foo == null) {
        throw new IllegalArgumentException("Input cannot be null");
    }
    String safeFoo = Encode.forHtml(foo); // Sanitize input to prevent HTML injection
    java.lang.Object message = new Object();
    try {
        ExpressionParser parser = new SpelExpressionParser();
        Expression exp = parser.parseExpression(safeFoo); // Parse only safe parts of the input
        message = (Object) exp.getValue();
    } catch (Exception ex) {
        System.out.println(ex.getMessage());
    }
    return message.toString();
}

    return message.toString();
  }
}

