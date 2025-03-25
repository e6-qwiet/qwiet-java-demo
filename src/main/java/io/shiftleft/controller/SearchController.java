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
  public String doGetSearch(@RequestParam String foo, HttpServletResponse response, HttpServletRequest request) {
    java.lang.Object message = new Object();
[
    {
        "[javax.servlet.http.HttpServletResponse]": "VALID and ACTIVE",
        "[javax.servlet.http.HttpServletRequest]": "VALID and ACTIVE",
        "[org.apache.commons.text.StringEscapeUtils]": "VALID and ACTIVE",
        "[org.slf4j.Logger]": "VALID and ACTIVE",
        "[org.slf4j.LoggerFactory]": "VALID and ACTIVE"
    }
]

    return message.toString();
  }
}
