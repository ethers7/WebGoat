/*
 * SPDX-FileCopyrightText: Copyright © 2016 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.container.controller;

import jakarta.servlet.http.HttpServletRequest;
import java.util.regex.Pattern;
import org.owasp.webgoat.container.session.Course;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.servlet.ModelAndView;

@Controller
public class StartLesson {

  /**
   * The lesson name is taken from the request URL, so it is validated against the form of a lesson
   * id (the simple name of the lesson class) before it is used to select the lesson which is placed
   * in request scope.
   */
  private static final Pattern VALID_LESSON_NAME = Pattern.compile("[A-Za-z][A-Za-z0-9_]{0,63}");

  private final Course course;

  public StartLesson(Course course) {
    this.course = course;
  }

  @GetMapping(
      value = {"*.lesson"},
      produces = "text/html")
  public ModelAndView lessonPage(HttpServletRequest request) {
    var model = new ModelAndView("lesson_content");
    var path = request.getRequestURL().toString(); // we now got /a/b/c/AccessControlMatrix.lesson
    var lessonName = path.substring(path.lastIndexOf('/') + 1, path.indexOf(".lesson"));
    if (!VALID_LESSON_NAME.matcher(lessonName).matches()) {
      throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid lesson name");
    }

    course.getLessons().stream()
        .filter(l -> l.getId().equals(lessonName))
        .findFirst()
        .ifPresent(
            lesson -> {
              request.setAttribute("lesson", lesson);
            });

    return model;
  }
}
