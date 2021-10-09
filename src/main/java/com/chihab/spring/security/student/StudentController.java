package com.chihab.spring.security.student;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("api/v1/student")
public class StudentController {
    private static final List<Student> students= Arrays.asList(
            new Student(1,"yassine"),
            new Student(2,"chihab"),
            new Student(3,"yassine_chihab")
    );
    @GetMapping(path = "{studentId}")
    public Student getStudent(@PathVariable("studentId") Integer studentId){
      return students.stream()
              .filter(student -> studentId.equals(student.getStudentId()))
              .findFirst()
              .orElseThrow(()->new IllegalStateException("Student" + studentId+"does not exist"));

    }
}
