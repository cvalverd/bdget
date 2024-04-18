package com.example.bdget.controller;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.hateoas.EntityModel;
import org.springframework.hateoas.CollectionModel;
import org.springframework.hateoas.server.mvc.WebMvcLinkBuilder;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import com.example.bdget.model.Student;
import com.example.bdget.service.StudentService;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;



@RestController
@RequestMapping("/students")
public class StudentController {


    private static final Logger log = LoggerFactory.getLogger(StudentController.class);

    @Autowired
    private StudentService studentService;

    @GetMapping
    public CollectionModel<EntityModel<Student>> getAllStudents() {
        List<Student> students = studentService.getAllStudents();
        log.info("GET /students");
        log.info("Retornando todos los estudiantes");
        List<EntityModel<Student>> studentsResources = students.stream()
            .map( student -> EntityModel.of(student,
                WebMvcLinkBuilder.linkTo(WebMvcLinkBuilder.methodOn(this.getClass()).getStudentById(student.getId())).withSelfRel()
            ))
            .collect(Collectors.toList());

        WebMvcLinkBuilder linkTo = WebMvcLinkBuilder.linkTo(WebMvcLinkBuilder.methodOn(this.getClass()).getAllStudents());
        CollectionModel<EntityModel<Student>> resources = CollectionModel.of(studentsResources, linkTo.withRel("students"));

        return resources;
    }
/* 
    public List<Student> getAllStudents(){
        log.info("GET /students");
        log.info("Retornando todos los estudiantes");
        return studentService.getAllStudents();
    }
    */    
    @GetMapping("/{id}")
    public EntityModel<Student> getStudentById(@PathVariable Long id) {
        Optional<Student> student = studentService.getStudentById(id);

        if (student.isPresent()) {
            return EntityModel.of(student.get(),
                WebMvcLinkBuilder.linkTo(WebMvcLinkBuilder.methodOn(this.getClass()).getStudentById(id)).withSelfRel(),
                WebMvcLinkBuilder.linkTo(WebMvcLinkBuilder.methodOn(this.getClass()).getAllStudents()).withRel("all-students"));
        } else {
            throw new StudentNotFoundException("Student not found with id: " + id);
        }
    }
    /*public ResponseEntity<Object> getStudentById(@PathVariable Long id) {
        Optional<Student> student = studentService.getStudentById(id);
        if (student.isEmpty()) {
            log.error("No se encontró el estudiante con ID {}", id);
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(new ErrorResponse("No se encontró el estudiante con ID " + id));
        }
        return ResponseEntity.ok(student);
    }
*/
    @PostMapping
    public EntityModel<Student> createStudent(@Validated @RequestBody Student student) {
        Student createdStudent = studentService.createStudent(student);
            return EntityModel.of(createdStudent,
                WebMvcLinkBuilder.linkTo(WebMvcLinkBuilder.methodOn(this.getClass()).getStudentById(createdStudent.getId())).withSelfRel(),
                WebMvcLinkBuilder.linkTo(WebMvcLinkBuilder.methodOn(this.getClass()).getAllStudents()).withRel("all-students"));

    }
    /*public ResponseEntity<Object> createStudent(@Validated @RequestBody Student student) {
        Student createdStudent = studentService.createStudent(student);
        if (createdStudent == null) {
            log.error("Error al crear el estudiante {}", student);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new ErrorResponse("Error al crear el estudiante"));
        }
        return ResponseEntity.ok(createdStudent);
    }
    */
    @PutMapping("/{id}")
    public EntityModel<Student> updateStudent(@PathVariable Long id, @RequestBody Student student) {
        Student updatedStudent = studentService.updateStudent(id, student);
        return EntityModel.of(updatedStudent,
                WebMvcLinkBuilder.linkTo(WebMvcLinkBuilder.methodOn(this.getClass()).getStudentById(id)).withSelfRel(),
                WebMvcLinkBuilder.linkTo(WebMvcLinkBuilder.methodOn(this.getClass()).getAllStudents()).withRel("all-students"));

    }
    /*public Student updateStudent(@PathVariable Long id, @RequestBody Student student) {
        return studentService.updateStudent(id, student);
    }
*/
    @DeleteMapping("/{id}")
    public void deleteStudent(@PathVariable Long id){
        studentService.deleteStudent(id);
    }


    static class ErrorResponse {
        private final String message;
    
        public ErrorResponse(String message) {
            this.message = message;
        }
    
        public String getMessage() {
            return message;
        }
    }


}
