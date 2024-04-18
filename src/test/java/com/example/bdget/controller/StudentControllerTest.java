package com.example.bdget.controller;
/*
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import java.util.List;
import java.util.stream.Collectors;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.hateoas.EntityModel;
import org.springframework.test.web.servlet.MockMvc;
import com.example.bdget.model.Student;
import com.example.bdget.service.StudentService;

@WebMvcTest(StudentController.class)
public class StudentControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private StudentService studentServiceMock;

    @Test
    public void obtenerTodosTest() throws Exception {
        Student estudiante1 = new Student();
        estudiante1.setName("John");
        estudiante1.setId(1L);
        Student estudiante2 = new Student();
        estudiante2.setName("Doe");
        estudiante2.setId(2L);
        List<Student> estudiantes = List.of(estudiante1, estudiante2);

        List<EntityModel<Student>> studentsResources = estudiantes.stream()
            .map(student -> EntityModel.of(student))
            .collect(Collectors.toList());

        when(studentServiceMock.getAllStudents()).thenReturn(estudiantes);

        mockMvc.perform(get("/students"))
                .andExpect(status().isOk())
                // Here, use direct JSON path matching without Matchers
                .andExpect(jsonPath("$._embedded.students.length()").value(2))
                .andExpect(jsonPath("$._embedded.students[0].name").value("John"))
                .andExpect(jsonPath("$._embedded.students[1].name").value("Doe"))
                .andExpect(jsonPath("$._embedded.students[0]._links.self.href").value("http://localhost:8080/students/1"))
                .andExpect(jsonPath("$._embedded.students[1]._links.self.href").value("http://localhost:8080/students/2"));
    }
}
*/