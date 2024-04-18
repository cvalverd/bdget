package com.example.bdget.controller;
import static org.mockito.Mockito.when;
import java.util.Arrays;
import java.util.List;

import org.hamcrest.Matchers;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;
import com.example.bdget.model.Student;
import com.example.bdget.service.StudentServiceImpl;


@WebMvcTest(StudentController.class)
public class StudentControllerTest {
    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private StudentServiceImpl estudianteServicioMock;

    @Test
    public void obtenerTodosTest() throws Exception {

        Student estudiante1 = new Student();
        estudiante1.setName("John");
        estudiante1.setId(1L);
        Student estudiante2 = new Student();
        estudiante2.setName("Doe");
        estudiante2.setId(2L);
        List<Student> estudiantes = Arrays.asList(estudiante1, estudiante2);
        when(estudianteServicioMock.getAllStudents()).thenReturn(estudiantes);

        mockMvc.perform(MockMvcRequestBuilders.get("/students"))
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andExpect(MockMvcResultMatchers.jsonPath("$",Matchers.hasSize(2)))
                .andExpect(MockMvcResultMatchers.jsonPath("$[0].name",Matchers.is("John")))
                .andExpect(MockMvcResultMatchers.jsonPath("$[1].name",Matchers.is("Doe")));
    }

    
}
