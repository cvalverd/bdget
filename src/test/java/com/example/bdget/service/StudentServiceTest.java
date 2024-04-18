package com.example.bdget.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import com.example.bdget.model.Student;
import com.example.bdget.repository.StudentRepository;

@ExtendWith(MockitoExtension.class)
public class StudentServiceTest {
    @InjectMocks
    private StudentServiceImpl estudianteServicio;

    @Mock
    private StudentRepository estudianteRepositoryMock;

    @Test
    public void guardarEstudianteTest() {

        Student estudiante = new Student();
        estudiante.setName("Jose Rondon");

        when(estudianteRepositoryMock.save(any())).thenReturn(estudiante);

        Student resultado = estudianteServicio.createStudent(estudiante);

        assertEquals("Jose Rondon", resultado.getName());
    }
}
