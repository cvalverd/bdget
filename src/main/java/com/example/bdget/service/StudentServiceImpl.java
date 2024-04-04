package com.example.bdget.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.example.bdget.model.Student;
import com.example.bdget.repository.StudentRepository;

import java.util.List;
import java.util.Optional;

@Service
public class StudentServiceImpl implements StudentService{
    @Autowired
    private StudentRepository studentRepository;

    @Override
    public List<Student> getAllStudents() {
        return studentRepository.findAll();
    }

    @Override
    public Optional<Student> getStudentById(Long id) {
        return studentRepository.findById(id);
    }
    
    @Override
    public Student createStudent(Student student){
        return studentRepository.save(student);
    }

    @Override
    public Student updateStudent(Long id, Student student){
        if(studentRepository.existsById(id)){
            student.setId(id);
            return studentRepository.save(student);
        }   else {
                return null;
        }
    }

    @Override
    public void deleteStudent(Long id){
        studentRepository.deleteById(id);
    }
}
