package com.example.server_evaluacion_final.repositorio;

import com.example.server_evaluacion_final.modelo.Usuario;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UsuarioRepository extends JpaRepository<Usuario , Long> {
    Optional<Usuario> findByCodigo(String codigo);
}
