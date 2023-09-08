package com.org.SecurityJWT.repository;

import com.org.SecurityJWT.models.UserEntity;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends CrudRepository<UserEntity, Long> {

    Optional<UserEntity> findByUsername(String username);

    @Query("select u from UserEntity u where u,username = ?1")  // ?1 nos encotrara el primer resultado "u" es un alias.
    Optional<UserEntity> getNname(String username);

}
