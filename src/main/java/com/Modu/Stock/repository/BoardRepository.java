package com.Modu.Stock.repository;


import com.Modu.Stock.entity.Board;
import com.Modu.Stock.repository.querydsl.BoardRepositoryCustom;
import org.springframework.data.jpa.repository.JpaRepository;

public interface BoardRepository extends JpaRepository<Board, Long>, BoardRepositoryCustom {


}
