package com.Modu.Stock.service;

import com.Modu.Stock.dto.UserBoardDto;
import com.Modu.Stock.entity.Board;
import com.Modu.Stock.entity.security.User;
import com.Modu.Stock.repository.BoardRepository;
import com.Modu.Stock.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional(readOnly = true)
public class BoardService {

    private  final BoardRepository boardRepository;

    private final UserRepository userRepository;


    public List<Board> findAll(){
        return boardRepository.findAll();
    }

    public Optional<Board> findById(Long id){
        return boardRepository.findById(id);
    }


    /**
     * board + user 연관관계 매핑
     */
    @Transactional
    public Board save(String username, Board board) {

        User findUsername = userRepository.findByUsername(username);

        board.addUser(findUsername);

        return boardRepository.save(board);

    }


    @Transactional
    public void deleteById(Long id) {
        boardRepository.deleteById(id);
    }


    /**
     * 내 게시글 목록 조회
     */
    public Page<UserBoardDto> findMyBoardList(Long userId, Pageable pageable) {
        return boardRepository.findMyBoardList(userId, pageable);
    }

    /**
     * 전체 게시글 조회
     */
    public Page<UserBoardDto> findAllList(String title, String content, Pageable pageable) {
        return boardRepository.findByListAll(title, content, pageable);
    }


    /**
     * 전체 게시글 조회 API
     */
    public Page<UserBoardDto> findAllBoardApi(Pageable pageable) {
        return boardRepository.findAllBoardApi(pageable);
    }
}
