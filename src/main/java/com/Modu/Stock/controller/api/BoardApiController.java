package com.Modu.Stock.controller.api;

import com.Modu.Stock.dto.UserBoardDto;
import com.Modu.Stock.entity.Board;
import com.Modu.Stock.service.BoardService;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableDefault;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequiredArgsConstructor
@Slf4j
@RequestMapping("/api")
public class BoardApiController {


    private final BoardService boardService;



    @GetMapping("/boards")
    public Result all() {
        List<Board> all = boardService.findAll();
        return new Result(all);
    }

    @PostMapping("/boards")
    public Board newBoard(@RequestBody Board newBoard, Authentication authentication) {
        String username = authentication.getName();
        return boardService.save(username,newBoard);
    }

    @GetMapping("boards/{id}")
    public Board one(@PathVariable Long id) throws Exception {
        return boardService.findById(id).orElseThrow(Exception::new);
    }


    /**
     * ADMIN 권한만 삭제 가능
     */
    @Secured("ROLE_ADMIN")
    @DeleteMapping("boards/{id}")
    void deleteBoard(@PathVariable Long id) {
        boardService.deleteById(id);
    }


    @GetMapping("boards/all")
    public Page<UserBoardDto> findTitleAndContent(@PageableDefault(page = 0, size = 10) Pageable pageable){
        log.info("in BoardApiController");
        Page<UserBoardDto> boards = boardService.findAllBoardApi(pageable);
        log.info("boards = {}", boards.getTotalPages());
        return boards;
    }


    @AllArgsConstructor
    @Getter
    static class Result<T>{
        private T data;


    }


}
