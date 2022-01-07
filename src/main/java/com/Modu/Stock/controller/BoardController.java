package com.Modu.Stock.controller;

import com.Modu.Stock.config.auth.PrincipalDetails;
import com.Modu.Stock.dto.UserBoardDto;
import com.Modu.Stock.entity.Board;
import com.Modu.Stock.dto.BoardDto;
import com.Modu.Stock.service.BoardService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableDefault;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.time.LocalDateTime;

@Controller
@RequiredArgsConstructor
@Slf4j
@RequestMapping("/board")
public class BoardController {


    private final BoardService boardService;


    /**
     * 게시글 전체 조회 및 검색 조건 동적 query
     */
    @GetMapping("/list")
    public String list(Model model, @PageableDefault(page = 0, size = 10) Pageable pageable,
                       @RequestParam(required = false, defaultValue = "") String searchText,
                       Authentication authentication) {
        Page<UserBoardDto> boards = boardService.findAllList(searchText, searchText, pageable);
        log.info("boards = {}", boards.getTotalElements());

        //사용자 아이디 반환
        Long userId = authenticationUserId(authentication);

        int startPage = Math.max(1, boards.getPageable().getPageNumber() - 4);
        int endPage = Math.min(boards.getTotalPages(), boards.getPageable().getPageNumber() + 4);
        model.addAttribute("startPage", startPage);
        model.addAttribute("endPage", endPage);
        model.addAttribute("boards", boards);
        model.addAttribute("userId", userId);


        return "board/list";
    }



    @GetMapping("/form")
    public String form(Model model, @RequestParam(required = false) Long id) {
        if (id == null) {
            BoardDto boardForm = new BoardDto();
            model.addAttribute("board",boardForm);
        } else {
            Board board = boardService.findById(id).orElse(null);
            model.addAttribute("board",board);
        }
        return "board/form";
    }

    @PostMapping("/form")
    public String postForm(@Valid @ModelAttribute(name = "board") BoardDto boardForm, BindingResult bindingResult, Authentication authentication){
        if (bindingResult.hasErrors()) {
            log.info("write has errors!");

            return "board/form";
        }


        String username = AuthenticationName(authentication);

        Board board = Board.createBoard(boardForm.getTitle(), boardForm.getContent(), LocalDateTime.now());

        boardService.save(username,board);

        return "redirect:/board/list";

    }

    /**
     * 사용자가 작성한 글
     */
    @GetMapping("list/myBoard")
    public String myList(@RequestParam Long id, @PageableDefault(page = 0, size = 10) Pageable pageable,
                         Model model) {
        log.info("MYList in");
        Page<UserBoardDto> findBoard = boardService.findMyBoardList(id, pageable);


        log.info("findBoard = {}", findBoard.getTotalElements());

        model.addAttribute("boards", findBoard);
        model.addAttribute("userId", id);

        return "board/myBoard";
    }

    /**
     *  User의 권한
     */
    private String AuthenticationName(Authentication authentication) {
        return authentication.getName();
    }

    /**
     * 인증 UserId 반환
     */
    private Long authenticationUserId(Authentication authentication) {
        PrincipalDetails principal = (PrincipalDetails) authentication.getPrincipal();
        Long userId = principal.getUserId();
        return userId;
    }
}

