package com.redmath.account;


import com.fasterxml.jackson.databind.ObjectMapper;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultHandlers;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;
import org.springframework.web.context.WebApplicationContext;

import java.util.regex.Matcher;

@SpringBootTest
@AutoConfigureMockMvc
public class AccountControllerTest {
    @Autowired
    private MockMvc mvc;
    @Autowired
    private WebApplicationContext context;

    @Autowired
    private ObjectMapper objectMapper;
    @Mock
    private AccountService accountService;

    @Mock
    private AccountRepository repository;
    @BeforeEach
    public void setUp() {
        MockitoAnnotations.openMocks(this);
    }
    //private ApplicationContext applicationContext;

    @Test
    @Order(1)
    public void testFindAll() throws Exception {
        //List<News> news = repository.findAll();
        String expectedJsonResponse = "[{\"password\":\"password1\",\"name\":\"account1\",\"email\":\"email1\",\"address\":\"address1\",\"id\":1},{\"password\":\"password2\",\"name\":\"account2\",\"email\":\"email2\",\"address\":\"address2\",\"id\":2}]";
        mvc.perform(MockMvcRequestBuilders.get("/api/v1/account"))
                .andDo(MockMvcResultHandlers.print())
                .andExpect(MockMvcResultMatchers.status().is2xxSuccessful())
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andExpect(MockMvcResultMatchers.content().string(Matchers.equalTo(expectedJsonResponse)));

//        mvc.perform(MockMvcRequestBuilders.get("/api/v1/account/1"))
//                //.with(testUser("reporter", "REPORTER")))
//                .andDo(MockMvcResultHandlers.print())
//                .andExpect(MockMvcResultMatchers.status().is2xxSuccessful())
//                .andExpect(MockMvcResultMatchers.jsonPath("$.content.id", Matchers.is(1)))
//                .andExpect(MockMvcResultMatchers.jsonPath("$.content.name", Matchers.is("title 1")))
//                .andExpect(MockMvcResultMatchers.jsonPath("$.content.password", Matchers.is("details 1")))
//                .andExpect(MockMvcResultMatchers.jsonPath("$.content.email", Matchers.is("tags 1")))
//                .andExpect(MockMvcResultMatchers.jsonPath("$.content.address", Matchers.notNullValue()));
    }

    @Test
    @Order(2)
    public void testcreate() throws Exception {


        mvc.perform(MockMvcRequestBuilders.post("/api/v1/account")
                        //.with(testUser("reporter", "REPORTER"))
                        //.with(SecurityMockMvcRequestPostProcessors.csrf())
                        .contentType("application/json")
                        .content("{\"password\":\"password5\",\"name\":\"account5\",\"email\":\"email5\",\"address\":\"address5\",\"id\":6}"))
                .andDo(MockMvcResultHandlers.print())
                .andExpect(MockMvcResultMatchers.status().is2xxSuccessful())
                .andExpect(MockMvcResultMatchers.jsonPath("$.content.id", Matchers.is(6)))
                .andExpect(MockMvcResultMatchers.jsonPath("$.content.name", Matchers.is("account5")))
                .andExpect(MockMvcResultMatchers.jsonPath("$.content.email", Matchers.is("email5")))
                .andExpect(MockMvcResultMatchers.jsonPath("$.content.password", Matchers.is("password5")))
                .andExpect(MockMvcResultMatchers.jsonPath("$.content.address", Matchers.is("address5")));


//        String expectedJsonResponse = "{\"password\":\"password5\",\"name\":\"account5\",\"email\":\"email5\",\"address\":\"address5\",\"id\":5}";
//        mvc.perform(MockMvcRequestBuilders.post("/api/v1/account")
//                        //.with(testUser("reporter", "REPORTER"))
//                        //.with(SecurityMockMvcRequestPostProcessors.csrf())
//                        .contentType("application/json")
//                        .content(expectedJsonResponse))
//                .andDo(MockMvcResultHandlers.print())
//                .andExpect(MockMvcResultMatchers.status().isConflict());

    }

    @Test
    @Order(3)
    public void testPut() throws Exception{
        mvc.perform(MockMvcRequestBuilders.put("/api/v1/account")
                        .contentType("application/json")
                        .content("{\"password\":\"password5\",\"name\":\"account5\",\"email\":\"email1\",\"address\":\"address1\",\"id\":1}"))
                .andDo(MockMvcResultHandlers.print())
                .andExpect(MockMvcResultMatchers.status().is2xxSuccessful());


    }

//    @Test
//    @Order(4)
//    public void testDelete() throws Exception{
//        mvc.perform(MockMvcRequestBuilders.delete("/api/v1/account/2").contentType("application/json"))
//                .andDo(MockMvcResultHandlers.print())
//                .andExpect(MockMvcResultMatchers.status().is2xxSuccessful())
//                .andExpect(MockMvcResultMatchers.content().string(""));
//    }


}