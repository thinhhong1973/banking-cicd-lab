
package com.example.banking;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(BalanceController.class)
class BalanceControllerTest {

    @Autowired
    private MockMvc mvc;

    @Test
    void balanceSuccess() throws Exception {
        mvc.perform(get("/api/v1/accounts/ACC-001/balance"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.currency").value("VND"));
    }

    @Test
    void unknownAccount() throws Exception {
        mvc.perform(get("/api/v1/accounts/ACC-999/balance"))
                .andExpect(status().isNotFound());
    }
}
