package com.example.banking;
import java.math.BigDecimal;
import java.util.Map;
import org.springframework.web.bind.annotation.*;
@RestController
@RequestMapping("/api/v1/accounts")
public class BalanceController {
  @GetMapping("/{id}/balance")
  public Map<String,Object> balance(@PathVariable String id) {
    if (!"ACC-001".equals(id)) throw new org.springframework.web.server.ResponseStatusException(org.springframework.http.HttpStatus.NOT_FOUND);
    return Map.of("accountId", id, "balance", new BigDecimal("135000.50"), "currency", "VND");
  }
}
