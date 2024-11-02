# crypto
crypto library for eth that use the MIT license.

### use case

- Verification signature

```go
message := "hello"
address := "0x8fd379246834eac74B8419FfdA202CF8051F7A03"

sign := "0x182dc2e4432e152adb9c8a8837474986469144160b09f77a45645b6d9240ceb0368de7f12b5c522171ea4139c8dfa030c868710d39eedb0172e69a88904174d400"

valid := ValidateSignature(message, sign, address)

println(valid) // true
```

