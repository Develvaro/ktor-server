package com.i12capea.security.hashing

data class SaltedHash(
    val hash: String,
    val salt: String
)
