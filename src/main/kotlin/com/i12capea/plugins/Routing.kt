package com.i12capea.plugins

import com.i12capea.authenticate
import com.i12capea.data.user.UserDataSource
import com.i12capea.getSecretInfo
import com.i12capea.security.hashing.HashingService
import com.i12capea.security.token.TokenConfig
import com.i12capea.security.token.TokenService
import com.i12capea.signIn
import com.i12capea.signUp
import io.ktor.server.routing.*
import io.ktor.server.response.*
import io.ktor.server.application.*

fun Application.configureRouting(
    userDataSource: UserDataSource,
    hashingService: HashingService,
    tokenService: TokenService,
    tokenConfig: TokenConfig,
) {
    routing {
        signIn(hashingService, userDataSource, tokenService, tokenConfig)
        signUp(hashingService, userDataSource)
        authenticate()
        getSecretInfo()
    }
}
