package com.i12capea


import com.i12capea.data.user.MongoUserDataSource
import com.i12capea.plugins.configureMonitoring
import com.i12capea.plugins.configureRouting
import com.i12capea.plugins.configureSecurity
import com.i12capea.plugins.configureSerialization
import com.i12capea.security.hashing.SHA256HashingService
import com.i12capea.security.token.JwtTokenService
import com.i12capea.security.token.TokenConfig
import io.ktor.server.application.*
import org.litote.kmongo.coroutine.coroutine
import org.litote.kmongo.reactivestreams.KMongo

fun main(args: Array<String>): Unit =
    io.ktor.server.netty.EngineMain.main(args)

@Suppress("unused") // application.conf references the main function. This annotation prevents the IDE from marking it as unused.
fun Application.module() {
    val mongoPw = System.getenv("MONGO_PW")
    val dbName = "myapp"
    val db = KMongo.createClient(
        connectionString = "mongodb+srv://alvarocp:$mongoPw@cluster0.vtjimba.mongodb.net/$dbName?retryWrites=true&w=majority"
    ).coroutine
        .getDatabase(dbName)

    val userDataSource = MongoUserDataSource(db)
    val tokenService = JwtTokenService()
    val tokenConfig = TokenConfig(
        issuer = environment.config.property("jwt.issuer").getString(),
        audience =  environment.config.property("jwt.audience").getString(),
        expiresIn = 365L * 1000L * 60L * 60L * 24L,
        secret = System.getenv("JWT_SECRET")
    )
    val hashingService = SHA256HashingService()

    configureSerialization()
    configureMonitoring()
    configureSecurity(tokenConfig)
    configureRouting(
        userDataSource, hashingService, tokenService, tokenConfig
    )
}
