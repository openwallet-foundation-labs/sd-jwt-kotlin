import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
    kotlin("jvm") version "1.6.21"
    kotlin("plugin.serialization") version "1.6.21"
    application
}

group = "com.yes"
version = "1.0-SNAPSHOT"

dependencies {
    testImplementation(kotlin("test"))
    implementation(kotlin("stdlib-jdk8"))

    // https://mvnrepository.com/artifact/com.nimbusds/nimbus-jose-jwt
    implementation("com.nimbusds:nimbus-jose-jwt:9.23")
    // For ED25519 key pairs
    implementation("com.google.crypto.tink:tink:1.6.1")

    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.3.3")

    // https://mvnrepository.com/artifact/org.json/json
    implementation("org.json:json:20220320")
}

tasks.test {
    useJUnitPlatform()
}

tasks.withType<KotlinCompile> {
    kotlinOptions.jvmTarget = "1.8"
}

application {
    mainClass.set("com.yes.sd_jwt.MainKt")
}
repositories {
    mavenCentral()
}
val compileKotlin: KotlinCompile by tasks
compileKotlin.kotlinOptions {
    jvmTarget = "1.8"
}
val compileTestKotlin: KotlinCompile by tasks
compileTestKotlin.kotlinOptions {
    jvmTarget = "1.8"
}

tasks.withType<Jar> {
    manifest {
        attributes["Main-Class"] = "com.yes.sd_jwt.MainKt"
    }

    // To add all of the dependencies
    from(sourceSets.main.get().output)

    dependsOn(configurations.runtimeClasspath)
    from({
        configurations.runtimeClasspath.get().filter { it.name.endsWith("jar") }.map { zipTree(it) }
    })
    duplicatesStrategy = org.gradle.api.file.DuplicatesStrategy.INCLUDE
}