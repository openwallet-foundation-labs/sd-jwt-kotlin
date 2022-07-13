import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
    kotlin("jvm") version "1.6.21"
    kotlin("plugin.serialization") version "1.6.21"
    application
    `maven-publish`
    id("org.jetbrains.dokka") version "1.6.20"
}

group = "com.yes"
version = "0.0-SNAPSHOT"

dependencies {
    testImplementation(kotlin("test"))
    implementation(kotlin("stdlib-jdk8"))
    implementation("org.jetbrains.dokka:dokka-gradle-plugin:1.6.20")

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

    // To add all the dependencies
    /*from(sourceSets.main.get().output)

    dependsOn(configurations.runtimeClasspath)
    from({
        configurations.runtimeClasspath.get().filter { it.name.endsWith("jar") }.map { zipTree(it) }
    })
    duplicatesStrategy = DuplicatesStrategy.INCLUDE*/
}

// Generates source jar
java {
    withSourcesJar()
}

sourceSets {
    main {
        java.srcDir("src/main/kotlin")
    }
}

// Create Javadoc jar
java {
    withJavadocJar()
}

val javadocJar = tasks.named<Jar>("javadocJar") {
    from(tasks.named("dokkaJavadoc"))
}

// Tutorial: https://docs.gradle.org/current/userguide/publishing_maven.html
publishing {
    publications {
        create<MavenPublication>("mavenJava") {
            pom {
                name.set("SD-JWT Kotlin Library (Alpha)")
                description.set("yes.com SD-JWT Kotlin Library")
                url.set("https://yes.com")
                developers {
                    developer {
                        id.set("fabian-hk")
                        name.set("Fabian Hauck")
                        email.set("fabianh@yes.com")
                    }
                }
                scm {
                    connection.set("scm:git:git@github.com:IDunion/SD-JWT-Kotlin.git")
                    developerConnection.set("scm:git:ssh://github.com:IDunion/SD-JWT-Kotlin.git")
                    url.set("https://github.com/IDunion/SD-JWT-Kotlin")
                }
            }

            from(components["java"])
        }
    }
}