import java.net.URL

plugins {
    // Apply the Kotlin JVM plugin to add support for Kotlin.
    id("org.jetbrains.kotlin.jvm") version "1.4.20-M2"
    id("io.gitlab.arturbosch.detekt") version "1.14.2"
    id("org.jmailen.kotlinter") version "3.2.0"
    id("jacoco")
    id("com.github.ben-manes.versions") version "0.36.0"
    id("org.jetbrains.dokka") version "1.4.10.2"

    // Apply the java-library plugin for API and implementation separation.
    `java-library`

    // Publish build artifacts to an Apache Maven repository
    `maven-publish`
}

java {
    withJavadocJar()
    withSourcesJar()
    sourceCompatibility = JavaVersion.VERSION_11
}

allprojects {
    group = "ch.veehaitch.devicecheck"
    version = "0.5-SNAPSHOT"

    publishing {
        publications {
            create<MavenPublication>("default") {
                from(components["java"])
            }
        }

        repositories {
            maven {
                name = "GitHubPackages"
                url = uri("https://maven.pkg.github.com/veehaitch/devicecheck-appattest")
                credentials {
                    username = System.getenv("GITHUB_ACTOR")
                    password = System.getenv("GITHUB_TOKEN")
                }
            }
        }
    }
}

repositories {
    // Use jcenter for resolving dependencies.
    // You can declare any Maven/Ivy/file repository here.
    jcenter()
}

dependencies {
    // Align versions of all Kotlin components
    implementation(platform("org.jetbrains.kotlin:kotlin-bom"))

    // Use the Kotlin JDK 8 standard library.
    implementation("org.jetbrains.kotlin:kotlin-stdlib-jdk8")

    // Use the Kotlin test library.
    testImplementation("org.jetbrains.kotlin:kotlin-test")

    // Use the Kotlin JUnit integration.
    testImplementation("org.jetbrains.kotlin:kotlin-test-junit")

    // Kotlin coroutines
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.4.1")

    // CBOR
    val jacksonVersion = "2.11.3"
    implementation("com.fasterxml.jackson.module:jackson-module-kotlin:$jacksonVersion")
    implementation("com.fasterxml.jackson.dataformat:jackson-dataformat-cbor:$jacksonVersion")
    testImplementation("com.fasterxml.jackson.datatype:jackson-datatype-jsr310:$jacksonVersion")

    // Bouncy Castle
    val bouncyCastleVersion = "1.67"
    implementation("org.bouncycastle:bcprov-jdk15on:$bouncyCastleVersion")
    implementation("org.bouncycastle:bcpkix-jdk15on:$bouncyCastleVersion")

    // Kotest
    val kotestVersion = "4.3.1"
    testImplementation("io.kotest:kotest-runner-junit5-jvm:$kotestVersion") // for kotest framework
    testImplementation("io.kotest:kotest-assertions-core-jvm:$kotestVersion") // for kotest core jvm assertions
    testImplementation("io.kotest:kotest-property-jvm:$kotestVersion") // for kotest property test

    // Testing of equals / hashcode
    testImplementation("nl.jqno.equalsverifier:equalsverifier:3.5")

    // MockWebServer
    testImplementation("com.squareup.okhttp3:mockwebserver:4.9.0")

    // JWS issuing
    testImplementation("com.nimbusds:nimbus-jose-jwt:9.1.2")
}

tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile> {
    kotlinOptions {
        jvmTarget = "1.8"
    }
}

detekt {
    autoCorrect = true
    buildUponDefaultConfig = true
}

tasks.withType<Test> {
    useJUnitPlatform()
}

tasks.test {
    finalizedBy(tasks.jacocoTestReport) // report is always generated after tests run
}

tasks.jacocoTestReport {
    dependsOn(tasks.test) // tests are required to run before generating the report
    reports {
        xml.isEnabled = true
    }
}

tasks.dokkaHtml.configure {
    outputDirectory.set(buildDir.resolve("dokka"))

    moduleName.set("Apple App Attest Kotlin Library")

    dokkaSourceSets {
        named("main") {
            sourceLink {
                localDirectory.set(file("src/main/kotlin"))
                remoteUrl.set(URL("https://github.com/veehaitch/devicecheck-appattest/tree/main/src/main/kotlin"))
                remoteLineSuffix.set("#L")
            }
        }
    }
}
