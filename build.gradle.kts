import java.net.URL

plugins {
    // Apply the Kotlin JVM plugin to add support for Kotlin.
    id("org.jetbrains.kotlin.jvm") version "1.6.10"
    id("io.gitlab.arturbosch.detekt") version "1.19.0"
    id("org.jmailen.kotlinter") version "3.7.0"
    id("jacoco")
    id("com.github.ben-manes.versions") version "0.39.0"
    id("org.jetbrains.dokka") version "1.6.0"
    id("io.github.gradle-nexus.publish-plugin") version "1.1.0"

    // Apply the java-library plugin for API and implementation separation.
    `java-library`

    // Publish build artifacts to an Apache Maven repository
    `maven-publish`

    // Sign artifacts
    signing
}

java {
    withJavadocJar()
    withSourcesJar()
    sourceCompatibility = JavaVersion.VERSION_11
}

allprojects {
    group = "ch.veehait.devicecheck"
    val baseVersion = "0.9.3"

    // Add the "-SNAPSHOT" suffix if the CI wasn't triggered by a new release
    version = when {
        System.getenv("GITHUB_EVENT_NAME") != "release" -> "$baseVersion-SNAPSHOT"
        else -> baseVersion
    }

    publishing {
        publications {
            create<MavenPublication>("mavenJava") {
                from(components["java"])

                pom {
                    name.set(project.name)
                    description.set("Server-side library to validate the authenticity of Apple App Attest artifacts," +
                            " written in Kotlin")
                    url.set("https://github.com/veehaitch/devicecheck-appattest")
                    licenses {
                        license {
                            name.set("The Apache Software License, Version 2.0")
                            url.set("http://www.apache.org/licenses/LICENSE-2.0")
                        }
                    }
                    developers {
                        developer {
                            id.set("veehaitch")
                            name.set("Vincent Haupert")
                            email.set("mail@vincent-haupert.de")
                        }
                    }
                    scm {
                        connection.set("scm:git:git@github.com:veehaitch/devicecheck-appattest.git")
                        developerConnection.set("scm:git:git@github.com:veehaitch/devicecheck-appattest.git")
                        url.set("https://github.com/veehaitch/devicecheck-appattest")
                    }
                }
            }
        }
    }
}

repositories {
    mavenCentral()
}

nexusPublishing {
    repositories {
        sonatype {
            nexusUrl.set(uri("https://s01.oss.sonatype.org/service/local/"))
            snapshotRepositoryUrl.set(uri("https://s01.oss.sonatype.org/content/repositories/snapshots/"))

            // env: ORG_GRADLE_PROJECT_sonatypeUsername
            val sonatypeUsername: String? by project
            username.set(sonatypeUsername)
            // env: ORG_GRADLE_PROJECT_sonatypePassword
            val sonatypePassword: String? by project
            password.set(sonatypePassword)
        }
    }
}

signing {
    // Env: ORG_GRADLE_PROJECT_signingKeyId
    val signingKeyId: String? by project
    // Env: ORG_GRADLE_PROJECT_signingKey
    // XXX: only the last 8 characters of the (sub)key ID!
    val signingKey: String? by project
    // Env: ORG_GRADLE_PROJECT_signingPassword
    val signingPassword: String? by project
    useInMemoryPgpKeys(signingKeyId, signingKey, signingPassword)
    sign(publishing.publications["mavenJava"])
}

dependencies {
    // Align versions of all Kotlin components
    implementation(platform("org.jetbrains.kotlin:kotlin-bom"))

    // Use the Kotlin JDK 8 standard library.
    implementation("org.jetbrains.kotlin:kotlin-stdlib-jdk8")

    // Use the Kotlin test library.
    testImplementation("org.jetbrains.kotlin:kotlin-test")

    // Use the Kotlin JUnit integration.
    testImplementation("org.jetbrains.kotlin:kotlin-test-junit5")

    // Kotlin coroutines
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.5.2")

    // CBOR
    val jacksonVersion = "2.13.0"
    implementation("com.fasterxml.jackson.module:jackson-module-kotlin:$jacksonVersion")
    implementation("com.fasterxml.jackson.dataformat:jackson-dataformat-cbor:$jacksonVersion")
    testImplementation("com.fasterxml.jackson.dataformat:jackson-dataformat-yaml:$jacksonVersion")
    testImplementation("com.fasterxml.jackson.datatype:jackson-datatype-jsr310:$jacksonVersion")

    // Bouncy Castle
    val bouncyCastleVersion = "1.70"
    implementation("org.bouncycastle:bcprov-jdk15on:$bouncyCastleVersion")
    implementation("org.bouncycastle:bcpkix-jdk15on:$bouncyCastleVersion")

    // Kotest
    val kotestVersion = "5.0.3"
    testImplementation("io.kotest:kotest-runner-junit5-jvm:$kotestVersion") // for kotest framework
    testImplementation("io.kotest:kotest-assertions-core-jvm:$kotestVersion") // for kotest core jvm assertions
    testImplementation("io.kotest:kotest-property-jvm:$kotestVersion") // for kotest property test

    // Testing of equals / hashcode
    testImplementation("nl.jqno.equalsverifier:equalsverifier:3.8.2")

    // MockWebServer
    testImplementation("com.squareup.okhttp3:mockwebserver:4.9.3")

    // JWS issuing
    testImplementation("com.nimbusds:nimbus-jose-jwt:9.15.2")

    // Google Guava: Bytes.indexOf
    testImplementation("com.google.guava:guava:31.0.1-jre")
}

dependencyLocking {
    lockMode.set(LockMode.STRICT)
    lockAllConfigurations()
}

tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile> {
    kotlinOptions {
        jvmTarget = "11"

        // For creation of default methods in interfaces
        freeCompilerArgs = listOf("-Xjvm-default=all")
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

jacoco {
    toolVersion = "0.8.7"
}

tasks.jacocoTestReport {
    dependsOn(tasks.test) // tests are required to run before generating the report
    reports {
        xml.required.set(true)
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
