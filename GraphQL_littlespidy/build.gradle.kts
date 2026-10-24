// Created with the help of an AI Agent and littlespidy.
plugins {
    id("java")
}

repositories {
    mavenCentral()
}

dependencies {
    compileOnly("net.portswigger.burp.extensions:montoya-api:2026.4")
    implementation("com.google.code.gson:gson:2.10.1")
    testImplementation("net.portswigger.burp.extensions:montoya-api:2026.4")
    testImplementation("org.junit.jupiter:junit-jupiter:5.10.0")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.withType<JavaCompile>().configureEach {
    sourceCompatibility = "17"
    targetCompatibility = "17"
    options.encoding = "UTF-8"
}

tasks.named<Test>("test") {
    useJUnitPlatform()
    systemProperty("java.awt.headless", "true")
}

tasks.named<Jar>("jar") {
    archiveBaseName.set("graphql-littlespidy")
    archiveClassifier.set("")
    archiveVersion.set("1.0.0")
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    from(configurations.runtimeClasspath.get().filter { it.isDirectory })
    from(configurations.runtimeClasspath.get().filterNot { it.isDirectory }.map { zipTree(it) })
}
