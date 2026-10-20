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
    testImplementation("org.junit.jupiter:junit-jupiter:5.10.2")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.named<Test>("test") {
    useJUnitPlatform()
}

tasks.withType<JavaCompile>().configureEach {
    sourceCompatibility = "21"
    targetCompatibility = "21"
    options.encoding = "UTF-8"
}

tasks.named<Jar>("jar") {
    archiveBaseName.set("payload-injector-littlespidy")
    archiveClassifier.set("")
    archiveVersion.set("1.0.0")
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    from(configurations.runtimeClasspath.get().filter { it.isDirectory })
    from(configurations.runtimeClasspath.get().filterNot { it.isDirectory }.map { zipTree(it) })
    from(fileTree(projectDir) {
        include("*.json")
    })
}

// ── Copy all JSON payload files into build/libs/ alongside the JAR ──
val copyPayloadsJson by tasks.registering(Copy::class) {
    description = "Copies JSON payload configuration files into build/libs/ alongside the JAR."
    from(fileTree(projectDir) {
        include("*.json")
    })
    into(layout.buildDirectory.dir("libs"))
}

tasks.named("build") {
    dependsOn(copyPayloadsJson)
}
