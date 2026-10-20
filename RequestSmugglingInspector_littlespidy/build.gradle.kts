plugins {
    id("java")
}

repositories {
    mavenCentral()
}

dependencies {
    compileOnly("net.portswigger.burp.extensions:montoya-api:2026.4")
    implementation("com.google.code.gson:gson:2.10.1")
    testImplementation("org.junit.jupiter:junit-jupiter:5.10.2")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
    testImplementation("net.portswigger.burp.extensions:montoya-api:2026.4")
    testImplementation("com.google.code.gson:gson:2.10.1")
}

tasks.withType<JavaCompile>().configureEach {
    sourceCompatibility = "21"
    targetCompatibility = "21"
    options.encoding = "UTF-8"
}

tasks.named<Test>("test") {
    useJUnitPlatform()
}

tasks.named<Jar>("jar") {
    archiveBaseName.set("request-smuggling-inspector-littlespidy")
    archiveClassifier.set("")
    archiveVersion.set("1.0.0")
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    // Bundle runtime dependencies (e.g. Gson) into the fat-JAR
    from(configurations.runtimeClasspath.get().filter { it.isDirectory })
    from(configurations.runtimeClasspath.get().filterNot { it.isDirectory }.map { zipTree(it) })
}

// -- Copy the JSON payloads file next to the JAR so they are always together --
val copyPayloadsJson by tasks.registering(Copy::class) {
    description = "Copies smuggling-payloads.json into build/libs/ alongside the JAR."
    from("smuggling-payloads.json")
    into(layout.buildDirectory.dir("libs"))
}

tasks.named("build") {
    dependsOn(copyPayloadsJson)
}
