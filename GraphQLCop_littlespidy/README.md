# GraphQL Cop (Security Auditing, Clairvoyance & InQL)

Created with the help of an AI Agent and littlespidy.

## Overview
GraphQL Cop is a Burp Suite extension built on the modern Montoya API standard that unifies GraphQL vulnerability auditing, blind schema reconstruction, and graph intelligence:
1. **Automated Security Auditing (GraphQL Cop Engine)**:
   - 13 security and Denial of Service probes ported from the graphql-cop utility.
   - Probes include: Introspection Query, GraphiQL/Playground Explorer Discovery, GET Method Support, POST-based CSRF / form-urlencoded confusion, Field Suggestions leakage, Directive Overloading DoS, Circular Introspection DoS, Field Duplication DoS, Alias Overloading DoS, Batch Queries DoS, Unhandled Error / Stack Trace Disclosure, and GET-based Mutations.
2. **InQL GraphQL Security Suite**:
   - **Engine Fingerprinting**: Probes GraphQL server implementations (Apollo, Hasura, AWS AppSync, GraphQL Yoga, Graphene, Ariadne, GraphQL-Java, WPGraphQL, Ruby GraphQL, Lighthouse, etc.) and maps them to the GraphQL Threat Matrix.
   - **Points of Interest (POI) Scanner**: Categorizes schema types and fields into 7 security sensitivity buckets (Auth, Privileged, PII, Payment, Database, Debugging, Files).
   - **Cycle Detection**: DFS recursion scanner identifying circular object graph relationships that enable query amplification DoS attacks.
   - **Batch Queries Generator**: Creates array-based and alias-packed queries with customizable batch counts for testing rate limit bypasses and batch authorization flaws.
3. **Clairvoyance Schema Oracle**:
   - Reconstructs GraphQL schema AST when introspection is disabled by parsing recursive suggestion errors ("Did you mean...?") using a dictionary oracle.
4. **Offline Localhost GraphQL Voyager**:
   - Embedded lightweight HTTP server on 127.0.0.1 serving bundled GraphQL Voyager assets offline.
   - Displays interactive schema relationship diagrams in the local browser without any external network dependencies.
5. **Native Burp HTTP Request Editor Tab ("GraphQL")**:
   - Registers a "GraphQL" tab across Proxy, Repeater, and Logger.
   - Provides structured, bidirectional synchronization of GraphQL query bodies, variables, and operation names with automatic Content-Length recalculation.
6. **Session & Authentication Management**:
   - Dedicated Session Headers dialog for setting Authorization bearer tokens, API keys, or cookies.
   - Retains standard Burp Suite / user-configured browser User-Agent without override.
   - Dedicated Stop button to halt background audits at any moment.
   - Session persistence with atomic auto-save and tab header renaming.

## Building the Extension Fat-JAR
Run the following command from the extension directory:
```bash
./gradlew clean test build jar
```
The compiled fat-JAR will be generated at:
`build/libs/graphql-cop-littlespidy-1.0.0.jar`

## Installing in Burp Suite
1. Open Burp Suite.
2. Navigate to **Extensions** -> **Installed**.
3. Click **Add**.
4. Choose **Extension type: Java**.
5. Select `GraphQLCop_littlespidy/build/libs/graphql-cop-littlespidy-1.0.0.jar`.
6. Confirm the "GraphQL Cop" suite tab and "GraphQL" request editor tab appear.
