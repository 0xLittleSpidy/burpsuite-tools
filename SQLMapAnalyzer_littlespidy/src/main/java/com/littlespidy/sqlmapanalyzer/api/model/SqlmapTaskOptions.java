// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.sqlmapanalyzer.api.model;

import java.io.Serializable;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Encapsulates SQLMap execution options and converts them to the SQLMap REST API format.
 * Plain ASCII text only.
 */
public class SqlmapTaskOptions implements Serializable {
    private static final long serialVersionUID = 1L;

    private String url = "";
    private String method = "GET";
    private String data = "";
    private String cookie = "";
    private String agent = "";
    private String referer = "";
    private String headers = "";
    private String testParameter = "";
    private int level = 1;
    private int risk = 1;
    private String technique = "BEUSTQ";
    private String dbms = "";
    private String os = "";
    private String tamper = "";
    private String db = "";
    private String tbl = "";
    private String col = "";
    private int threads = 1;
    private int delay = 0;
    private int timeout = 30;
    private int retries = 3;
    private int timeSec = 5;

    // Enumeration flags
    private boolean getBanner = true;
    private boolean getCurrentUser = false;
    private boolean getCurrentDb = false;
    private boolean getHostname = false;
    private boolean isDba = false;
    private boolean getUsers = false;
    private boolean getPasswordHashes = false;
    private boolean getPrivileges = false;
    private boolean getRoles = false;
    private boolean getDbs = false;
    private boolean getTables = false;
    private boolean getColumns = false;
    private boolean dumpTable = false;
    private boolean dumpAll = false;

    // General & Network
    private boolean batch = true;
    private String answers = "crack=N,dict=N,continue=Y,quit=N";
    private String ignoreCode = "";
    private String proxy = "";
    private boolean tor = false;
    private String torPort = "9050";
    private String torType = "SOCKS5";
    private boolean hpp = false;
    private boolean textOnly = false;
    private boolean skipHeuristics = false;

    public SqlmapTaskOptions() {}

    public SqlmapTaskOptions(SqlmapTaskOptions other) {
        if (other != null) {
            this.url = other.url;
            this.method = other.method;
            this.data = other.data;
            this.cookie = other.cookie;
            this.agent = other.agent;
            this.referer = other.referer;
            this.headers = other.headers;
            this.testParameter = other.testParameter;
            this.level = other.level;
            this.risk = other.risk;
            this.technique = other.technique;
            this.dbms = other.dbms;
            this.os = other.os;
            this.tamper = other.tamper;
            this.db = other.db;
            this.tbl = other.tbl;
            this.col = other.col;
            this.threads = other.threads;
            this.delay = other.delay;
            this.timeout = other.timeout;
            this.retries = other.retries;
            this.timeSec = other.timeSec;
            this.getBanner = other.getBanner;
            this.getCurrentUser = other.getCurrentUser;
            this.getCurrentDb = other.getCurrentDb;
            this.getHostname = other.getHostname;
            this.isDba = other.isDba;
            this.getUsers = other.getUsers;
            this.getPasswordHashes = other.getPasswordHashes;
            this.getPrivileges = other.getPrivileges;
            this.getRoles = other.getRoles;
            this.getDbs = other.getDbs;
            this.getTables = other.getTables;
            this.getColumns = other.getColumns;
            this.dumpTable = other.dumpTable;
            this.dumpAll = other.dumpAll;
            this.batch = other.batch;
            this.answers = other.answers;
            this.ignoreCode = other.ignoreCode;
            this.proxy = other.proxy;
            this.tor = other.tor;
            this.torPort = other.torPort;
            this.torType = other.torType;
            this.hpp = other.hpp;
            this.textOnly = other.textOnly;
            this.skipHeuristics = other.skipHeuristics;
        }
    }

    public Map<String, Object> toOptionMap() {
        Map<String, Object> map = new LinkedHashMap<>();
        if (url != null && !url.isBlank()) map.put("url", url);
        if (method != null && !method.isBlank()) map.put("method", method);
        if (data != null && !data.isBlank()) map.put("data", data);
        if (cookie != null && !cookie.isBlank()) map.put("cookie", cookie);
        if (agent != null && !agent.isBlank()) map.put("agent", agent);
        if (referer != null && !referer.isBlank()) map.put("referer", referer);
        if (headers != null && !headers.isBlank()) map.put("headers", headers);
        if (testParameter != null && !testParameter.isBlank()) map.put("testParameter", testParameter);

        map.put("level", level);
        map.put("risk", risk);
        if (technique != null && !technique.isBlank()) map.put("technique", technique);
        if (dbms != null && !dbms.isBlank()) map.put("dbms", dbms);
        if (os != null && !os.isBlank()) map.put("os", os);
        if (tamper != null && !tamper.isBlank()) map.put("tamper", tamper);
        if (db != null && !db.isBlank()) map.put("db", db);
        if (tbl != null && !tbl.isBlank()) map.put("tbl", tbl);
        if (col != null && !col.isBlank()) map.put("col", col);

        map.put("threads", threads);
        map.put("delay", delay);
        map.put("timeout", timeout);
        map.put("retries", retries);
        map.put("timeSec", timeSec);

        if (getBanner) map.put("getBanner", "true");
        if (getCurrentUser) map.put("getCurrentUser", "true");
        if (getCurrentDb) map.put("getCurrentDb", "true");
        if (getHostname) map.put("getHostname", "true");
        if (isDba) map.put("isDba", "true");
        if (getUsers) map.put("getUsers", "true");
        if (getPasswordHashes) map.put("getPasswordHashes", "true");
        if (getPrivileges) map.put("getPrivileges", "true");
        if (getRoles) map.put("getRoles", "true");
        if (getDbs) map.put("getDbs", "true");
        if (getTables) map.put("getTables", "true");
        if (getColumns) map.put("getColumns", "true");
        if (dumpTable) map.put("dumpTable", "true");
        if (dumpAll) map.put("dumpAll", "true");

        if (batch) map.put("batch", "true");
        if (answers != null && !answers.isBlank()) map.put("answers", answers);
        if (ignoreCode != null && !ignoreCode.isBlank()) map.put("ignoreCode", ignoreCode);
        if (proxy != null && !proxy.isBlank()) map.put("proxy", proxy);
        if (tor) {
            map.put("tor", "true");
            map.put("torPort", torPort);
            map.put("torType", torType);
        }
        if (hpp) map.put("hpp", "true");
        if (textOnly) map.put("textOnly", "true");
        if (skipHeuristics) map.put("skipHeuristics", "true");

        return map;
    }

    public String buildCommandLine() {
        StringBuilder sb = new StringBuilder("sqlmap -u \"").append(url).append("\"");
        if (method != null && !method.equalsIgnoreCase("GET")) {
            sb.append(" --method=").append(method);
        }
        if (data != null && !data.isBlank()) {
            sb.append(" --data=\"").append(data).append("\"");
        }
        if (cookie != null && !cookie.isBlank()) {
            sb.append(" --cookie=\"").append(cookie).append("\"");
        }
        if (agent != null && !agent.isBlank()) {
            sb.append(" --user-agent=\"").append(agent).append("\"");
        }
        if (testParameter != null && !testParameter.isBlank()) {
            sb.append(" -p \"").append(testParameter).append("\"");
        }
        if (level > 1) sb.append(" --level=").append(level);
        if (risk > 1) sb.append(" --risk=").append(risk);
        if (technique != null && !technique.isBlank() && !technique.equalsIgnoreCase("BEUSTQ")) {
            sb.append(" --technique=").append(technique);
        }
        if (dbms != null && !dbms.isBlank()) sb.append(" --dbms=\"").append(dbms).append("\"");
        if (os != null && !os.isBlank()) sb.append(" --os=\"").append(os).append("\"");
        if (tamper != null && !tamper.isBlank()) sb.append(" --tamper=\"").append(tamper).append("\"");
        if (db != null && !db.isBlank()) sb.append(" -D \"").append(db).append("\"");
        if (tbl != null && !tbl.isBlank()) sb.append(" -T \"").append(tbl).append("\"");
        if (col != null && !col.isBlank()) sb.append(" -C \"").append(col).append("\"");
        if (threads > 1) sb.append(" --threads=").append(threads);
        if (delay > 0) sb.append(" --delay=").append(delay);
        if (batch) sb.append(" --batch");
        if (getBanner) sb.append(" -b");
        if (getCurrentUser) sb.append(" --current-user");
        if (getCurrentDb) sb.append(" --current-db");
        if (getHostname) sb.append(" --hostname");
        if (isDba) sb.append(" --is-dba");
        if (getUsers) sb.append(" --users");
        if (getPasswordHashes) sb.append(" --passwords");
        if (getDbs) sb.append(" --dbs");
        if (getTables) sb.append(" --tables");
        if (dumpTable) sb.append(" --dump");

        return sb.toString();
    }

    // Getters and Setters
    public String getUrl() { return url; }
    public void setUrl(String url) { this.url = url; }
    public String getMethod() { return method; }
    public void setMethod(String method) { this.method = method; }
    public String getData() { return data; }
    public void setData(String data) { this.data = data; }
    public String getCookie() { return cookie; }
    public void setCookie(String cookie) { this.cookie = cookie; }
    public String getAgent() { return agent; }
    public void setAgent(String agent) { this.agent = agent; }
    public String getReferer() { return referer; }
    public void setReferer(String referer) { this.referer = referer; }
    public String getHeaders() { return headers; }
    public void setHeaders(String headers) { this.headers = headers; }
    public String getTestParameter() { return testParameter; }
    public void setTestParameter(String testParameter) { this.testParameter = testParameter; }
    public int getLevel() { return level; }
    public void setLevel(int level) { this.level = level; }
    public int getRisk() { return risk; }
    public void setRisk(int risk) { this.risk = risk; }
    public String getTechnique() { return technique; }
    public void setTechnique(String technique) { this.technique = technique; }
    public String getDbms() { return dbms; }
    public void setDbms(String dbms) { this.dbms = dbms; }
    public String getOs() { return os; }
    public void setOs(String os) { this.os = os; }
    public String getTamper() { return tamper; }
    public void setTamper(String tamper) { this.tamper = tamper; }
    public String getDb() { return db; }
    public void setDb(String db) { this.db = db; }
    public String getTbl() { return tbl; }
    public void setTbl(String tbl) { this.tbl = tbl; }
    public String getCol() { return col; }
    public void setCol(String col) { this.col = col; }
    public int getThreads() { return threads; }
    public void setThreads(int threads) { this.threads = threads; }
    public int getDelay() { return delay; }
    public void setDelay(int delay) { this.delay = delay; }
    public int getTimeout() { return timeout; }
    public void setTimeout(int timeout) { this.timeout = timeout; }
    public int getRetries() { return retries; }
    public void setRetries(int retries) { this.retries = retries; }
    public int getTimeSec() { return timeSec; }
    public void setTimeSec(int timeSec) { this.timeSec = timeSec; }
    public boolean isGetBanner() { return getBanner; }
    public void setGetBanner(boolean getBanner) { this.getBanner = getBanner; }
    public boolean isGetCurrentUser() { return getCurrentUser; }
    public void setGetCurrentUser(boolean getCurrentUser) { this.getCurrentUser = getCurrentUser; }
    public boolean isGetCurrentDb() { return getCurrentDb; }
    public void setGetCurrentDb(boolean getCurrentDb) { this.getCurrentDb = getCurrentDb; }
    public boolean isGetHostname() { return getHostname; }
    public void setGetHostname(boolean getHostname) { this.getHostname = getHostname; }
    public boolean isDba() { return isDba; }
    public void setDba(boolean dba) { isDba = dba; }
    public boolean isGetUsers() { return getUsers; }
    public void setGetUsers(boolean getUsers) { this.getUsers = getUsers; }
    public boolean isGetPasswordHashes() { return getPasswordHashes; }
    public void setGetPasswordHashes(boolean getPasswordHashes) { this.getPasswordHashes = getPasswordHashes; }
    public boolean isGetPrivileges() { return getPrivileges; }
    public void setGetPrivileges(boolean getPrivileges) { this.getPrivileges = getPrivileges; }
    public boolean isGetRoles() { return getRoles; }
    public void setGetRoles(boolean getRoles) { this.getRoles = getRoles; }
    public boolean isGetDbs() { return getDbs; }
    public void setGetDbs(boolean getDbs) { this.getDbs = getDbs; }
    public boolean isGetTables() { return getTables; }
    public void setGetTables(boolean getTables) { this.getTables = getTables; }
    public boolean isGetColumns() { return getColumns; }
    public void setGetColumns(boolean getColumns) { this.getColumns = getColumns; }
    public boolean isDumpTable() { return dumpTable; }
    public void setDumpTable(boolean dumpTable) { this.dumpTable = dumpTable; }
    public boolean isDumpAll() { return dumpAll; }
    public void setDumpAll(boolean dumpAll) { this.dumpAll = dumpAll; }
    public boolean isBatch() { return batch; }
    public void setBatch(boolean batch) { this.batch = batch; }
    public String getAnswers() { return answers; }
    public void setAnswers(String answers) { this.answers = answers; }
    public String getIgnoreCode() { return ignoreCode; }
    public void setIgnoreCode(String ignoreCode) { this.ignoreCode = ignoreCode; }
    public String getProxy() { return proxy; }
    public void setProxy(String proxy) { this.proxy = proxy; }
    public boolean isTor() { return tor; }
    public void setTor(boolean tor) { this.tor = tor; }
    public String getTorPort() { return torPort; }
    public void setTorPort(String torPort) { this.torPort = torPort; }
    public String getTorType() { return torType; }
    public void setTorType(String torType) { this.torType = torType; }
    public boolean isHpp() { return hpp; }
    public void setHpp(boolean hpp) { this.hpp = hpp; }
    public boolean isTextOnly() { return textOnly; }
    public void setTextOnly(boolean textOnly) { this.textOnly = textOnly; }
    public boolean isSkipHeuristics() { return skipHeuristics; }
    public void setSkipHeuristics(boolean skipHeuristics) { this.skipHeuristics = skipHeuristics; }
}
