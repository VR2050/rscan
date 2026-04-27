package im.uwrkaxlmjj.tgnet;

/* JADX INFO: loaded from: classes2.dex */
public class NetBean {
    private String dDomain;
    private String dName;
    private String dPort;

    public NetBean(String dName, String dDomain, String dPort) {
        this.dName = dName;
        this.dDomain = dDomain;
        this.dPort = dPort;
    }

    String getdName() {
        return this.dName;
    }

    public String getdDomain() {
        return this.dDomain;
    }

    public String getdPort() {
        return this.dPort;
    }
}
