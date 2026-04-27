package org.webrtc.mozi;

/* JADX INFO: loaded from: classes3.dex */
public class McsEvent {
    private String attr;
    private long code;
    private String desc;
    private long level;
    private String module;

    public enum McsEventLevel {
        kMcsEventDebug(0, "debug"),
        kMcsEventInfo(1, "info"),
        kMcsEventWarning(2, "warning"),
        kMcsEventError(3, "error");

        private long code;
        private String msg;

        McsEventLevel(long code, String msg) {
            this.code = code;
            this.msg = msg;
        }

        public String getMsg() {
            return this.msg;
        }

        public long getCode() {
            return this.code;
        }
    }

    public McsEvent(String module, long level, long code, String desc, String attr) {
        this.module = module;
        this.level = level;
        this.code = code;
        this.desc = desc;
        this.attr = attr;
    }

    public String getModule() {
        return this.module;
    }

    public void setModule(String module) {
        this.module = module;
    }

    public long getLevel() {
        return this.level;
    }

    public void setLevel(long level) {
        this.level = level;
    }

    public long getCode() {
        return this.code;
    }

    public void setCode(long code) {
        this.code = code;
    }

    public String getDesc() {
        return this.desc;
    }

    public void setDesc(String desc) {
        this.desc = desc;
    }

    public String getAttr() {
        return this.attr;
    }

    public void setAttr(String attr) {
        this.attr = attr;
    }

    static McsEvent create(String module, long level, long code, String desc, String attr) {
        return new McsEvent(module, level, code, desc, attr);
    }
}
