package io.openinstall.sdk;

/* JADX INFO: loaded from: classes3.dex */
public class cy {
    private String a;
    private a b;

    public enum a {
        NOT_INIT(-8, "未调用初始化", "initialize is not called"),
        INIT_ERROR(-12, "初始化时错误", "Initialization returned an error"),
        REQUEST_FAIL(-1, "请求失败", "request failed"),
        REQUEST_EXCEPTION(-1, "请求异常", "request exception"),
        REQUEST_ERROR(-2, "请求错误", "request returned an error"),
        REQUEST_TIMEOUT(-4, "请求超时，请重试", "request timeout. Please try again"),
        INVALID_INTENT(-7, "无效的 intent ", "invalid intent"),
        INVALID_DATA(-7, "无效的 data ", "invalid data");

        public final int i;
        public final String j;
        public final String k;
        public String l;

        a(int i, String str, String str2) {
            this.i = i;
            this.j = str;
            this.k = str2;
        }

        public cy a() {
            return new cy(this);
        }

        public cy a(String str) {
            this.l = str;
            return new cy(this);
        }
    }

    private cy(a aVar) {
        this.b = aVar;
    }

    private cy(String str) {
        this.a = str;
    }

    public static cy a() {
        return a("");
    }

    public static cy a(cr crVar) {
        if (!crVar.a()) {
            return crVar.b() == 0 ? a.REQUEST_EXCEPTION.a(crVar.c()) : a.REQUEST_FAIL.a(crVar.c());
        }
        cq cqVarE = crVar.e();
        return cqVarE.a() == 0 ? a(cqVarE.c()) : a.REQUEST_ERROR.a(cqVarE.b());
    }

    public static cy a(String str) {
        return new cy(str);
    }

    public String b() {
        return this.a;
    }

    public a c() {
        return this.b;
    }
}
