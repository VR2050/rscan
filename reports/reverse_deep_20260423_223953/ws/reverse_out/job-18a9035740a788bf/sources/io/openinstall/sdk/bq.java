package io.openinstall.sdk;

/* JADX INFO: loaded from: classes3.dex */
public class bq {
    private static bq b;
    private static final Object c = new Object();
    private final br a;

    private bq(bs bsVar) {
        this.a = bsVar.a_();
    }

    public static bq a(bs bsVar) {
        synchronized (c) {
            if (b == null) {
                b = new bq(bsVar);
            }
        }
        return b;
    }

    public String a(String str) {
        return this.a.a(str);
    }

    public void a(String str, String str2) {
        this.a.a(str, str2);
    }

    public void b(String str, String str2) {
        String strA = a(str);
        if (strA == null || !strA.equals(str2)) {
            a(str, str2);
        }
    }
}
