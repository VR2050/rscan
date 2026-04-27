package io.openinstall.sdk;

/* JADX INFO: loaded from: classes3.dex */
public class cr {
    private final boolean a;
    private int b;
    private String c;
    private String d;
    private cq e;

    public cr(int i, String str) {
        this.a = false;
        this.b = i;
        this.c = str;
    }

    public cr(Exception exc) {
        this.a = false;
        this.b = 0;
        this.c = exc.getMessage();
    }

    public cr(String str) {
        this.a = true;
        this.d = str;
        this.e = cq.a(str);
    }

    public boolean a() {
        return this.a;
    }

    public int b() {
        return this.b;
    }

    public String c() {
        return this.c;
    }

    public String d() {
        return this.d;
    }

    public cq e() {
        return this.e;
    }

    public boolean f() {
        return !this.a;
    }
}
