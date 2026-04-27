package io.openinstall.sdk;

/* JADX INFO: loaded from: classes3.dex */
public class f implements ch {
    private static final String[] a = {"openinstall.com", "deepinstall.com"};
    private static int b = 0;

    @Override // io.openinstall.sdk.ch
    public void a() {
        b = (b + 1) % a.length;
    }

    @Override // io.openinstall.sdk.ch
    public String b() {
        return "api2-" + as.a().e() + "." + a[b];
    }

    @Override // io.openinstall.sdk.ch
    public String c() {
        return "stat2-" + as.a().e() + "." + a[b];
    }
}
