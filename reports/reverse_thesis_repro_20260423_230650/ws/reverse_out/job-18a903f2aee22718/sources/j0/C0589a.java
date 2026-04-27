package j0;

import i0.C0569a;
import t2.j;

/* JADX INFO: renamed from: j0.a, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public final class C0589a implements InterfaceC0590b {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    public static final C0589a f9364a = new C0589a();

    private C0589a() {
    }

    @Override // j0.InterfaceC0590b
    public boolean a(C0569a c0569a) {
        j.f(c0569a, "tag");
        return false;
    }

    @Override // j0.InterfaceC0590b
    public void b(C0569a c0569a, String str, Object... objArr) {
        j.f(c0569a, "tag");
        j.f(str, "message");
        j.f(objArr, "args");
    }

    @Override // j0.InterfaceC0590b
    public void c(C0569a c0569a, String str) {
        j.f(c0569a, "tag");
        j.f(str, "message");
    }
}
