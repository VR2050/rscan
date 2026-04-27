package r0;

import android.graphics.drawable.Animatable;
import p0.C0644c;
import t2.j;

/* JADX INFO: renamed from: r0.a, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public final class C0674a extends C0644c {

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final InterfaceC0675b f9982c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private long f9983d = -1;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private long f9984e = -1;

    public C0674a(InterfaceC0675b interfaceC0675b) {
        this.f9982c = interfaceC0675b;
    }

    @Override // p0.C0644c, p0.InterfaceC0645d
    public void j(String str, Object obj) {
        j.f(str, "id");
        this.f9983d = System.currentTimeMillis();
    }

    @Override // p0.C0644c, p0.InterfaceC0645d
    public void k(String str, Object obj, Animatable animatable) {
        j.f(str, "id");
        long jCurrentTimeMillis = System.currentTimeMillis();
        this.f9984e = jCurrentTimeMillis;
        InterfaceC0675b interfaceC0675b = this.f9982c;
        if (interfaceC0675b != null) {
            interfaceC0675b.a(jCurrentTimeMillis - this.f9983d);
        }
    }
}
