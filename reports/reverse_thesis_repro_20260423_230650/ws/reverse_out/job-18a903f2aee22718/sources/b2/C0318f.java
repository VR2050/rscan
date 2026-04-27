package b2;

import android.content.Context;

/* JADX INFO: renamed from: b2.f, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public class C0318f implements InterfaceC0321i {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final Context f5408a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final C0313a f5409b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final int f5410c;

    public C0318f(Context context, int i3) {
        this.f5408a = context;
        this.f5410c = i3;
        C0313a c0313a = new C0313a(5);
        this.f5409b = c0313a;
        c0313a.a(context.getApplicationInfo().sourceDir);
    }

    @Override // b2.InterfaceC0321i
    public InterfaceC0320h get() {
        return new C0317e(new C0319g(this.f5408a, this.f5409b), new C0314b(this.f5408a, this.f5409b), new C0324l(), new C0315c(this.f5408a), new C0322j(this.f5410c), new C0316d(), new C0323k(), new C0324l());
    }
}
