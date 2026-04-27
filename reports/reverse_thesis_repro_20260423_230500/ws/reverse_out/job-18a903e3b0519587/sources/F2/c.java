package F2;

import s2.InterfaceC0688a;

/* JADX INFO: loaded from: classes.dex */
public final class c extends a {

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    final /* synthetic */ InterfaceC0688a f742e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    final /* synthetic */ String f743f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    final /* synthetic */ boolean f744g;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(InterfaceC0688a interfaceC0688a, String str, boolean z3, String str2, boolean z4) {
        super(str2, z4);
        this.f742e = interfaceC0688a;
        this.f743f = str;
        this.f744g = z3;
    }

    @Override // F2.a
    public long f() {
        this.f742e.a();
        return -1L;
    }
}
