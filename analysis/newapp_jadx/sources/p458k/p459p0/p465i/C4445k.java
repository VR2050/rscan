package p458k.p459p0.p465i;

import p458k.p459p0.p461e.AbstractC4408a;

/* renamed from: k.p0.i.k */
/* loaded from: classes3.dex */
public final class C4445k extends AbstractC4408a {

    /* renamed from: e */
    public final /* synthetic */ C4440f f11891e;

    /* renamed from: f */
    public final /* synthetic */ int f11892f;

    /* renamed from: g */
    public final /* synthetic */ EnumC4436b f11893g;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4445k(String str, boolean z, String str2, boolean z2, C4440f c4440f, int i2, EnumC4436b enumC4436b) {
        super(str2, z2);
        this.f11891e = c4440f;
        this.f11892f = i2;
        this.f11893g = enumC4436b;
    }

    @Override // p458k.p459p0.p461e.AbstractC4408a
    /* renamed from: a */
    public long mo5066a() {
        this.f11891e.f11838q.mo5219c(this.f11892f, this.f11893g);
        synchronized (this.f11891e) {
            this.f11891e.f11826G.remove(Integer.valueOf(this.f11892f));
        }
        return -1L;
    }
}
