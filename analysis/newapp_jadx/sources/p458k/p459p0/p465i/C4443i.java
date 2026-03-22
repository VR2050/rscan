package p458k.p459p0.p465i;

import java.io.IOException;
import java.util.List;
import p458k.p459p0.p461e.AbstractC4408a;

/* renamed from: k.p0.i.i */
/* loaded from: classes3.dex */
public final class C4443i extends AbstractC4408a {

    /* renamed from: e */
    public final /* synthetic */ C4440f f11884e;

    /* renamed from: f */
    public final /* synthetic */ int f11885f;

    /* renamed from: g */
    public final /* synthetic */ List f11886g;

    /* renamed from: h */
    public final /* synthetic */ boolean f11887h;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4443i(String str, boolean z, String str2, boolean z2, C4440f c4440f, int i2, List list, boolean z3) {
        super(str2, z2);
        this.f11884e = c4440f;
        this.f11885f = i2;
        this.f11886g = list;
        this.f11887h = z3;
    }

    @Override // p458k.p459p0.p461e.AbstractC4408a
    /* renamed from: a */
    public long mo5066a() {
        boolean mo5218b = this.f11884e.f11838q.mo5218b(this.f11885f, this.f11886g, this.f11887h);
        if (mo5218b) {
            try {
                this.f11884e.f11824E.m5213s(this.f11885f, EnumC4436b.CANCEL);
            } catch (IOException unused) {
                return -1L;
            }
        }
        if (!mo5218b && !this.f11887h) {
            return -1L;
        }
        synchronized (this.f11884e) {
            this.f11884e.f11826G.remove(Integer.valueOf(this.f11885f));
        }
        return -1L;
    }
}
