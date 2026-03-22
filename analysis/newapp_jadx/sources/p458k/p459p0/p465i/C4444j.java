package p458k.p459p0.p465i;

import java.io.IOException;
import java.util.List;
import p458k.p459p0.p461e.AbstractC4408a;

/* renamed from: k.p0.i.j */
/* loaded from: classes3.dex */
public final class C4444j extends AbstractC4408a {

    /* renamed from: e */
    public final /* synthetic */ C4440f f11888e;

    /* renamed from: f */
    public final /* synthetic */ int f11889f;

    /* renamed from: g */
    public final /* synthetic */ List f11890g;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4444j(String str, boolean z, String str2, boolean z2, C4440f c4440f, int i2, List list) {
        super(str2, z2);
        this.f11888e = c4440f;
        this.f11889f = i2;
        this.f11890g = list;
    }

    @Override // p458k.p459p0.p461e.AbstractC4408a
    /* renamed from: a */
    public long mo5066a() {
        if (!this.f11888e.f11838q.mo5217a(this.f11889f, this.f11890g)) {
            return -1L;
        }
        try {
            this.f11888e.f11824E.m5213s(this.f11889f, EnumC4436b.CANCEL);
            synchronized (this.f11888e) {
                this.f11888e.f11826G.remove(Integer.valueOf(this.f11889f));
            }
            return -1L;
        } catch (IOException unused) {
            return -1L;
        }
    }
}
