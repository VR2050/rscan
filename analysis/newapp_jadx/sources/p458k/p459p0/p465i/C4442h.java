package p458k.p459p0.p465i;

import java.io.IOException;
import p458k.p459p0.p461e.AbstractC4408a;
import p474l.C4744f;

/* renamed from: k.p0.i.h */
/* loaded from: classes3.dex */
public final class C4442h extends AbstractC4408a {

    /* renamed from: e */
    public final /* synthetic */ C4440f f11879e;

    /* renamed from: f */
    public final /* synthetic */ int f11880f;

    /* renamed from: g */
    public final /* synthetic */ C4744f f11881g;

    /* renamed from: h */
    public final /* synthetic */ int f11882h;

    /* renamed from: i */
    public final /* synthetic */ boolean f11883i;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4442h(String str, boolean z, String str2, boolean z2, C4440f c4440f, int i2, C4744f c4744f, int i3, boolean z3) {
        super(str2, z2);
        this.f11879e = c4440f;
        this.f11880f = i2;
        this.f11881g = c4744f;
        this.f11882h = i3;
        this.f11883i = z3;
    }

    @Override // p458k.p459p0.p461e.AbstractC4408a
    /* renamed from: a */
    public long mo5066a() {
        try {
            boolean mo5220d = this.f11879e.f11838q.mo5220d(this.f11880f, this.f11881g, this.f11882h, this.f11883i);
            if (mo5220d) {
                this.f11879e.f11824E.m5213s(this.f11880f, EnumC4436b.CANCEL);
            }
            if (!mo5220d && !this.f11883i) {
                return -1L;
            }
            synchronized (this.f11879e) {
                this.f11879e.f11826G.remove(Integer.valueOf(this.f11880f));
            }
            return -1L;
        } catch (IOException unused) {
            return -1L;
        }
    }
}
