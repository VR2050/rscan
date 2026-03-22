package p448i.p449a.p450a.p451c;

import android.os.Handler;
import java.util.List;
import me.jessyan.progressmanager.body.ProgressInfo;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p448i.p449a.p450a.InterfaceC4348a;
import p458k.AbstractC4393m0;
import p458k.C4371b0;
import p474l.InterfaceC4746h;

/* renamed from: i.a.a.c.c */
/* loaded from: classes2.dex */
public class C4352c extends AbstractC4393m0 {

    /* renamed from: e */
    public Handler f11241e;

    /* renamed from: f */
    public int f11242f;

    /* renamed from: g */
    public final AbstractC4393m0 f11243g;

    /* renamed from: h */
    public final InterfaceC4348a[] f11244h;

    /* renamed from: i */
    public final ProgressInfo f11245i = new ProgressInfo(System.currentTimeMillis());

    /* renamed from: j */
    public InterfaceC4746h f11246j;

    public C4352c(Handler handler, AbstractC4393m0 abstractC4393m0, List<InterfaceC4348a> list, int i2) {
        this.f11243g = abstractC4393m0;
        this.f11244h = (InterfaceC4348a[]) list.toArray(new InterfaceC4348a[list.size()]);
        this.f11241e = handler;
        this.f11242f = i2;
    }

    @Override // p458k.AbstractC4393m0
    /* renamed from: d */
    public long mo4925d() {
        return this.f11243g.mo4925d();
    }

    @Override // p458k.AbstractC4393m0
    /* renamed from: e */
    public C4371b0 mo4926e() {
        return this.f11243g.mo4926e();
    }

    @Override // p458k.AbstractC4393m0
    /* renamed from: k */
    public InterfaceC4746h mo4927k() {
        if (this.f11246j == null) {
            this.f11246j = C2354n.m2500o(new C4351b(this, this.f11243g.mo4927k()));
        }
        return this.f11246j;
    }
}
