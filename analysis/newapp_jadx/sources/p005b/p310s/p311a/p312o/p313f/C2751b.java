package p005b.p310s.p311a.p312o.p313f;

import android.hardware.Camera;
import p005b.p131d.p132a.p133a.C1499a;

/* renamed from: b.s.a.o.f.b */
/* loaded from: classes2.dex */
public final class C2751b {

    /* renamed from: a */
    public final int f7554a;

    /* renamed from: b */
    public final Camera f7555b;

    /* renamed from: c */
    public final EnumC2750a f7556c;

    /* renamed from: d */
    public final int f7557d;

    public C2751b(int i2, Camera camera, EnumC2750a enumC2750a, int i3) {
        this.f7554a = i2;
        this.f7555b = camera;
        this.f7556c = enumC2750a;
        this.f7557d = i3;
    }

    public String toString() {
        StringBuilder m586H = C1499a.m586H("Camera #");
        m586H.append(this.f7554a);
        m586H.append(" : ");
        m586H.append(this.f7556c);
        m586H.append(',');
        m586H.append(this.f7557d);
        return m586H.toString();
    }
}
