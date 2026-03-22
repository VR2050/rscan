package p005b.p340x.p341a.p343b.p345b.p346a;

import android.view.animation.Animation;
import android.view.animation.Transformation;
import p005b.p340x.p341a.p343b.p345b.p346a.C2870c;

/* renamed from: b.x.a.b.b.a.a */
/* loaded from: classes2.dex */
public class C2868a extends Animation {

    /* renamed from: c */
    public final /* synthetic */ C2870c.a f7811c;

    /* renamed from: e */
    public final /* synthetic */ C2870c f7812e;

    public C2868a(C2870c c2870c, C2870c.a aVar) {
        this.f7812e = c2870c;
        this.f7811c = aVar;
    }

    @Override // android.view.animation.Animation
    public void applyTransformation(float f2, Transformation transformation) {
        C2870c c2870c = this.f7812e;
        if (c2870c.f7826o) {
            C2870c.a aVar = this.f7811c;
            c2870c.m3312e(f2, aVar);
            float floor = (float) (Math.floor(aVar.f7839m / 0.8f) + 1.0d);
            float radians = (float) Math.toRadians(aVar.f7833g / (aVar.f7843q * 6.283185307179586d));
            float f3 = aVar.f7837k;
            float f4 = aVar.f7838l;
            c2870c.m3310c((((f4 - radians) - f3) * f2) + f3, f4);
            float f5 = aVar.f7839m;
            c2870c.m3308a(((floor - f5) * f2) + f5);
            return;
        }
        float radians2 = (float) Math.toRadians(r11.f7833g / (this.f7811c.f7843q * 6.283185307179586d));
        C2870c.a aVar2 = this.f7811c;
        float f6 = aVar2.f7838l;
        float f7 = aVar2.f7837k;
        float f8 = aVar2.f7839m;
        this.f7812e.m3312e(f2, aVar2);
        if (f2 <= 0.5f) {
            this.f7811c.f7830d = (C2870c.f7816e.getInterpolation(f2 / 0.5f) * (0.8f - radians2)) + f7;
        }
        if (f2 > 0.5f) {
            this.f7811c.f7831e = (C2870c.f7816e.getInterpolation((f2 - 0.5f) / 0.5f) * (0.8f - radians2)) + f6;
        }
        this.f7812e.m3308a((0.25f * f2) + f8);
        C2870c c2870c2 = this.f7812e;
        c2870c2.f7820i = ((c2870c2.f7823l / 5.0f) * 1080.0f) + (f2 * 216.0f);
        c2870c2.invalidateSelf();
    }
}
