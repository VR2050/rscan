package p005b.p340x.p341a.p343b.p345b.p346a;

import android.view.animation.Animation;
import p005b.p340x.p341a.p343b.p345b.p346a.C2870c;

/* renamed from: b.x.a.b.b.a.b */
/* loaded from: classes2.dex */
public class AnimationAnimationListenerC2869b implements Animation.AnimationListener {

    /* renamed from: a */
    public final /* synthetic */ C2870c.a f7813a;

    /* renamed from: b */
    public final /* synthetic */ C2870c f7814b;

    public AnimationAnimationListenerC2869b(C2870c c2870c, C2870c.a aVar) {
        this.f7814b = c2870c;
        this.f7813a = aVar;
    }

    @Override // android.view.animation.Animation.AnimationListener
    public void onAnimationEnd(Animation animation) {
    }

    @Override // android.view.animation.Animation.AnimationListener
    public void onAnimationRepeat(Animation animation) {
        C2870c.a aVar = this.f7813a;
        aVar.f7837k = aVar.f7830d;
        aVar.f7838l = aVar.f7831e;
        aVar.f7839m = aVar.f7832f;
        aVar.m3313a((aVar.f7836j + 1) % aVar.f7835i.length);
        C2870c.a aVar2 = this.f7813a;
        aVar2.f7830d = aVar2.f7831e;
        C2870c c2870c = this.f7814b;
        if (!c2870c.f7826o) {
            c2870c.f7823l = (c2870c.f7823l + 1.0f) % 5.0f;
            return;
        }
        c2870c.f7826o = false;
        animation.setDuration(1332L);
        this.f7814b.m3311d(false);
    }

    @Override // android.view.animation.Animation.AnimationListener
    public void onAnimationStart(Animation animation) {
        this.f7814b.f7823l = 0.0f;
    }
}
