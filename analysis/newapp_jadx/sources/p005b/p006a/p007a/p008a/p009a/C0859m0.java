package p005b.p006a.p007a.p008a.p009a;

import android.graphics.Outline;
import android.view.View;
import android.view.ViewOutlineProvider;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

/* renamed from: b.a.a.a.a.m0 */
/* loaded from: classes2.dex */
public final class C0859m0 extends ViewOutlineProvider {

    /* renamed from: a */
    public final /* synthetic */ double f287a;

    public C0859m0(double d2) {
        this.f287a = d2;
    }

    @Override // android.view.ViewOutlineProvider
    public void getOutline(@NotNull View view, @NotNull Outline outline) {
        Intrinsics.checkNotNullParameter(view, "view");
        Intrinsics.checkNotNullParameter(outline, "outline");
        outline.setRoundRect(0, 0, view.getWidth(), view.getHeight(), C2354n.m2437V(view.getContext(), this.f287a));
    }
}
