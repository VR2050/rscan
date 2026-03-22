package p005b.p067b.p068a.p069a.p070a.p078m;

import android.view.View;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Lambda;
import p005b.p067b.p068a.p069a.p070a.p077l.EnumC1311b;

/* renamed from: b.b.a.a.a.m.e */
/* loaded from: classes.dex */
public final class C1317e extends Lambda implements Function1<View, Unit> {

    /* renamed from: c */
    public final /* synthetic */ C1318f f1051c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C1317e(C1318f c1318f) {
        super(1);
        this.f1051c = c1318f;
    }

    @Override // kotlin.jvm.functions.Function1
    public Unit invoke(View view) {
        View it = view;
        Intrinsics.checkNotNullParameter(it, "it");
        C1318f c1318f = this.f1051c;
        EnumC1311b enumC1311b = c1318f.f1055d;
        if (enumC1311b == EnumC1311b.Fail) {
            c1318f.m333j();
        } else if (enumC1311b == EnumC1311b.Complete) {
            c1318f.m333j();
        } else if (c1318f.f1058g && enumC1311b == EnumC1311b.End) {
            c1318f.m333j();
        }
        return Unit.INSTANCE;
    }
}
