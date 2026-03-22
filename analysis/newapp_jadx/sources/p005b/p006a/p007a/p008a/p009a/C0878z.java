package p005b.p006a.p007a.p008a.p009a;

import android.view.View;
import com.jbzd.media.movecartoons.bean.response.home.AdBean;
import com.jbzd.media.movecartoons.utils.MyAdAdapter;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Lambda;

/* renamed from: b.a.a.a.a.z */
/* loaded from: classes2.dex */
public final class C0878z extends Lambda implements Function1<View, Unit> {

    /* renamed from: c */
    public final /* synthetic */ MyAdAdapter f321c;

    /* renamed from: e */
    public final /* synthetic */ AdBean f322e;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0878z(MyAdAdapter myAdAdapter, AdBean adBean) {
        super(1);
        this.f321c = myAdAdapter;
        this.f322e = adBean;
    }

    @Override // kotlin.jvm.functions.Function1
    public Unit invoke(View view) {
        View it = view;
        Intrinsics.checkNotNullParameter(it, "it");
        C0840d.f235a.m176b(this.f321c.getContext(), this.f322e);
        return Unit.INSTANCE;
    }
}
