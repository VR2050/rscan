package com.angcyo.tablayout;

import android.view.View;
import com.angcyo.tablayout.DslTabLayout;
import java.util.List;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function4;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Lambda;

@Metadata(m5310d1 = {"\u0000\u001c\n\u0000\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010 \n\u0000\n\u0002\u0010\u000b\n\u0002\b\u0002\u0010\u0000\u001a\u00020\u00012\b\u0010\u0002\u001a\u0004\u0018\u00010\u00032\f\u0010\u0004\u001a\b\u0012\u0004\u0012\u00020\u00030\u00052\u0006\u0010\u0006\u001a\u00020\u00072\u0006\u0010\b\u001a\u00020\u0007H\n¢\u0006\u0002\b\t"}, m5311d2 = {"<anonymous>", "", "fromView", "Landroid/view/View;", "selectViewList", "", "reselect", "", "fromUser", "invoke"}, m5312k = 3, m5313mv = {1, 6, 0}, m5315xi = 48)
/* renamed from: b.e.a.u */
/* loaded from: classes.dex */
public final class C1524u extends Lambda implements Function4<View, List<? extends View>, Boolean, Boolean, Unit> {

    /* renamed from: c */
    public final /* synthetic */ DslTabLayout f1651c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C1524u(DslTabLayout dslTabLayout) {
        super(4);
        this.f1651c = dslTabLayout;
    }

    @Override // kotlin.jvm.functions.Function4
    public Unit invoke(View view, List<? extends View> list, Boolean bool, Boolean bool2) {
        Function4<? super View, ? super List<? extends View>, ? super Boolean, ? super Boolean, Unit> function4;
        View view2 = view;
        List<? extends View> selectViewList = list;
        boolean booleanValue = bool.booleanValue();
        boolean booleanValue2 = bool2.booleanValue();
        Intrinsics.checkNotNullParameter(selectViewList, "selectViewList");
        DslTabLayoutConfig f8767m = this.f1651c.getF8767m();
        if (f8767m != null && (function4 = f8767m.f1588b) != null) {
            function4.invoke(view2, selectViewList, Boolean.valueOf(booleanValue), Boolean.valueOf(booleanValue2));
        }
        return Unit.INSTANCE;
    }
}
