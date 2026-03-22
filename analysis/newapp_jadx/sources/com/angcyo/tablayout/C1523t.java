package com.angcyo.tablayout;

import android.view.View;
import com.angcyo.tablayout.DslTabLayout;
import kotlin.Metadata;
import kotlin.jvm.functions.Function4;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Lambda;

@Metadata(m5310d1 = {"\u0000\u0016\n\u0000\n\u0002\u0010\u000b\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\b\n\u0002\b\u0004\u0010\u0000\u001a\u00020\u00012\u0006\u0010\u0002\u001a\u00020\u00032\u0006\u0010\u0004\u001a\u00020\u00052\u0006\u0010\u0006\u001a\u00020\u00012\u0006\u0010\u0007\u001a\u00020\u0001H\n¢\u0006\u0004\b\b\u0010\t"}, m5311d2 = {"<anonymous>", "", "itemView", "Landroid/view/View;", "index", "", "select", "fromUser", "invoke", "(Landroid/view/View;IZZ)Ljava/lang/Boolean;"}, m5312k = 3, m5313mv = {1, 6, 0}, m5315xi = 48)
/* renamed from: b.e.a.t */
/* loaded from: classes.dex */
public final class C1523t extends Lambda implements Function4<View, Integer, Boolean, Boolean, Boolean> {

    /* renamed from: c */
    public final /* synthetic */ DslTabLayout f1650c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C1523t(DslTabLayout dslTabLayout) {
        super(4);
        this.f1650c = dslTabLayout;
    }

    @Override // kotlin.jvm.functions.Function4
    public Boolean invoke(View view, Integer num, Boolean bool, Boolean bool2) {
        Function4<? super View, ? super Integer, ? super Boolean, ? super Boolean, Boolean> function4;
        Boolean invoke;
        View itemView = view;
        int intValue = num.intValue();
        boolean booleanValue = bool.booleanValue();
        boolean booleanValue2 = bool2.booleanValue();
        Intrinsics.checkNotNullParameter(itemView, "itemView");
        DslTabLayoutConfig f8767m = this.f1650c.getF8767m();
        boolean z = false;
        if (f8767m != null && (function4 = f8767m.f1590d) != null && (invoke = function4.invoke(itemView, Integer.valueOf(intValue), Boolean.valueOf(booleanValue), Boolean.valueOf(booleanValue2))) != null) {
            z = invoke.booleanValue();
        }
        return Boolean.valueOf(z);
    }
}
