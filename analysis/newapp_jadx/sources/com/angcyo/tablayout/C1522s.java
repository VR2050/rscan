package com.angcyo.tablayout;

import android.view.View;
import com.angcyo.tablayout.DslTabLayout;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function3;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Lambda;

@Metadata(m5310d1 = {"\u0000\u001a\n\u0000\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\b\n\u0000\n\u0002\u0010\u000b\n\u0000\u0010\u0000\u001a\u00020\u00012\u0006\u0010\u0002\u001a\u00020\u00032\u0006\u0010\u0004\u001a\u00020\u00052\u0006\u0010\u0006\u001a\u00020\u0007H\n¢\u0006\u0002\b\b"}, m5311d2 = {"<anonymous>", "", "itemView", "Landroid/view/View;", "index", "", "select", "", "invoke"}, m5312k = 3, m5313mv = {1, 6, 0}, m5315xi = 48)
/* renamed from: b.e.a.s */
/* loaded from: classes.dex */
public final class C1522s extends Lambda implements Function3<View, Integer, Boolean, Unit> {

    /* renamed from: c */
    public final /* synthetic */ DslTabLayout f1649c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C1522s(DslTabLayout dslTabLayout) {
        super(3);
        this.f1649c = dslTabLayout;
    }

    @Override // kotlin.jvm.functions.Function3
    public Unit invoke(View view, Integer num, Boolean bool) {
        Function3<? super View, ? super Integer, ? super Boolean, Unit> function3;
        View itemView = view;
        int intValue = num.intValue();
        boolean booleanValue = bool.booleanValue();
        Intrinsics.checkNotNullParameter(itemView, "itemView");
        DslTabLayoutConfig f8767m = this.f1649c.getF8767m();
        if (f8767m != null && (function3 = f8767m.f1587a) != null) {
            function3.invoke(itemView, Integer.valueOf(intValue), Boolean.valueOf(booleanValue));
        }
        return Unit.INSTANCE;
    }
}
