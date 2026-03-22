package com.angcyo.tablayout;

import com.angcyo.tablayout.DslTabLayout;
import com.luck.picture.lib.config.PictureConfig;
import java.util.List;
import java.util.Objects;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.collections.CollectionsKt___CollectionsKt;
import kotlin.jvm.functions.Function4;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Lambda;
import p403d.p404a.p405a.p407b.p408a.C4195m;

@Metadata(m5310d1 = {"\u0000\u001c\n\u0000\n\u0002\u0010\u0002\n\u0000\n\u0002\u0010\b\n\u0000\n\u0002\u0010 \n\u0000\n\u0002\u0010\u000b\n\u0002\b\u0002\u0010\u0000\u001a\u00020\u00012\u0006\u0010\u0002\u001a\u00020\u00032\f\u0010\u0004\u001a\b\u0012\u0004\u0012\u00020\u00030\u00052\u0006\u0010\u0006\u001a\u00020\u00072\u0006\u0010\b\u001a\u00020\u0007H\n¢\u0006\u0002\b\t"}, m5311d2 = {"<anonymous>", "", "fromIndex", "", PictureConfig.EXTRA_SELECT_LIST, "", "reselect", "", "fromUser", "invoke"}, m5312k = 3, m5313mv = {1, 6, 0}, m5315xi = 48)
/* renamed from: b.e.a.v */
/* loaded from: classes.dex */
public final class C1525v extends Lambda implements Function4<Integer, List<? extends Integer>, Boolean, Boolean, Unit> {

    /* renamed from: c */
    public final /* synthetic */ DslTabLayout f1652c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C1525v(DslTabLayout dslTabLayout) {
        super(4);
        this.f1652c = dslTabLayout;
    }

    @Override // kotlin.jvm.functions.Function4
    public Unit invoke(Integer num, List<? extends Integer> list, Boolean bool, Boolean bool2) {
        ViewPagerDelegate f8756n;
        Function4<? super Integer, ? super List<Integer>, ? super Boolean, ? super Boolean, Unit> function4;
        int intValue = num.intValue();
        List<? extends Integer> selectList = list;
        boolean booleanValue = bool.booleanValue();
        boolean booleanValue2 = bool2.booleanValue();
        Intrinsics.checkNotNullParameter(selectList, "selectList");
        if (this.f1652c.getF8767m() == null) {
            C4195m.m4837v0("选择:[" + intValue + "]->" + selectList + " reselect:" + booleanValue + " fromUser:" + booleanValue2);
        }
        int intValue2 = ((Number) CollectionsKt___CollectionsKt.last((List) selectList)).intValue();
        DslTabLayout dslTabLayout = this.f1652c;
        Objects.requireNonNull(dslTabLayout);
        if (intValue2 != intValue) {
            dslTabLayout.get_scrollAnimator().cancel();
            DslTabIndicator dslTabIndicator = dslTabLayout.f8764j;
            if (dslTabIndicator.f1630I) {
                if (intValue < 0) {
                    dslTabIndicator.f1632K = intValue2;
                } else {
                    dslTabIndicator.f1632K = intValue;
                }
                dslTabIndicator.f1633L = intValue2;
                if (dslTabLayout.isInEditMode()) {
                    dslTabLayout.f8764j.f1632K = intValue2;
                } else {
                    DslTabIndicator dslTabIndicator2 = dslTabLayout.f8764j;
                    if (dslTabIndicator2.f1632K != dslTabIndicator2.f1633L) {
                        dslTabLayout.get_scrollAnimator().setFloatValues(dslTabLayout.f8764j.f1631J, 1.0f);
                        dslTabLayout.get_scrollAnimator().start();
                    }
                }
            } else {
                dslTabLayout.m3863a();
            }
        }
        DslTabLayout dslTabLayout2 = this.f1652c;
        dslTabLayout2.m3865c(intValue2, dslTabLayout2.getF8764j().f1630I);
        this.f1652c.postInvalidate();
        DslTabLayoutConfig f8767m = this.f1652c.getF8767m();
        Unit unit = null;
        if (f8767m != null && (function4 = f8767m.f1589c) != null) {
            function4.invoke(Integer.valueOf(intValue), selectList, Boolean.valueOf(booleanValue), Boolean.valueOf(booleanValue2));
            unit = Unit.INSTANCE;
        }
        if (unit == null && (f8756n = this.f1652c.getF8756N()) != null) {
            f8756n.mo642a(intValue, intValue2, booleanValue, booleanValue2);
        }
        return Unit.INSTANCE;
    }
}
