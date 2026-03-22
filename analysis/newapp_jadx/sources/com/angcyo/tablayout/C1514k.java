package com.angcyo.tablayout;

import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Lambda;

@Metadata(m5310d1 = {"\u0000\f\n\u0000\n\u0002\u0010\u0002\n\u0002\u0018\u0002\n\u0000\u0010\u0000\u001a\u00020\u0001*\u00020\u0002H\n¢\u0006\u0002\b\u0003"}, m5311d2 = {"<anonymous>", "", "Lcom/angcyo/tablayout/DslGradientDrawable;", "invoke"}, m5312k = 3, m5313mv = {1, 6, 0}, m5315xi = 48)
/* renamed from: b.e.a.k */
/* loaded from: classes.dex */
public final class C1514k extends Lambda implements Function1<DslGradientDrawable, Unit> {

    /* renamed from: c */
    public final /* synthetic */ int f1597c;

    /* renamed from: e */
    public final /* synthetic */ DslTabBorder f1598e;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C1514k(int i2, DslTabBorder dslTabBorder) {
        super(1);
        this.f1597c = i2;
        this.f1598e = dslTabBorder;
    }

    @Override // kotlin.jvm.functions.Function1
    public Unit invoke(DslGradientDrawable dslGradientDrawable) {
        DslGradientDrawable configDrawable = dslGradientDrawable;
        Intrinsics.checkNotNullParameter(configDrawable, "$this$configDrawable");
        configDrawable.f1554c = this.f1597c;
        configDrawable.m656j(this.f1598e.f1559h);
        return Unit.INSTANCE;
    }
}
