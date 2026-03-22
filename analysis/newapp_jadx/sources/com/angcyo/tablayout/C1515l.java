package com.angcyo.tablayout;

import com.angcyo.tablayout.DslTabLayout;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Lambda;

@Metadata(m5310d1 = {"\u0000\f\n\u0000\n\u0002\u0010\u0002\n\u0002\u0018\u0002\n\u0000\u0010\u0000\u001a\u00020\u0001*\u00020\u0002H\n¢\u0006\u0002\b\u0003"}, m5311d2 = {"<anonymous>", "", "Lcom/angcyo/tablayout/DslGradientDrawable;", "invoke"}, m5312k = 3, m5313mv = {1, 6, 0}, m5315xi = 48)
/* renamed from: b.e.a.l */
/* loaded from: classes.dex */
public final class C1515l extends Lambda implements Function1<DslGradientDrawable, Unit> {

    /* renamed from: c */
    public final /* synthetic */ DslTabBorder f1599c;

    /* renamed from: e */
    public final /* synthetic */ boolean f1600e;

    /* renamed from: f */
    public final /* synthetic */ boolean f1601f;

    /* renamed from: g */
    public final /* synthetic */ DslTabLayout f1602g;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C1515l(DslTabBorder dslTabBorder, boolean z, boolean z2, DslTabLayout dslTabLayout) {
        super(1);
        this.f1599c = dslTabBorder;
        this.f1600e = z;
        this.f1601f = z2;
        this.f1602g = dslTabLayout;
    }

    @Override // kotlin.jvm.functions.Function1
    public Unit invoke(DslGradientDrawable dslGradientDrawable) {
        DslGradientDrawable configDrawable = dslGradientDrawable;
        Intrinsics.checkNotNullParameter(configDrawable, "$this$configDrawable");
        DslTabBorder dslTabBorder = this.f1599c;
        configDrawable.f1566o = dslTabBorder.f1605s;
        configDrawable.f1567p = dslTabBorder.f1606t;
        configDrawable.f1554c = dslTabBorder.f1555d;
        boolean z = this.f1600e;
        if (z && this.f1601f) {
            configDrawable.m656j(dslTabBorder.f1559h);
        } else if (z) {
            if (!this.f1602g.m3866d()) {
                float[] fArr = this.f1599c.f1559h;
                configDrawable.m656j(new float[]{fArr[0], fArr[1], fArr[2], fArr[3], 0.0f, 0.0f, 0.0f, 0.0f});
            } else if (this.f1602g.m3867e()) {
                float[] fArr2 = this.f1599c.f1559h;
                configDrawable.m656j(new float[]{0.0f, 0.0f, fArr2[2], fArr2[3], fArr2[4], fArr2[5], 0.0f, 0.0f});
            } else {
                float[] fArr3 = this.f1599c.f1559h;
                configDrawable.m656j(new float[]{fArr3[0], fArr3[1], 0.0f, 0.0f, 0.0f, 0.0f, fArr3[6], fArr3[7]});
            }
        } else if (this.f1601f) {
            if (!this.f1602g.m3866d()) {
                float[] fArr4 = this.f1599c.f1559h;
                configDrawable.m656j(new float[]{0.0f, 0.0f, 0.0f, 0.0f, fArr4[4], fArr4[5], fArr4[6], fArr4[7]});
            } else if (this.f1602g.m3867e()) {
                float[] fArr5 = this.f1599c.f1559h;
                configDrawable.m656j(new float[]{fArr5[0], fArr5[1], 0.0f, 0.0f, 0.0f, 0.0f, fArr5[6], fArr5[7]});
            } else {
                float[] fArr6 = this.f1599c.f1559h;
                configDrawable.m656j(new float[]{0.0f, 0.0f, fArr6[2], fArr6[3], fArr6[4], fArr6[5], 0.0f, 0.0f});
            }
        }
        return Unit.INSTANCE;
    }
}
