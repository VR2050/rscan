package com.drake.brv.utils;

import android.graphics.drawable.Drawable;
import androidx.core.content.ContextCompat;
import com.drake.brv.DefaultDecoration;
import com.drake.brv.annotaion.DividerOrientation;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Lambda;

@Metadata(m5310d1 = {"\u0000\f\n\u0000\n\u0002\u0010\u0002\n\u0002\u0018\u0002\n\u0000\u0010\u0000\u001a\u00020\u0001*\u00020\u0002H\n¢\u0006\u0002\b\u0003"}, m5311d2 = {"<anonymous>", "", "Lcom/drake/brv/DefaultDecoration;", "invoke"}, m5312k = 3, m5313mv = {1, 6, 0}, m5315xi = 48)
/* renamed from: b.i.a.m.b */
/* loaded from: classes.dex */
public final class C1867b extends Lambda implements Function1<DefaultDecoration, Unit> {

    /* renamed from: c */
    public final /* synthetic */ int f2871c;

    /* renamed from: e */
    public final /* synthetic */ DividerOrientation f2872e;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C1867b(int i2, DividerOrientation dividerOrientation) {
        super(1);
        this.f2871c = i2;
        this.f2872e = dividerOrientation;
    }

    @Override // kotlin.jvm.functions.Function1
    public Unit invoke(DefaultDecoration defaultDecoration) {
        DefaultDecoration divider = defaultDecoration;
        Intrinsics.checkNotNullParameter(divider, "$this$divider");
        Drawable drawable = ContextCompat.getDrawable(divider.f8938a, this.f2871c);
        if (drawable == null) {
            throw new IllegalArgumentException("Drawable cannot be find");
        }
        divider.f8941d = drawable;
        divider.m3946d(this.f2872e);
        return Unit.INSTANCE;
    }
}
