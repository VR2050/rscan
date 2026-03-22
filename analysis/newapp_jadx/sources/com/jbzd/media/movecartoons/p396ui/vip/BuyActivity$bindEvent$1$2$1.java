package com.jbzd.media.movecartoons.p396ui.vip;

import android.view.View;
import com.jbzd.media.movecartoons.p396ui.dialog.XAlertDialog;
import com.jbzd.media.movecartoons.p396ui.vip.BuyActivity$bindEvent$1$2$1;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Lambda;
import p005b.p006a.p007a.p008a.p013o.C0909c;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\b\n\u0002\u0010\u0002\n\u0002\b\u0002\u0010\u0001\u001a\u00020\u0000H\n¢\u0006\u0004\b\u0001\u0010\u0002"}, m5311d2 = {"", "<anonymous>", "()V"}, m5312k = 3, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class BuyActivity$bindEvent$1$2$1 extends Lambda implements Function0<Unit> {
    public final /* synthetic */ BuyActivity this$0;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public BuyActivity$bindEvent$1$2$1(BuyActivity buyActivity) {
        super(0);
        this.this$0 = buyActivity;
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: invoke$lambda-0, reason: not valid java name */
    public static final void m6016invoke$lambda0(View view) {
    }

    @Override // kotlin.jvm.functions.Function0
    public /* bridge */ /* synthetic */ Unit invoke() {
        invoke2();
        return Unit.INSTANCE;
    }

    /* renamed from: invoke, reason: avoid collision after fix types in other method */
    public final void invoke2() {
        XAlertDialog builder = new XAlertDialog(this.this$0).builder();
        C0909c value = this.this$0.getViewModel().getInfoBean().getValue();
        builder.setMsg(value == null ? null : value.f366c).setNegativeButton("取消", null).setPositiveButton("已支付", new View.OnClickListener() { // from class: b.a.a.a.t.q.a
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                BuyActivity$bindEvent$1$2$1.m6016invoke$lambda0(view);
            }
        }).show();
    }
}
