package com.jbzd.media.movecartoons.p396ui.vip;

import androidx.lifecycle.MutableLiveData;
import androidx.lifecycle.Observer;
import com.jbzd.media.movecartoons.bean.response.PayBean;
import com.jbzd.media.movecartoons.p396ui.vip.BuyActivity;
import com.jbzd.media.movecartoons.p396ui.vip.BuyActivity$bindEvent$1;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Lambda;
import org.jetbrains.annotations.NotNull;
import p005b.p006a.p007a.p008a.p009a.C0837b0;
import p005b.p006a.p007a.p008a.p009a.C0840d;
import p005b.p006a.p007a.p008a.p013o.C0909c;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p379c.p380a.C3079m0;
import p379c.p380a.C3109w0;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\f\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\u0010\u0002\u001a\u00020\u0001*\u00020\u0000H\n¢\u0006\u0004\b\u0002\u0010\u0003"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/vip/VipViewModel;", "", "<anonymous>", "(Lcom/jbzd/media/movecartoons/ui/vip/VipViewModel;)V"}, m5312k = 3, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class BuyActivity$bindEvent$1 extends Lambda implements Function1<VipViewModel, Unit> {
    public final /* synthetic */ BuyActivity this$0;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public BuyActivity$bindEvent$1(BuyActivity buyActivity) {
        super(1);
        this.this$0 = buyActivity;
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: invoke$lambda-0, reason: not valid java name */
    public static final void m6014invoke$lambda0(BuyActivity this$0, C0909c it) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullExpressionValue(it, "it");
        this$0.showVipCard(it);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: invoke$lambda-1, reason: not valid java name */
    public static final void m6015invoke$lambda1(BuyActivity activity, PayBean buyResponse) {
        Intrinsics.checkNotNullParameter(activity, "this$0");
        Intrinsics.checkNotNullExpressionValue(buyResponse, "it");
        BuyActivity$bindEvent$1$2$1 after = new BuyActivity$bindEvent$1$2$1(activity);
        Intrinsics.checkNotNullParameter(activity, "activity");
        Intrinsics.checkNotNullParameter(buyResponse, "buyResponse");
        Intrinsics.checkNotNullParameter(after, "after");
        if (Intrinsics.areEqual(buyResponse.type, "online")) {
            after.invoke();
            return;
        }
        if (Intrinsics.areEqual(buyResponse.type, "url")) {
            after.invoke();
            C0840d.a.m174d(C0840d.f235a, activity, buyResponse.url, null, null, 12);
        } else if (Intrinsics.areEqual(buyResponse.type, "alipay")) {
            String str = buyResponse.url;
            Intrinsics.checkNotNullExpressionValue(str, "buyResponse.url");
            C3109w0 c3109w0 = C3109w0.f8471c;
            C3079m0 c3079m0 = C3079m0.f8432c;
            C2354n.m2435U0(c3109w0, C3079m0.f8431b, 0, new C0837b0(activity, str, after, null), 2, null);
        }
    }

    @Override // kotlin.jvm.functions.Function1
    public /* bridge */ /* synthetic */ Unit invoke(VipViewModel vipViewModel) {
        invoke2(vipViewModel);
        return Unit.INSTANCE;
    }

    /* renamed from: invoke, reason: avoid collision after fix types in other method */
    public final void invoke2(@NotNull VipViewModel viewModels) {
        Intrinsics.checkNotNullParameter(viewModels, "$this$viewModels");
        MutableLiveData<C0909c> infoBean = viewModels.getInfoBean();
        final BuyActivity buyActivity = this.this$0;
        infoBean.observe(buyActivity, new Observer() { // from class: b.a.a.a.t.q.b
            @Override // androidx.lifecycle.Observer
            public final void onChanged(Object obj) {
                BuyActivity$bindEvent$1.m6014invoke$lambda0(BuyActivity.this, (C0909c) obj);
            }
        });
        MutableLiveData<PayBean> payBean = viewModels.getPayBean();
        final BuyActivity buyActivity2 = this.this$0;
        payBean.observe(buyActivity2, new Observer() { // from class: b.a.a.a.t.q.c
            @Override // androidx.lifecycle.Observer
            public final void onChanged(Object obj) {
                BuyActivity$bindEvent$1.m6015invoke$lambda1(BuyActivity.this, (PayBean) obj);
            }
        });
        viewModels.loadVipCard();
    }
}
