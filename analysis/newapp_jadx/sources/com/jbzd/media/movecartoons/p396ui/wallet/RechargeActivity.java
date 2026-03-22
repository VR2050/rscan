package com.jbzd.media.movecartoons.p396ui.wallet;

import android.content.Context;
import android.widget.TextView;
import androidx.lifecycle.Observer;
import androidx.recyclerview.widget.RecyclerView;
import com.drake.brv.BindingAdapter;
import com.drake.brv.annotaion.DividerOrientation;
import com.jbzd.media.movecartoons.MyApp;
import com.jbzd.media.movecartoons.bean.response.RechargeBean;
import com.jbzd.media.movecartoons.databinding.ActivityRechargeBinding;
import com.jbzd.media.movecartoons.p396ui.chat.ChatDetailActivity;
import com.jbzd.media.movecartoons.p396ui.dialog.PayPointBottomSheetDialog;
import com.jbzd.media.movecartoons.p396ui.wallet.RechargeActivity;
import com.jbzd.media.movecartoons.p396ui.web.WebActivity;
import com.qnmd.adnnm.da0yzo.R;
import com.qunidayede.supportlibrary.core.view.BaseVMActivity;
import java.util.HashMap;
import java.util.List;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Reflection;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p006a.p007a.p008a.p009a.C0852j;
import p005b.p006a.p007a.p008a.p017r.C0917a;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p403d.p404a.p405a.p407b.p408a.C4195m;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000.\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0005\n\u0002\u0010\u000e\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0005\u0018\u0000 \u00152\u000e\u0012\u0004\u0012\u00020\u0002\u0012\u0004\u0012\u00020\u00030\u0001:\u0001\u0015B\u0007¢\u0006\u0004\b\u0014\u0010\nJ\u0017\u0010\u0007\u001a\u00020\u00062\u0006\u0010\u0005\u001a\u00020\u0004H\u0002¢\u0006\u0004\b\u0007\u0010\bJ\u000f\u0010\t\u001a\u00020\u0006H\u0016¢\u0006\u0004\b\t\u0010\nJ\u000f\u0010\u000b\u001a\u00020\u0006H\u0016¢\u0006\u0004\b\u000b\u0010\nJ\u000f\u0010\r\u001a\u00020\fH\u0016¢\u0006\u0004\b\r\u0010\u000eJ\u000f\u0010\u000f\u001a\u00020\fH\u0016¢\u0006\u0004\b\u000f\u0010\u000eJ\u000f\u0010\u0010\u001a\u00020\u0006H\u0016¢\u0006\u0004\b\u0010\u0010\nR\u0018\u0010\u0012\u001a\u0004\u0018\u00010\u00118\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\u0012\u0010\u0013¨\u0006\u0016"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/wallet/RechargeActivity;", "Lcom/qunidayede/supportlibrary/core/view/BaseVMActivity;", "Lcom/jbzd/media/movecartoons/databinding/ActivityRechargeBinding;", "Lcom/jbzd/media/movecartoons/ui/wallet/RechargeViewModel;", "Lcom/jbzd/media/movecartoons/bean/response/RechargeBean$ProductsBean;", "productsBean", "", "showPaymentDialog", "(Lcom/jbzd/media/movecartoons/bean/response/RechargeBean$ProductsBean;)V", "bindEvent", "()V", "initView", "", "getTopBarTitle", "()Ljava/lang/String;", "getRightTitle", "clickRight", "Lcom/jbzd/media/movecartoons/ui/dialog/PayPointBottomSheetDialog;", "paymentDialog", "Lcom/jbzd/media/movecartoons/ui/dialog/PayPointBottomSheetDialog;", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class RechargeActivity extends BaseVMActivity<ActivityRechargeBinding, RechargeViewModel> {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    @Nullable
    private PayPointBottomSheetDialog paymentDialog;

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0016\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0005\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0007\u0010\bJ\u0015\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u0003\u001a\u00020\u0002¢\u0006\u0004\b\u0005\u0010\u0006¨\u0006\t"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/wallet/RechargeActivity$Companion;", "", "Landroid/content/Context;", "context", "", "start", "(Landroid/content/Context;)V", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public final void start(@NotNull Context context) {
            C1499a.m602X(context, "context", context, RechargeActivity.class);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* JADX WARN: Multi-variable type inference failed */
    /* renamed from: bindEvent$lambda-0, reason: not valid java name */
    public static final void m6019bindEvent$lambda0(RechargeActivity this$0, RechargeBean rechargeBean) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        ((ActivityRechargeBinding) this$0.getBodyBinding()).tvAmount.setText(this$0.getString(R.string.recharge_yuan, new Object[]{rechargeBean.getBalance()}));
        RecyclerView recyclerView = ((ActivityRechargeBinding) this$0.getBodyBinding()).rechargeCoinList;
        Intrinsics.checkNotNullExpressionValue(recyclerView, "bodyBinding.rechargeCoinList");
        BindingAdapter.m3923a(C4195m.m4793Z(recyclerView), rechargeBean.getProducts(), false, 0, 6, null);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void showPaymentDialog(RechargeBean.ProductsBean productsBean) {
        if (this.paymentDialog == null) {
            this.paymentDialog = PayPointBottomSheetDialog.INSTANCE.getShareBottomSheetDialog(this, getViewModel());
        }
        PayPointBottomSheetDialog payPointBottomSheetDialog = this.paymentDialog;
        Intrinsics.checkNotNull(payPointBottomSheetDialog);
        if (payPointBottomSheetDialog.isShowing()) {
            return;
        }
        StringBuilder m586H = C1499a.m586H("支付");
        m586H.append((Object) productsBean.priceZero);
        m586H.append((char) 20803);
        productsBean.button_text = m586H.toString();
        PayPointBottomSheetDialog payPointBottomSheetDialog2 = this.paymentDialog;
        if (payPointBottomSheetDialog2 != null) {
            List<RechargeBean.ProductsBean.PaymentsBean> list = productsBean.payments;
            RechargeBean value = getViewModel().getInfoBean().getValue();
            payPointBottomSheetDialog2.setRechargeShowData(list, productsBean, value == null ? null : value.getTips());
        }
        PayPointBottomSheetDialog payPointBottomSheetDialog3 = this.paymentDialog;
        if (payPointBottomSheetDialog3 == null) {
            return;
        }
        payPointBottomSheetDialog3.show();
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseVMActivity, com.qunidayede.supportlibrary.core.view.BaseBindingActivity
    public void _$_clearFindViewByIdCache() {
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseBindingActivity, p005b.p327w.p330b.p331b.p334e.InterfaceC2847j
    public void bindEvent() {
        getViewModel().getInfoBean().observe(this, new Observer() { // from class: b.a.a.a.t.r.a
            @Override // androidx.lifecycle.Observer
            public final void onChanged(Object obj) {
                RechargeActivity.m6019bindEvent$lambda0(RechargeActivity.this, (RechargeBean) obj);
            }
        });
        getViewModel().loadInfo();
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseBindingActivity
    public void clickRight() {
        BillActivity.INSTANCE.start(this);
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseBindingActivity
    @NotNull
    public String getRightTitle() {
        return "消费明细";
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseBindingActivity
    @NotNull
    public String getTopBarTitle() {
        String string = getString(R.string.recharge);
        Intrinsics.checkNotNullExpressionValue(string, "getString(R.string.recharge)");
        return string;
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseBindingActivity
    public void initView() {
        C0917a c0917a = C0917a.f372a;
        HashMap m595Q = C1499a.m595Q("object_type", "enter_buy_point");
        Unit unit = Unit.INSTANCE;
        C0917a.m221e(c0917a, "system/track", Object.class, m595Q, C0852j.f253c, null, false, false, null, false, 432);
        bodyBinding(new Function1<ActivityRechargeBinding, Unit>() { // from class: com.jbzd.media.movecartoons.ui.wallet.RechargeActivity$initView$1
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(ActivityRechargeBinding activityRechargeBinding) {
                invoke2(activityRechargeBinding);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull ActivityRechargeBinding bodyBinding) {
                Intrinsics.checkNotNullParameter(bodyBinding, "$this$bodyBinding");
                RecyclerView rechargeCoinList = bodyBinding.rechargeCoinList;
                Intrinsics.checkNotNullExpressionValue(rechargeCoinList, "rechargeCoinList");
                C4195m.m4821n0(rechargeCoinList, 3, 0, false, false, 14);
                C4195m.m4784Q(rechargeCoinList, C4195m.m4785R(6.0f), DividerOrientation.GRID);
                final RechargeActivity rechargeActivity = RechargeActivity.this;
                C4195m.m4774J0(rechargeCoinList, new Function2<BindingAdapter, RecyclerView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.wallet.RechargeActivity$initView$1.1
                    {
                        super(2);
                    }

                    @Override // kotlin.jvm.functions.Function2
                    public /* bridge */ /* synthetic */ Unit invoke(BindingAdapter bindingAdapter, RecyclerView recyclerView) {
                        invoke2(bindingAdapter, recyclerView);
                        return Unit.INSTANCE;
                    }

                    /* renamed from: invoke, reason: avoid collision after fix types in other method */
                    public final void invoke2(@NotNull BindingAdapter bindingAdapter, @NotNull RecyclerView recyclerView) {
                        boolean m616f0 = C1499a.m616f0(bindingAdapter, "$this$setup", recyclerView, "it", RechargeBean.ProductsBean.class);
                        final int i2 = R.layout.item_recharge_coin;
                        if (m616f0) {
                            bindingAdapter.f8910l.put(Reflection.typeOf(RechargeBean.ProductsBean.class), new Function2<Object, Integer, Integer>() { // from class: com.jbzd.media.movecartoons.ui.wallet.RechargeActivity$initView$1$1$invoke$$inlined$addType$1
                                /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                                {
                                    super(2);
                                }

                                @NotNull
                                public final Integer invoke(@NotNull Object obj, int i3) {
                                    Intrinsics.checkNotNullParameter(obj, "$this$null");
                                    return Integer.valueOf(i2);
                                }

                                @Override // kotlin.jvm.functions.Function2
                                public /* bridge */ /* synthetic */ Integer invoke(Object obj, Integer num) {
                                    return invoke(obj, num.intValue());
                                }
                            });
                        } else {
                            bindingAdapter.f8909k.put(Reflection.typeOf(RechargeBean.ProductsBean.class), new Function2<Object, Integer, Integer>() { // from class: com.jbzd.media.movecartoons.ui.wallet.RechargeActivity$initView$1$1$invoke$$inlined$addType$2
                                /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                                {
                                    super(2);
                                }

                                @NotNull
                                public final Integer invoke(@NotNull Object obj, int i3) {
                                    Intrinsics.checkNotNullParameter(obj, "$this$null");
                                    return Integer.valueOf(i2);
                                }

                                @Override // kotlin.jvm.functions.Function2
                                public /* bridge */ /* synthetic */ Integer invoke(Object obj, Integer num) {
                                    return invoke(obj, num.intValue());
                                }
                            });
                        }
                        int[] iArr = {R.id.root};
                        final RechargeActivity rechargeActivity2 = RechargeActivity.this;
                        bindingAdapter.m3937n(iArr, new Function2<BindingAdapter.BindingViewHolder, Integer, Unit>() { // from class: com.jbzd.media.movecartoons.ui.wallet.RechargeActivity.initView.1.1.1
                            {
                                super(2);
                            }

                            @Override // kotlin.jvm.functions.Function2
                            public /* bridge */ /* synthetic */ Unit invoke(BindingAdapter.BindingViewHolder bindingViewHolder, Integer num) {
                                invoke(bindingViewHolder, num.intValue());
                                return Unit.INSTANCE;
                            }

                            public final void invoke(@NotNull BindingAdapter.BindingViewHolder onClick, int i3) {
                                Intrinsics.checkNotNullParameter(onClick, "$this$onClick");
                                RechargeActivity.this.showPaymentDialog((RechargeBean.ProductsBean) onClick.m3942b());
                            }
                        });
                        bindingAdapter.m3935l(new Function1<BindingAdapter.BindingViewHolder, Unit>() { // from class: com.jbzd.media.movecartoons.ui.wallet.RechargeActivity.initView.1.1.2
                            @Override // kotlin.jvm.functions.Function1
                            public /* bridge */ /* synthetic */ Unit invoke(BindingAdapter.BindingViewHolder bindingViewHolder) {
                                invoke2(bindingViewHolder);
                                return Unit.INSTANCE;
                            }

                            /* renamed from: invoke, reason: avoid collision after fix types in other method */
                            public final void invoke2(@NotNull BindingAdapter.BindingViewHolder onBind) {
                                Intrinsics.checkNotNullParameter(onBind, "$this$onBind");
                                TextView textView = (TextView) onBind.m3941a(R.id.promotion_tips);
                                StringBuilder m586H = C1499a.m586H("赠送");
                                m586H.append((Object) ((RechargeBean.ProductsBean) onBind.m3942b()).gift_num);
                                m586H.append("金币");
                                textView.setText(m586H.toString());
                            }
                        });
                    }
                });
                TextView tvService = bodyBinding.tvService;
                Intrinsics.checkNotNullExpressionValue(tvService, "tvService");
                final RechargeActivity rechargeActivity2 = RechargeActivity.this;
                C2354n.m2376A1(tvService, "如有疑问，请咨询", "在线客服", new Function1<String, Unit>() { // from class: com.jbzd.media.movecartoons.ui.wallet.RechargeActivity$initView$1.2
                    {
                        super(1);
                    }

                    @Override // kotlin.jvm.functions.Function1
                    public /* bridge */ /* synthetic */ Unit invoke(String str) {
                        invoke2(str);
                        return Unit.INSTANCE;
                    }

                    /* renamed from: invoke, reason: avoid collision after fix types in other method */
                    public final void invoke2(@NotNull String it) {
                        Boolean valueOf;
                        Intrinsics.checkNotNullParameter(it, "it");
                        RechargeActivity context = RechargeActivity.this;
                        Intrinsics.checkNotNullParameter(context, "context");
                        MyApp myApp = MyApp.f9891f;
                        String str = MyApp.f9897l;
                        if (str == null) {
                            valueOf = null;
                        } else {
                            valueOf = Boolean.valueOf(str.length() > 0);
                        }
                        if (!Intrinsics.areEqual(valueOf, Boolean.TRUE)) {
                            ChatDetailActivity.Companion.start$default(ChatDetailActivity.INSTANCE, context, null, null, null, null, 30, null);
                            return;
                        }
                        String str2 = MyApp.f9897l;
                        if (str2 == null) {
                            return;
                        }
                        WebActivity.INSTANCE.start(context, str2);
                    }
                });
                TextView textView = bodyBinding.txtConsumerDetails;
                final RechargeActivity rechargeActivity3 = RechargeActivity.this;
                C2354n.m2374A(textView, 0L, new Function1<TextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.wallet.RechargeActivity$initView$1.3
                    {
                        super(1);
                    }

                    @Override // kotlin.jvm.functions.Function1
                    public /* bridge */ /* synthetic */ Unit invoke(TextView textView2) {
                        invoke2(textView2);
                        return Unit.INSTANCE;
                    }

                    /* renamed from: invoke, reason: avoid collision after fix types in other method */
                    public final void invoke2(@NotNull TextView it) {
                        Intrinsics.checkNotNullParameter(it, "it");
                        BillActivity.INSTANCE.start(RechargeActivity.this);
                    }
                }, 1);
            }
        });
    }
}
