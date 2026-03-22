package com.jbzd.media.movecartoons.p396ui.wallet;

import androidx.lifecycle.MutableLiveData;
import com.jbzd.media.movecartoons.bean.response.PayBean;
import com.jbzd.media.movecartoons.bean.response.RechargeBean;
import com.jbzd.media.movecartoons.bean.response.VideoTypeBean;
import com.qunidayede.supportlibrary.core.viewmodel.BaseViewModel;
import java.util.HashMap;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p006a.p007a.p008a.p017r.C0917a;
import p005b.p006a.p007a.p008a.p017r.p021n.C0944a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p327w.p330b.p331b.p335f.C2848a;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000D\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0006\u0018\u00002\u00020\u00012\u00020\u0002B\u0007¢\u0006\u0004\b\u001f\u0010\u0005J\u000f\u0010\u0004\u001a\u00020\u0003H\u0016¢\u0006\u0004\b\u0004\u0010\u0005J\r\u0010\u0006\u001a\u00020\u0003¢\u0006\u0004\b\u0006\u0010\u0005JB\u0010\u0011\u001a\u00020\u00032\u0006\u0010\b\u001a\u00020\u00072\u0006\u0010\n\u001a\u00020\t2!\u0010\u0010\u001a\u001d\u0012\u0013\u0012\u00110\f¢\u0006\f\b\r\u0012\b\b\u000e\u0012\u0004\b\b(\u000f\u0012\u0004\u0012\u00020\u00030\u000bH\u0016¢\u0006\u0004\b\u0011\u0010\u0012R#\u0010\u0019\u001a\b\u0012\u0004\u0012\u00020\u00140\u00138F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u0015\u0010\u0016\u001a\u0004\b\u0017\u0010\u0018R\u001d\u0010\u001e\u001a\u00020\u001a8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u001b\u0010\u0016\u001a\u0004\b\u001c\u0010\u001d¨\u0006 "}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/wallet/RechargeViewModel;", "Lcom/qunidayede/supportlibrary/core/viewmodel/BaseViewModel;", "Lcom/jbzd/media/movecartoons/ui/wallet/IdoPointPay;", "", "onCreate", "()V", "loadInfo", "Lcom/jbzd/media/movecartoons/bean/response/RechargeBean$ProductsBean$PaymentsBean;", "payment", "Lcom/jbzd/media/movecartoons/bean/response/RechargeBean$ProductsBean;", "mProductsBean", "Lkotlin/Function1;", "Lcom/jbzd/media/movecartoons/bean/response/PayBean;", "Lkotlin/ParameterName;", "name", "paybean", "onSuccess", "doPay", "(Lcom/jbzd/media/movecartoons/bean/response/RechargeBean$ProductsBean$PaymentsBean;Lcom/jbzd/media/movecartoons/bean/response/RechargeBean$ProductsBean;Lkotlin/jvm/functions/Function1;)V", "Landroidx/lifecycle/MutableLiveData;", "Lcom/jbzd/media/movecartoons/bean/response/RechargeBean;", "infoBean$delegate", "Lkotlin/Lazy;", "getInfoBean", "()Landroidx/lifecycle/MutableLiveData;", "infoBean", "Lb/a/a/a/r/n/a;", "repository$delegate", "getRepository", "()Lb/a/a/a/r/n/a;", "repository", "<init>", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class RechargeViewModel extends BaseViewModel implements IdoPointPay {

    /* renamed from: repository$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy repository = LazyKt__LazyJVMKt.lazy(new Function0<C0944a>() { // from class: com.jbzd.media.movecartoons.ui.wallet.RechargeViewModel$repository$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final C0944a invoke() {
            return new C0944a();
        }
    });

    /* renamed from: infoBean$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy infoBean = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<RechargeBean>>() { // from class: com.jbzd.media.movecartoons.ui.wallet.RechargeViewModel$infoBean$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<RechargeBean> invoke() {
            return new MutableLiveData<>();
        }
    });

    private final C0944a getRepository() {
        return (C0944a) this.repository.getValue();
    }

    @Override // com.jbzd.media.movecartoons.p396ui.wallet.IdoPointPay
    public void doPay(@NotNull RechargeBean.ProductsBean.PaymentsBean payment, @NotNull RechargeBean.ProductsBean mProductsBean, @NotNull final Function1<? super PayBean, Unit> onSuccess) {
        Intrinsics.checkNotNullParameter(payment, "payment");
        Intrinsics.checkNotNullParameter(mProductsBean, "mProductsBean");
        Intrinsics.checkNotNullParameter(onSuccess, "onSuccess");
        getLoading().setValue(new C2848a(true, null, false, false, 14));
        HashMap hashMap = new HashMap();
        hashMap.put("product_id", mProductsBean.f9984id);
        hashMap.put("payment_id", payment.getPayment_id());
        hashMap.put("type", VideoTypeBean.video_type_point);
        C0917a.m221e(C0917a.f372a, "user/doRecharge", PayBean.class, hashMap, new Function1<PayBean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.wallet.RechargeViewModel$doPay$2
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            /* JADX WARN: Multi-variable type inference failed */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(PayBean payBean) {
                invoke2(payBean);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable PayBean payBean) {
                RechargeViewModel.this.getLoading().setValue(new C2848a(false, null, false, false, 14));
                if (payBean == null) {
                    return;
                }
                onSuccess.invoke(payBean);
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.wallet.RechargeViewModel$doPay$3
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(Exception exc) {
                invoke2(exc);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull Exception it) {
                Intrinsics.checkNotNullParameter(it, "it");
                RechargeViewModel.this.getLoading().setValue(new C2848a(false, null, false, false, 14));
            }
        }, false, false, null, false, 480);
    }

    @NotNull
    public final MutableLiveData<RechargeBean> getInfoBean() {
        return (MutableLiveData) this.infoBean.getValue();
    }

    public final void loadInfo() {
        C2354n.m2444X0(getRepository().m287a().m258q(VideoTypeBean.video_type_point), this, false, null, new Function1<RechargeBean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.wallet.RechargeViewModel$loadInfo$1
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(RechargeBean rechargeBean) {
                invoke2(rechargeBean);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull RechargeBean lifecycleLoadingDialog) {
                Intrinsics.checkNotNullParameter(lifecycleLoadingDialog, "$this$lifecycleLoadingDialog");
                RechargeViewModel.this.getInfoBean().setValue(lifecycleLoadingDialog);
            }
        }, 6);
    }

    @Override // com.qunidayede.supportlibrary.core.viewmodel.BaseViewModel
    public void onCreate() {
    }
}
