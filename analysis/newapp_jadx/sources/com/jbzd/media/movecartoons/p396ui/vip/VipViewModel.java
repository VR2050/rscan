package com.jbzd.media.movecartoons.p396ui.vip;

import androidx.lifecycle.MutableLiveData;
import com.jbzd.media.movecartoons.bean.response.GroupBean;
import com.jbzd.media.movecartoons.bean.response.PayBean;
import com.qunidayede.supportlibrary.core.viewmodel.BaseViewModel;
import java.util.Objects;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p006a.p007a.p008a.p013o.C0909c;
import p005b.p006a.p007a.p008a.p017r.p021n.C0944a;
import p005b.p006a.p007a.p008a.p017r.p021n.C0946c;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p379c.p380a.C3079m0;
import p379c.p380a.C3109w0;
import p379c.p380a.InterfaceC3053d1;
import p379c.p380a.p381a.C2964m;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000^\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\b\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\b\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0005\u0018\u00002\u00020\u00012\u00020\u0002B\u0007¢\u0006\u0004\b3\u0010\tJ\u0017\u0010\u0006\u001a\u00020\u00052\u0006\u0010\u0004\u001a\u00020\u0003H\u0002¢\u0006\u0004\b\u0006\u0010\u0007J\u000f\u0010\b\u001a\u00020\u0005H\u0016¢\u0006\u0004\b\b\u0010\tJ\r\u0010\n\u001a\u00020\u0005¢\u0006\u0004\b\n\u0010\tJB\u0010\u0015\u001a\u00020\u00052\u0006\u0010\f\u001a\u00020\u000b2\u0006\u0010\u000e\u001a\u00020\r2!\u0010\u0014\u001a\u001d\u0012\u0013\u0012\u00110\u0010¢\u0006\f\b\u0011\u0012\b\b\u0012\u0012\u0004\b\b(\u0013\u0012\u0004\u0012\u00020\u00050\u000fH\u0016¢\u0006\u0004\b\u0015\u0010\u0016R#\u0010\u001c\u001a\b\u0012\u0004\u0012\u00020\u00100\u00178F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u0018\u0010\u0019\u001a\u0004\b\u001a\u0010\u001bR#\u0010\u001f\u001a\b\u0012\u0004\u0012\u00020\u00030\u00178F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u001d\u0010\u0019\u001a\u0004\b\u001e\u0010\u001bR\u0018\u0010!\u001a\u0004\u0018\u00010 8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b!\u0010\"R\"\u0010$\u001a\u00020#8\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b$\u0010%\u001a\u0004\b&\u0010'\"\u0004\b(\u0010)R\u001d\u0010.\u001a\u00020*8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b+\u0010\u0019\u001a\u0004\b,\u0010-R#\u00102\u001a\b\u0012\u0004\u0012\u00020/0\u00178F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b0\u0010\u0019\u001a\u0004\b1\u0010\u001b¨\u00064"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/vip/VipViewModel;", "Lcom/qunidayede/supportlibrary/core/viewmodel/BaseViewModel;", "Lcom/jbzd/media/movecartoons/ui/vip/IdoVipPay;", "", "time", "", "countDown", "(I)V", "onCreate", "()V", "loadVipCard", "Lcom/jbzd/media/movecartoons/bean/response/GroupBean$PaymentsBean;", "payment", "Lcom/jbzd/media/movecartoons/bean/response/GroupBean;", "vipGroup", "Lkotlin/Function1;", "Lcom/jbzd/media/movecartoons/bean/response/PayBean;", "Lkotlin/ParameterName;", "name", "paybean", "onSuccess", "buyVip", "(Lcom/jbzd/media/movecartoons/bean/response/GroupBean$PaymentsBean;Lcom/jbzd/media/movecartoons/bean/response/GroupBean;Lkotlin/jvm/functions/Function1;)V", "Landroidx/lifecycle/MutableLiveData;", "payBean$delegate", "Lkotlin/Lazy;", "getPayBean", "()Landroidx/lifecycle/MutableLiveData;", "payBean", "passCount$delegate", "getPassCount", "passCount", "Lc/a/d1;", "jobCountDown", "Lc/a/d1;", "", "category", "Ljava/lang/String;", "getCategory", "()Ljava/lang/String;", "setCategory", "(Ljava/lang/String;)V", "Lb/a/a/a/r/n/a;", "repository$delegate", "getRepository", "()Lb/a/a/a/r/n/a;", "repository", "Lb/a/a/a/o/c;", "infoBean$delegate", "getInfoBean", "infoBean", "<init>", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class VipViewModel extends BaseViewModel implements IdoVipPay {

    @Nullable
    private InterfaceC3053d1 jobCountDown;

    /* renamed from: repository$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy repository = LazyKt__LazyJVMKt.lazy(new Function0<C0944a>() { // from class: com.jbzd.media.movecartoons.ui.vip.VipViewModel$repository$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final C0944a invoke() {
            return new C0944a();
        }
    });

    /* renamed from: infoBean$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy infoBean = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<C0909c>>() { // from class: com.jbzd.media.movecartoons.ui.vip.VipViewModel$infoBean$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<C0909c> invoke() {
            return new MutableLiveData<>();
        }
    });

    /* renamed from: passCount$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy passCount = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<Integer>>() { // from class: com.jbzd.media.movecartoons.ui.vip.VipViewModel$passCount$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<Integer> invoke() {
            return new MutableLiveData<>(0);
        }
    });

    /* renamed from: payBean$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy payBean = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<PayBean>>() { // from class: com.jbzd.media.movecartoons.ui.vip.VipViewModel$payBean$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<PayBean> invoke() {
            return new MutableLiveData<>();
        }
    });

    @NotNull
    private String category = "1";

    /* JADX INFO: Access modifiers changed from: private */
    public final void countDown(int time) {
        cancelJob(this.jobCountDown);
        getPassCount().setValue(0);
        C3109w0 c3109w0 = C3109w0.f8471c;
        C3079m0 c3079m0 = C3079m0.f8432c;
        this.jobCountDown = C2354n.m2435U0(c3109w0, C2964m.f8127b, 0, new VipViewModel$countDown$1(time, this, null), 2, null);
    }

    private final C0944a getRepository() {
        return (C0944a) this.repository.getValue();
    }

    @Override // com.jbzd.media.movecartoons.p396ui.vip.IdoVipPay
    public void buyVip(@NotNull GroupBean.PaymentsBean payment, @NotNull GroupBean vipGroup, @NotNull Function1<? super PayBean, Unit> onSuccess) {
        Intrinsics.checkNotNullParameter(payment, "payment");
        Intrinsics.checkNotNullParameter(vipGroup, "vipGroup");
        Intrinsics.checkNotNullParameter(onSuccess, "onSuccess");
        C0944a repository = getRepository();
        String group = vipGroup.getId();
        String payment2 = payment.getPayment_id();
        Objects.requireNonNull(repository);
        Intrinsics.checkNotNullParameter(group, "group");
        Intrinsics.checkNotNullParameter(payment2, "payment");
        C2354n.m2444X0(repository.m287a().m261t(group, payment2), this, false, null, new Function1<PayBean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.vip.VipViewModel$buyVip$1
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(PayBean payBean) {
                invoke2(payBean);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull PayBean lifecycleLoadingDialog) {
                Intrinsics.checkNotNullParameter(lifecycleLoadingDialog, "$this$lifecycleLoadingDialog");
                VipViewModel.this.getPayBean().setValue(lifecycleLoadingDialog);
            }
        }, 6);
    }

    @NotNull
    public final String getCategory() {
        return this.category;
    }

    @NotNull
    public final MutableLiveData<C0909c> getInfoBean() {
        return (MutableLiveData) this.infoBean.getValue();
    }

    @NotNull
    public final MutableLiveData<Integer> getPassCount() {
        return (MutableLiveData) this.passCount.getValue();
    }

    @NotNull
    public final MutableLiveData<PayBean> getPayBean() {
        return (MutableLiveData) this.payBean.getValue();
    }

    public final void loadVipCard() {
        C2354n.m2444X0(new C0946c(getRepository().m287a().m244c()), this, false, null, new Function1<C0909c, Unit>() { // from class: com.jbzd.media.movecartoons.ui.vip.VipViewModel$loadVipCard$1
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(C0909c c0909c) {
                invoke2(c0909c);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull C0909c lifecycleLoadingDialog) {
                Intrinsics.checkNotNullParameter(lifecycleLoadingDialog, "$this$lifecycleLoadingDialog");
                VipViewModel.this.getInfoBean().setValue(lifecycleLoadingDialog);
                VipViewModel.this.countDown(Integer.MAX_VALUE);
            }
        }, 6);
    }

    @Override // com.qunidayede.supportlibrary.core.viewmodel.BaseViewModel
    public void onCreate() {
    }

    public final void setCategory(@NotNull String str) {
        Intrinsics.checkNotNullParameter(str, "<set-?>");
        this.category = str;
    }
}
