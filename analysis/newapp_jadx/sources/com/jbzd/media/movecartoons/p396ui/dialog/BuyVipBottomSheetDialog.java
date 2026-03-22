package com.jbzd.media.movecartoons.p396ui.dialog;

import android.app.Activity;
import android.content.DialogInterface;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.appcompat.widget.ActivityChooserModel;
import androidx.recyclerview.widget.RecyclerView;
import com.drake.brv.BindingAdapter;
import com.jbzd.media.movecartoons.MyApp;
import com.jbzd.media.movecartoons.bean.response.GroupBean;
import com.jbzd.media.movecartoons.bean.response.PayBean;
import com.jbzd.media.movecartoons.p396ui.chat.ChatDetailActivity;
import com.jbzd.media.movecartoons.p396ui.dialog.BuyVipBottomSheetDialog;
import com.jbzd.media.movecartoons.p396ui.vip.IdoVipPay;
import com.jbzd.media.movecartoons.p396ui.web.WebActivity;
import com.qnmd.adnnm.da0yzo.R;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.collections.CollectionsKt___CollectionsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.functions.Function3;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Reflection;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p327w.p330b.p337d.C2861e;
import p403d.p404a.p405a.p407b.p408a.C4195m;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000h\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010 \n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\r\n\u0002\u0010\b\n\u0002\b\u0006\u0018\u0000 A2\u00020\u0001:\u0001AB'\u0012\u0006\u0010\u001d\u001a\u00020\u001c\u0012\u0006\u0010&\u001a\u00020%\u0012\u0006\u0010=\u001a\u00020<\u0012\u0006\u0010>\u001a\u00020<¢\u0006\u0004\b?\u0010@J\u000f\u0010\u0003\u001a\u00020\u0002H\u0002¢\u0006\u0004\b\u0003\u0010\u0004J1\u0010\f\u001a\u00020\u00022\u000e\u0010\u0007\u001a\n\u0012\u0004\u0012\u00020\u0006\u0018\u00010\u00052\b\u0010\t\u001a\u0004\u0018\u00010\b2\b\u0010\u000b\u001a\u0004\u0018\u00010\n¢\u0006\u0004\b\f\u0010\rJ\r\u0010\u000e\u001a\u00020\u0002¢\u0006\u0004\b\u000e\u0010\u0004J\u000f\u0010\u000f\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\u000f\u0010\u0004R\u001d\u0010\u0015\u001a\u00020\u00108B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u0011\u0010\u0012\u001a\u0004\b\u0013\u0010\u0014R%\u0010\u001b\u001a\n \u0017*\u0004\u0018\u00010\u00160\u00168B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u0018\u0010\u0012\u001a\u0004\b\u0019\u0010\u001aR\u0016\u0010\u001d\u001a\u00020\u001c8\u0002@\u0002X\u0082\u0004¢\u0006\u0006\n\u0004\b\u001d\u0010\u001eR\u001d\u0010#\u001a\u00020\u001f8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b \u0010\u0012\u001a\u0004\b!\u0010\"R\u0018\u0010\u000b\u001a\u0004\u0018\u00010\n8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\u000b\u0010$R\u0016\u0010&\u001a\u00020%8\u0002@\u0002X\u0082\u0004¢\u0006\u0006\n\u0004\b&\u0010'R\u001d\u0010,\u001a\u00020(8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b)\u0010\u0012\u001a\u0004\b*\u0010+R\u0018\u0010\t\u001a\u0004\u0018\u00010\b8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\t\u0010-R\u001d\u00102\u001a\u00020.8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b/\u0010\u0012\u001a\u0004\b0\u00101R\u001d\u00105\u001a\u00020\u001f8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b3\u0010\u0012\u001a\u0004\b4\u0010\"R\u001d\u00108\u001a\u00020\u001f8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b6\u0010\u0012\u001a\u0004\b7\u0010\"R%\u0010;\u001a\n \u0017*\u0004\u0018\u00010(0(8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b9\u0010\u0012\u001a\u0004\b:\u0010+¨\u0006B"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/dialog/BuyVipBottomSheetDialog;", "Lcom/jbzd/media/movecartoons/ui/dialog/StrongBottomSheetDialog;", "", "initDefaultShow", "()V", "", "Lcom/jbzd/media/movecartoons/bean/response/GroupBean$PaymentsBean;", "payments", "Lcom/jbzd/media/movecartoons/bean/response/GroupBean;", "vipGroup", "", "tips", "setVipShowData", "(Ljava/util/List;Lcom/jbzd/media/movecartoons/bean/response/GroupBean;Ljava/lang/String;)V", "init", "dismiss", "Landroid/widget/ImageView;", "ivDismiss$delegate", "Lkotlin/Lazy;", "getIvDismiss", "()Landroid/widget/ImageView;", "ivDismiss", "Lcom/jbzd/media/movecartoons/ui/dialog/XAlertDialog;", "kotlin.jvm.PlatformType", "dialog$delegate", "getDialog", "()Lcom/jbzd/media/movecartoons/ui/dialog/XAlertDialog;", "dialog", "Landroid/app/Activity;", "context", "Landroid/app/Activity;", "Landroid/widget/TextView;", "tv_pay$delegate", "getTv_pay", "()Landroid/widget/TextView;", "tv_pay", "Ljava/lang/String;", "Lcom/jbzd/media/movecartoons/ui/vip/IdoVipPay;", "viewModel", "Lcom/jbzd/media/movecartoons/ui/vip/IdoVipPay;", "Landroid/view/View;", "outsideView$delegate", "getOutsideView", "()Landroid/view/View;", "outsideView", "Lcom/jbzd/media/movecartoons/bean/response/GroupBean;", "Landroidx/recyclerview/widget/RecyclerView;", "rv_payments$delegate", "getRv_payments", "()Landroidx/recyclerview/widget/RecyclerView;", "rv_payments", "tvService$delegate", "getTvService", "tvService", "tvNamePrice$delegate", "getTvNamePrice", "tvNamePrice", "contentView$delegate", "getContentView", "contentView", "", "peekHeight", "maxHeight", "<init>", "(Landroid/app/Activity;Lcom/jbzd/media/movecartoons/ui/vip/IdoVipPay;II)V", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class BuyVipBottomSheetDialog extends StrongBottomSheetDialog {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    /* renamed from: contentView$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy contentView;

    @NotNull
    private final Activity context;

    /* renamed from: dialog$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy dialog;

    /* renamed from: ivDismiss$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy ivDismiss;

    /* renamed from: outsideView$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy outsideView;

    /* renamed from: rv_payments$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy rv_payments;

    @Nullable
    private String tips;

    /* renamed from: tvNamePrice$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tvNamePrice;

    /* renamed from: tvService$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tvService;

    /* renamed from: tv_pay$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_pay;

    @NotNull
    private final IdoVipPay viewModel;

    @Nullable
    private GroupBean vipGroup;

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u001c\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0005\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\t\u0010\nJ\u001d\u0010\u0007\u001a\u00020\u00062\u0006\u0010\u0003\u001a\u00020\u00022\u0006\u0010\u0005\u001a\u00020\u0004¢\u0006\u0004\b\u0007\u0010\b¨\u0006\u000b"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/dialog/BuyVipBottomSheetDialog$Companion;", "", "Landroid/app/Activity;", ActivityChooserModel.ATTRIBUTE_ACTIVITY, "Lcom/jbzd/media/movecartoons/ui/vip/IdoVipPay;", "viewModel", "Lcom/jbzd/media/movecartoons/ui/dialog/BuyVipBottomSheetDialog;", "getShareBottomSheetDialog", "(Landroid/app/Activity;Lcom/jbzd/media/movecartoons/ui/vip/IdoVipPay;)Lcom/jbzd/media/movecartoons/ui/dialog/BuyVipBottomSheetDialog;", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        @NotNull
        public final BuyVipBottomSheetDialog getShareBottomSheetDialog(@NotNull Activity activity, @NotNull IdoVipPay viewModel) {
            View findViewById;
            Intrinsics.checkNotNullParameter(activity, "activity");
            Intrinsics.checkNotNullParameter(viewModel, "viewModel");
            int m2513s0 = (C2354n.m2513s0(activity) * 3) / 5;
            BuyVipBottomSheetDialog buyVipBottomSheetDialog = new BuyVipBottomSheetDialog(activity, viewModel, m2513s0, m2513s0);
            buyVipBottomSheetDialog.init();
            Window window = buyVipBottomSheetDialog.getWindow();
            if (window != null && (findViewById = window.findViewById(R.id.design_bottom_sheet)) != null) {
                findViewById.setBackgroundResource(android.R.color.transparent);
            }
            return buyVipBottomSheetDialog;
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public BuyVipBottomSheetDialog(@NotNull Activity context, @NotNull IdoVipPay viewModel, int i2, int i3) {
        super(context, i2, i3, R.style.TransBottomSheetDialogStyle);
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(viewModel, "viewModel");
        this.context = context;
        this.viewModel = viewModel;
        this.contentView = LazyKt__LazyJVMKt.lazy(new Function0<View>() { // from class: com.jbzd.media.movecartoons.ui.dialog.BuyVipBottomSheetDialog$contentView$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            public final View invoke() {
                Activity activity;
                activity = BuyVipBottomSheetDialog.this.context;
                return LayoutInflater.from(activity).inflate(R.layout.dialog_pay_bottom, (ViewGroup) null);
            }
        });
        this.outsideView = LazyKt__LazyJVMKt.lazy(new Function0<View>() { // from class: com.jbzd.media.movecartoons.ui.dialog.BuyVipBottomSheetDialog$outsideView$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final View invoke() {
                View contentView;
                contentView = BuyVipBottomSheetDialog.this.getContentView();
                View findViewById = contentView.findViewById(R.id.outside_view);
                Objects.requireNonNull(findViewById, "null cannot be cast to non-null type android.view.View");
                return findViewById;
            }
        });
        this.ivDismiss = LazyKt__LazyJVMKt.lazy(new Function0<ImageView>() { // from class: com.jbzd.media.movecartoons.ui.dialog.BuyVipBottomSheetDialog$ivDismiss$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final ImageView invoke() {
                View contentView;
                contentView = BuyVipBottomSheetDialog.this.getContentView();
                View findViewById = contentView.findViewById(R.id.iv_dismiss);
                Objects.requireNonNull(findViewById, "null cannot be cast to non-null type android.widget.ImageView");
                return (ImageView) findViewById;
            }
        });
        this.tv_pay = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.dialog.BuyVipBottomSheetDialog$tv_pay$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final TextView invoke() {
                View contentView;
                contentView = BuyVipBottomSheetDialog.this.getContentView();
                View findViewById = contentView.findViewById(R.id.tv_pay);
                Objects.requireNonNull(findViewById, "null cannot be cast to non-null type android.widget.TextView");
                return (TextView) findViewById;
            }
        });
        this.tvNamePrice = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.dialog.BuyVipBottomSheetDialog$tvNamePrice$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final TextView invoke() {
                View contentView;
                contentView = BuyVipBottomSheetDialog.this.getContentView();
                View findViewById = contentView.findViewById(R.id.tv_name_price);
                Objects.requireNonNull(findViewById, "null cannot be cast to non-null type android.widget.TextView");
                return (TextView) findViewById;
            }
        });
        this.tvService = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.dialog.BuyVipBottomSheetDialog$tvService$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final TextView invoke() {
                View contentView;
                contentView = BuyVipBottomSheetDialog.this.getContentView();
                View findViewById = contentView.findViewById(R.id.tv_service);
                Objects.requireNonNull(findViewById, "null cannot be cast to non-null type android.widget.TextView");
                return (TextView) findViewById;
            }
        });
        this.rv_payments = LazyKt__LazyJVMKt.lazy(new Function0<RecyclerView>() { // from class: com.jbzd.media.movecartoons.ui.dialog.BuyVipBottomSheetDialog$rv_payments$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final RecyclerView invoke() {
                View contentView;
                contentView = BuyVipBottomSheetDialog.this.getContentView();
                View findViewById = contentView.findViewById(R.id.rv_payments);
                Objects.requireNonNull(findViewById, "null cannot be cast to non-null type androidx.recyclerview.widget.RecyclerView");
                return (RecyclerView) findViewById;
            }
        });
        this.dialog = LazyKt__LazyJVMKt.lazy(new Function0<XAlertDialog>() { // from class: com.jbzd.media.movecartoons.ui.dialog.BuyVipBottomSheetDialog$dialog$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            public final XAlertDialog invoke() {
                Activity activity;
                activity = BuyVipBottomSheetDialog.this.context;
                return new XAlertDialog(activity).builder();
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final View getContentView() {
        return (View) this.contentView.getValue();
    }

    private final XAlertDialog getDialog() {
        return (XAlertDialog) this.dialog.getValue();
    }

    private final ImageView getIvDismiss() {
        return (ImageView) this.ivDismiss.getValue();
    }

    private final View getOutsideView() {
        return (View) this.outsideView.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final RecyclerView getRv_payments() {
        return (RecyclerView) this.rv_payments.getValue();
    }

    private final TextView getTvNamePrice() {
        return (TextView) this.tvNamePrice.getValue();
    }

    private final TextView getTvService() {
        return (TextView) this.tvService.getValue();
    }

    private final TextView getTv_pay() {
        return (TextView) this.tv_pay.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: init$lambda-2, reason: not valid java name */
    public static final void m5770init$lambda2(BuyVipBottomSheetDialog this$0, DialogInterface dialogInterface) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        C4195m.m4793Z(this$0.getRv_payments()).m3926b(false);
    }

    private final void initDefaultShow() {
        C2354n.m2374A(getIvDismiss(), 0L, new Function1<ImageView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.BuyVipBottomSheetDialog$initDefaultShow$1
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(ImageView imageView) {
                invoke2(imageView);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull ImageView it) {
                Intrinsics.checkNotNullParameter(it, "it");
                BuyVipBottomSheetDialog.this.dismiss();
            }
        }, 1);
        C2354n.m2374A(getOutsideView(), 0L, new Function1<View, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.BuyVipBottomSheetDialog$initDefaultShow$2
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(View view) {
                invoke2(view);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull View it) {
                Intrinsics.checkNotNullParameter(it, "it");
                BuyVipBottomSheetDialog.this.dismiss();
            }
        }, 1);
        getRv_payments().setNestedScrollingEnabled(false);
        RecyclerView rv_payments = getRv_payments();
        C4195m.m4835u0(rv_payments, 0, false, false, false, 15);
        C4195m.m4774J0(rv_payments, new Function2<BindingAdapter, RecyclerView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.BuyVipBottomSheetDialog$initDefaultShow$3
            @Override // kotlin.jvm.functions.Function2
            public /* bridge */ /* synthetic */ Unit invoke(BindingAdapter bindingAdapter, RecyclerView recyclerView) {
                invoke2(bindingAdapter, recyclerView);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull final BindingAdapter bindingAdapter, @NotNull RecyclerView recyclerView) {
                boolean m616f0 = C1499a.m616f0(bindingAdapter, "$this$setup", recyclerView, "it", GroupBean.PaymentsBean.class);
                final int i2 = R.layout.item_vip_payment;
                if (m616f0) {
                    bindingAdapter.f8910l.put(Reflection.typeOf(GroupBean.PaymentsBean.class), new Function2<Object, Integer, Integer>() { // from class: com.jbzd.media.movecartoons.ui.dialog.BuyVipBottomSheetDialog$initDefaultShow$3$invoke$$inlined$addType$1
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
                    bindingAdapter.f8909k.put(Reflection.typeOf(GroupBean.PaymentsBean.class), new Function2<Object, Integer, Integer>() { // from class: com.jbzd.media.movecartoons.ui.dialog.BuyVipBottomSheetDialog$initDefaultShow$3$invoke$$inlined$addType$2
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
                bindingAdapter.m3940r(true);
                bindingAdapter.m3935l(new Function1<BindingAdapter.BindingViewHolder, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.BuyVipBottomSheetDialog$initDefaultShow$3.1
                    @Override // kotlin.jvm.functions.Function1
                    public /* bridge */ /* synthetic */ Unit invoke(BindingAdapter.BindingViewHolder bindingViewHolder) {
                        invoke2(bindingViewHolder);
                        return Unit.INSTANCE;
                    }

                    /* renamed from: invoke, reason: avoid collision after fix types in other method */
                    public final void invoke2(@NotNull BindingAdapter.BindingViewHolder onBind) {
                        Intrinsics.checkNotNullParameter(onBind, "$this$onBind");
                        GroupBean.PaymentsBean paymentsBean = (GroupBean.PaymentsBean) onBind.m3942b();
                        C2354n.m2455a2(onBind.f8926b).m3298p(paymentsBean.getPayment_ico()).m3292f0().m757R((ImageView) onBind.m3941a(R.id.iv_icon));
                        ((TextView) onBind.m3941a(R.id.tv_name)).setText(paymentsBean.getPayment_name());
                        ((CheckBox) onBind.m3941a(R.id.iv_select)).setChecked(paymentsBean.getIsChecked());
                    }
                });
                bindingAdapter.m3937n(new int[]{R.id.ll_group}, new Function2<BindingAdapter.BindingViewHolder, Integer, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.BuyVipBottomSheetDialog$initDefaultShow$3.2
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
                        if (((GroupBean.PaymentsBean) onClick.m3942b()).getIsChecked()) {
                            return;
                        }
                        BindingAdapter.this.m3938o(onClick.getLayoutPosition(), true);
                    }
                });
                bindingAdapter.m3936m(new Function3<Integer, Boolean, Boolean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.BuyVipBottomSheetDialog$initDefaultShow$3.3
                    {
                        super(3);
                    }

                    @Override // kotlin.jvm.functions.Function3
                    public /* bridge */ /* synthetic */ Unit invoke(Integer num, Boolean bool, Boolean bool2) {
                        invoke(num.intValue(), bool.booleanValue(), bool2.booleanValue());
                        return Unit.INSTANCE;
                    }

                    public final void invoke(int i3, boolean z, boolean z2) {
                        ((GroupBean.PaymentsBean) BindingAdapter.this.m3930g(i3)).setChecked(z);
                        BindingAdapter.this.notifyItemChanged(i3);
                    }
                });
            }
        });
        C2354n.m2374A(getTv_pay(), 0L, new Function1<TextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.BuyVipBottomSheetDialog$initDefaultShow$4
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(TextView textView) {
                invoke2(textView);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull TextView it) {
                GroupBean groupBean;
                RecyclerView rv_payments2;
                IdoVipPay idoVipPay;
                Intrinsics.checkNotNullParameter(it, "it");
                BuyVipBottomSheetDialog.this.dismiss();
                groupBean = BuyVipBottomSheetDialog.this.vipGroup;
                rv_payments2 = BuyVipBottomSheetDialog.this.getRv_payments();
                List m3928e = C4195m.m4793Z(rv_payments2).m3928e();
                if (!(!m3928e.isEmpty())) {
                    C2354n.m2451Z1("选择支付方式");
                } else {
                    if (groupBean == null) {
                        return;
                    }
                    idoVipPay = BuyVipBottomSheetDialog.this.viewModel;
                    idoVipPay.buyVip((GroupBean.PaymentsBean) ((ArrayList) m3928e).get(0), groupBean, new Function1<PayBean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.BuyVipBottomSheetDialog$initDefaultShow$4$1$1
                        @Override // kotlin.jvm.functions.Function1
                        public /* bridge */ /* synthetic */ Unit invoke(PayBean payBean) {
                            invoke2(payBean);
                            return Unit.INSTANCE;
                        }

                        /* renamed from: invoke, reason: avoid collision after fix types in other method */
                        public final void invoke2(@NotNull PayBean it2) {
                            Intrinsics.checkNotNullParameter(it2, "it");
                        }
                    });
                }
            }
        }, 1);
        C2354n.m2376A1(getTvService(), "如有疑问，请咨询", " 在线客服", new Function1<String, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.BuyVipBottomSheetDialog$initDefaultShow$5
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
                Activity context;
                Boolean valueOf;
                Intrinsics.checkNotNullParameter(it, "it");
                context = BuyVipBottomSheetDialog.this.context;
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
    }

    @Override // androidx.appcompat.app.AppCompatDialog, android.app.Dialog, android.content.DialogInterface
    public void dismiss() {
        View currentFocus = getCurrentFocus();
        if (currentFocus instanceof EditText) {
            C2861e.m3306d(currentFocus);
        }
        super.dismiss();
    }

    public final void init() {
        setContentView(getContentView());
        initDefaultShow();
        setOnDismissListener(new DialogInterface.OnDismissListener() { // from class: b.a.a.a.t.e.f
            @Override // android.content.DialogInterface.OnDismissListener
            public final void onDismiss(DialogInterface dialogInterface) {
                BuyVipBottomSheetDialog.m5770init$lambda2(BuyVipBottomSheetDialog.this, dialogInterface);
            }
        });
    }

    public final void setVipShowData(@Nullable List<GroupBean.PaymentsBean> payments, @Nullable GroupBean vipGroup, @Nullable String tips) {
        C4195m.m4793Z(getRv_payments()).m3939q(payments == null ? null : CollectionsKt___CollectionsKt.toMutableList((Collection) payments));
        if (vipGroup != null) {
            getTvNamePrice().setText(this.context.getString(R.string.payment_price, new Object[]{Intrinsics.stringPlus(vipGroup.getPrice(), ".00")}));
        }
        this.vipGroup = vipGroup;
        this.tips = tips;
    }
}
