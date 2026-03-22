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
import com.jbzd.media.movecartoons.bean.response.PayBean;
import com.jbzd.media.movecartoons.bean.response.RechargeBean;
import com.jbzd.media.movecartoons.p396ui.chat.ChatDetailActivity;
import com.jbzd.media.movecartoons.p396ui.dialog.PayPointBottomSheetDialog;
import com.jbzd.media.movecartoons.p396ui.wallet.IdoPointPay;
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
import kotlin.jvm.internal.Lambda;
import kotlin.jvm.internal.Reflection;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p006a.p007a.p008a.p009a.C0837b0;
import p005b.p006a.p007a.p008a.p009a.C0840d;
import p005b.p006a.p007a.p008a.p024t.p029e.ViewOnClickListenerC1026q;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p327w.p330b.p337d.C2861e;
import p379c.p380a.C3079m0;
import p379c.p380a.C3109w0;
import p403d.p404a.p405a.p407b.p408a.C4195m;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000h\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010 \n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\b\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0007\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0010\b\n\u0002\b\u0006\u0018\u0000 A2\u00020\u0001:\u0001AB'\u0012\u0006\u0010-\u001a\u00020,\u0012\u0006\u0010'\u001a\u00020&\u0012\u0006\u0010=\u001a\u00020<\u0012\u0006\u0010>\u001a\u00020<¢\u0006\u0004\b?\u0010@J\u000f\u0010\u0003\u001a\u00020\u0002H\u0002¢\u0006\u0004\b\u0003\u0010\u0004J1\u0010\f\u001a\u00020\u00022\u000e\u0010\u0007\u001a\n\u0012\u0004\u0012\u00020\u0006\u0018\u00010\u00052\b\u0010\t\u001a\u0004\u0018\u00010\b2\b\u0010\u000b\u001a\u0004\u0018\u00010\n¢\u0006\u0004\b\f\u0010\rJ\r\u0010\u000e\u001a\u00020\u0002¢\u0006\u0004\b\u000e\u0010\u0004J\u000f\u0010\u000f\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\u000f\u0010\u0004R\u001d\u0010\u0015\u001a\u00020\u00108B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u0011\u0010\u0012\u001a\u0004\b\u0013\u0010\u0014R\u001d\u0010\u001a\u001a\u00020\u00168B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u0017\u0010\u0012\u001a\u0004\b\u0018\u0010\u0019R\u001d\u0010\u001d\u001a\u00020\u00168B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u001b\u0010\u0012\u001a\u0004\b\u001c\u0010\u0019R\u0018\u0010\t\u001a\u0004\u0018\u00010\b8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\t\u0010\u001eR%\u0010$\u001a\n  *\u0004\u0018\u00010\u001f0\u001f8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b!\u0010\u0012\u001a\u0004\b\"\u0010#R\u0018\u0010\u000b\u001a\u0004\u0018\u00010\n8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\u000b\u0010%R\u0016\u0010'\u001a\u00020&8\u0002@\u0002X\u0082\u0004¢\u0006\u0006\n\u0004\b'\u0010(R\u001d\u0010+\u001a\u00020\u001f8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b)\u0010\u0012\u001a\u0004\b*\u0010#R\u0016\u0010-\u001a\u00020,8\u0002@\u0002X\u0082\u0004¢\u0006\u0006\n\u0004\b-\u0010.R\u001d\u00103\u001a\u00020/8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b0\u0010\u0012\u001a\u0004\b1\u00102R\u001d\u00106\u001a\u00020\u00168B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b4\u0010\u0012\u001a\u0004\b5\u0010\u0019R%\u0010;\u001a\n  *\u0004\u0018\u000107078B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b8\u0010\u0012\u001a\u0004\b9\u0010:¨\u0006B"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/dialog/PayPointBottomSheetDialog;", "Lcom/jbzd/media/movecartoons/ui/dialog/StrongBottomSheetDialog;", "", "initDefaultShow", "()V", "", "Lcom/jbzd/media/movecartoons/bean/response/RechargeBean$ProductsBean$PaymentsBean;", "payments", "Lcom/jbzd/media/movecartoons/bean/response/RechargeBean$ProductsBean;", "vipGroup", "", "tips", "setRechargeShowData", "(Ljava/util/List;Lcom/jbzd/media/movecartoons/bean/response/RechargeBean$ProductsBean;Ljava/lang/String;)V", "init", "dismiss", "Landroidx/recyclerview/widget/RecyclerView;", "rvPayments$delegate", "Lkotlin/Lazy;", "getRvPayments", "()Landroidx/recyclerview/widget/RecyclerView;", "rvPayments", "Landroid/widget/TextView;", "tv_name_price$delegate", "getTv_name_price", "()Landroid/widget/TextView;", "tv_name_price", "tv_service$delegate", "getTv_service", "tv_service", "Lcom/jbzd/media/movecartoons/bean/response/RechargeBean$ProductsBean;", "Landroid/view/View;", "kotlin.jvm.PlatformType", "contentView$delegate", "getContentView", "()Landroid/view/View;", "contentView", "Ljava/lang/String;", "Lcom/jbzd/media/movecartoons/ui/wallet/IdoPointPay;", "viewModel", "Lcom/jbzd/media/movecartoons/ui/wallet/IdoPointPay;", "outsideView$delegate", "getOutsideView", "outsideView", "Landroid/app/Activity;", "context", "Landroid/app/Activity;", "Landroid/widget/ImageView;", "ivDismiss$delegate", "getIvDismiss", "()Landroid/widget/ImageView;", "ivDismiss", "tvPay$delegate", "getTvPay", "tvPay", "Lcom/jbzd/media/movecartoons/ui/dialog/XAlertDialog;", "dialog$delegate", "getDialog", "()Lcom/jbzd/media/movecartoons/ui/dialog/XAlertDialog;", "dialog", "", "peekHeight", "maxHeight", "<init>", "(Landroid/app/Activity;Lcom/jbzd/media/movecartoons/ui/wallet/IdoPointPay;II)V", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class PayPointBottomSheetDialog extends StrongBottomSheetDialog {

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

    /* renamed from: rvPayments$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy rvPayments;

    @Nullable
    private String tips;

    /* renamed from: tvPay$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tvPay;

    /* renamed from: tv_name_price$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_name_price;

    /* renamed from: tv_service$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_service;

    @NotNull
    private final IdoPointPay viewModel;

    @Nullable
    private RechargeBean.ProductsBean vipGroup;

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u001c\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0005\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\t\u0010\nJ\u001d\u0010\u0007\u001a\u00020\u00062\u0006\u0010\u0003\u001a\u00020\u00022\u0006\u0010\u0005\u001a\u00020\u0004¢\u0006\u0004\b\u0007\u0010\b¨\u0006\u000b"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/dialog/PayPointBottomSheetDialog$Companion;", "", "Landroid/app/Activity;", ActivityChooserModel.ATTRIBUTE_ACTIVITY, "Lcom/jbzd/media/movecartoons/ui/wallet/IdoPointPay;", "viewModel", "Lcom/jbzd/media/movecartoons/ui/dialog/PayPointBottomSheetDialog;", "getShareBottomSheetDialog", "(Landroid/app/Activity;Lcom/jbzd/media/movecartoons/ui/wallet/IdoPointPay;)Lcom/jbzd/media/movecartoons/ui/dialog/PayPointBottomSheetDialog;", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        @NotNull
        public final PayPointBottomSheetDialog getShareBottomSheetDialog(@NotNull Activity activity, @NotNull IdoPointPay viewModel) {
            View findViewById;
            Intrinsics.checkNotNullParameter(activity, "activity");
            Intrinsics.checkNotNullParameter(viewModel, "viewModel");
            int m2513s0 = (C2354n.m2513s0(activity) * 3) / 5;
            PayPointBottomSheetDialog payPointBottomSheetDialog = new PayPointBottomSheetDialog(activity, viewModel, m2513s0, m2513s0);
            payPointBottomSheetDialog.init();
            Window window = payPointBottomSheetDialog.getWindow();
            if (window != null && (findViewById = window.findViewById(R.id.design_bottom_sheet)) != null) {
                findViewById.setBackgroundResource(android.R.color.transparent);
            }
            return payPointBottomSheetDialog;
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public PayPointBottomSheetDialog(@NotNull Activity context, @NotNull IdoPointPay viewModel, int i2, int i3) {
        super(context, i2, i3, R.style.TransBottomSheetDialogStyle);
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(viewModel, "viewModel");
        this.context = context;
        this.viewModel = viewModel;
        this.contentView = LazyKt__LazyJVMKt.lazy(new Function0<View>() { // from class: com.jbzd.media.movecartoons.ui.dialog.PayPointBottomSheetDialog$contentView$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            public final View invoke() {
                Activity activity;
                activity = PayPointBottomSheetDialog.this.context;
                return LayoutInflater.from(activity).inflate(R.layout.dialog_pay_bottom, (ViewGroup) null);
            }
        });
        this.outsideView = LazyKt__LazyJVMKt.lazy(new Function0<View>() { // from class: com.jbzd.media.movecartoons.ui.dialog.PayPointBottomSheetDialog$outsideView$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final View invoke() {
                View contentView;
                contentView = PayPointBottomSheetDialog.this.getContentView();
                View findViewById = contentView.findViewById(R.id.outside_view);
                Objects.requireNonNull(findViewById, "null cannot be cast to non-null type android.view.View");
                return findViewById;
            }
        });
        this.ivDismiss = LazyKt__LazyJVMKt.lazy(new Function0<ImageView>() { // from class: com.jbzd.media.movecartoons.ui.dialog.PayPointBottomSheetDialog$ivDismiss$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final ImageView invoke() {
                View contentView;
                contentView = PayPointBottomSheetDialog.this.getContentView();
                View findViewById = contentView.findViewById(R.id.iv_dismiss);
                Objects.requireNonNull(findViewById, "null cannot be cast to non-null type android.widget.ImageView");
                return (ImageView) findViewById;
            }
        });
        this.tvPay = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.dialog.PayPointBottomSheetDialog$tvPay$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final TextView invoke() {
                View contentView;
                contentView = PayPointBottomSheetDialog.this.getContentView();
                View findViewById = contentView.findViewById(R.id.tv_pay);
                Objects.requireNonNull(findViewById, "null cannot be cast to non-null type android.widget.TextView");
                return (TextView) findViewById;
            }
        });
        this.tv_name_price = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.dialog.PayPointBottomSheetDialog$tv_name_price$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final TextView invoke() {
                View contentView;
                contentView = PayPointBottomSheetDialog.this.getContentView();
                View findViewById = contentView.findViewById(R.id.tv_name_price);
                Objects.requireNonNull(findViewById, "null cannot be cast to non-null type android.widget.TextView");
                return (TextView) findViewById;
            }
        });
        this.tv_service = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.dialog.PayPointBottomSheetDialog$tv_service$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final TextView invoke() {
                View contentView;
                contentView = PayPointBottomSheetDialog.this.getContentView();
                View findViewById = contentView.findViewById(R.id.tv_service);
                Objects.requireNonNull(findViewById, "null cannot be cast to non-null type android.widget.TextView");
                return (TextView) findViewById;
            }
        });
        this.rvPayments = LazyKt__LazyJVMKt.lazy(new Function0<RecyclerView>() { // from class: com.jbzd.media.movecartoons.ui.dialog.PayPointBottomSheetDialog$rvPayments$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final RecyclerView invoke() {
                View contentView;
                contentView = PayPointBottomSheetDialog.this.getContentView();
                View findViewById = contentView.findViewById(R.id.rv_payments);
                Objects.requireNonNull(findViewById, "null cannot be cast to non-null type androidx.recyclerview.widget.RecyclerView");
                return (RecyclerView) findViewById;
            }
        });
        this.dialog = LazyKt__LazyJVMKt.lazy(new Function0<XAlertDialog>() { // from class: com.jbzd.media.movecartoons.ui.dialog.PayPointBottomSheetDialog$dialog$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            public final XAlertDialog invoke() {
                Activity activity;
                activity = PayPointBottomSheetDialog.this.context;
                return new XAlertDialog(activity).builder();
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final View getContentView() {
        return (View) this.contentView.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final XAlertDialog getDialog() {
        return (XAlertDialog) this.dialog.getValue();
    }

    private final ImageView getIvDismiss() {
        return (ImageView) this.ivDismiss.getValue();
    }

    private final View getOutsideView() {
        return (View) this.outsideView.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final RecyclerView getRvPayments() {
        return (RecyclerView) this.rvPayments.getValue();
    }

    private final TextView getTvPay() {
        return (TextView) this.tvPay.getValue();
    }

    private final TextView getTv_name_price() {
        return (TextView) this.tv_name_price.getValue();
    }

    private final TextView getTv_service() {
        return (TextView) this.tv_service.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: init$lambda-2, reason: not valid java name */
    public static final void m5780init$lambda2(PayPointBottomSheetDialog this$0, DialogInterface dialogInterface) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        C4195m.m4793Z(this$0.getRvPayments()).m3926b(false);
    }

    private final void initDefaultShow() {
        C2354n.m2374A(getIvDismiss(), 0L, new Function1<ImageView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.PayPointBottomSheetDialog$initDefaultShow$1
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
                PayPointBottomSheetDialog.this.dismiss();
            }
        }, 1);
        C2354n.m2374A(getOutsideView(), 0L, new Function1<View, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.PayPointBottomSheetDialog$initDefaultShow$2
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
                PayPointBottomSheetDialog.this.dismiss();
            }
        }, 1);
        getRvPayments().setNestedScrollingEnabled(false);
        RecyclerView rvPayments = getRvPayments();
        C4195m.m4835u0(rvPayments, 0, false, false, false, 15);
        C4195m.m4774J0(rvPayments, new Function2<BindingAdapter, RecyclerView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.PayPointBottomSheetDialog$initDefaultShow$3
            @Override // kotlin.jvm.functions.Function2
            public /* bridge */ /* synthetic */ Unit invoke(BindingAdapter bindingAdapter, RecyclerView recyclerView) {
                invoke2(bindingAdapter, recyclerView);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull final BindingAdapter bindingAdapter, @NotNull RecyclerView recyclerView) {
                boolean m616f0 = C1499a.m616f0(bindingAdapter, "$this$setup", recyclerView, "it", RechargeBean.ProductsBean.PaymentsBean.class);
                final int i2 = R.layout.item_vip_payment;
                if (m616f0) {
                    bindingAdapter.f8910l.put(Reflection.typeOf(RechargeBean.ProductsBean.PaymentsBean.class), new Function2<Object, Integer, Integer>() { // from class: com.jbzd.media.movecartoons.ui.dialog.PayPointBottomSheetDialog$initDefaultShow$3$invoke$$inlined$addType$1
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
                    bindingAdapter.f8909k.put(Reflection.typeOf(RechargeBean.ProductsBean.PaymentsBean.class), new Function2<Object, Integer, Integer>() { // from class: com.jbzd.media.movecartoons.ui.dialog.PayPointBottomSheetDialog$initDefaultShow$3$invoke$$inlined$addType$2
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
                bindingAdapter.m3935l(new Function1<BindingAdapter.BindingViewHolder, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.PayPointBottomSheetDialog$initDefaultShow$3.1
                    @Override // kotlin.jvm.functions.Function1
                    public /* bridge */ /* synthetic */ Unit invoke(BindingAdapter.BindingViewHolder bindingViewHolder) {
                        invoke2(bindingViewHolder);
                        return Unit.INSTANCE;
                    }

                    /* renamed from: invoke, reason: avoid collision after fix types in other method */
                    public final void invoke2(@NotNull BindingAdapter.BindingViewHolder onBind) {
                        Intrinsics.checkNotNullParameter(onBind, "$this$onBind");
                        RechargeBean.ProductsBean.PaymentsBean paymentsBean = (RechargeBean.ProductsBean.PaymentsBean) onBind.m3942b();
                        C2354n.m2455a2(onBind.f8926b).m3298p(paymentsBean.getPayment_ico()).m3292f0().m757R((ImageView) onBind.m3941a(R.id.iv_icon));
                        ((TextView) onBind.m3941a(R.id.tv_name)).setText(paymentsBean.getPayment_name());
                        ((CheckBox) onBind.m3941a(R.id.iv_select)).setChecked(paymentsBean.isChecked());
                    }
                });
                bindingAdapter.m3937n(new int[]{R.id.ll_group}, new Function2<BindingAdapter.BindingViewHolder, Integer, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.PayPointBottomSheetDialog$initDefaultShow$3.2
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
                        if (((RechargeBean.ProductsBean.PaymentsBean) onClick.m3942b()).isChecked()) {
                            return;
                        }
                        BindingAdapter.this.m3938o(onClick.getLayoutPosition(), true);
                    }
                });
                bindingAdapter.m3936m(new Function3<Integer, Boolean, Boolean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.PayPointBottomSheetDialog$initDefaultShow$3.3
                    {
                        super(3);
                    }

                    @Override // kotlin.jvm.functions.Function3
                    public /* bridge */ /* synthetic */ Unit invoke(Integer num, Boolean bool, Boolean bool2) {
                        invoke(num.intValue(), bool.booleanValue(), bool2.booleanValue());
                        return Unit.INSTANCE;
                    }

                    public final void invoke(int i3, boolean z, boolean z2) {
                        ((RechargeBean.ProductsBean.PaymentsBean) BindingAdapter.this.m3930g(i3)).setChecked(z);
                        BindingAdapter.this.notifyItemChanged(i3);
                    }
                });
            }
        });
        C2354n.m2374A(getTvPay(), 0L, new Function1<TextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.PayPointBottomSheetDialog$initDefaultShow$4
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
                RechargeBean.ProductsBean productsBean;
                RecyclerView rvPayments2;
                IdoPointPay idoPointPay;
                Intrinsics.checkNotNullParameter(it, "it");
                PayPointBottomSheetDialog.this.dismiss();
                productsBean = PayPointBottomSheetDialog.this.vipGroup;
                rvPayments2 = PayPointBottomSheetDialog.this.getRvPayments();
                List m3928e = C4195m.m4793Z(rvPayments2).m3928e();
                if (!(!m3928e.isEmpty())) {
                    C2354n.m2451Z1("选择支付方式");
                } else {
                    if (productsBean == null) {
                        return;
                    }
                    final PayPointBottomSheetDialog payPointBottomSheetDialog = PayPointBottomSheetDialog.this;
                    idoPointPay = payPointBottomSheetDialog.viewModel;
                    idoPointPay.doPay((RechargeBean.ProductsBean.PaymentsBean) ((ArrayList) m3928e).get(0), productsBean, new Function1<PayBean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.PayPointBottomSheetDialog$initDefaultShow$4$1$1

                        @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\b\n\u0002\u0010\u0002\n\u0002\b\u0002\u0010\u0001\u001a\u00020\u0000H\n¢\u0006\u0004\b\u0001\u0010\u0002"}, m5311d2 = {"", "<anonymous>", "()V"}, m5312k = 3, m5313mv = {1, 5, 1})
                        /* renamed from: com.jbzd.media.movecartoons.ui.dialog.PayPointBottomSheetDialog$initDefaultShow$4$1$1$1 */
                        public static final class C37221 extends Lambda implements Function0<Unit> {
                            public final /* synthetic */ PayPointBottomSheetDialog this$0;

                            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                            public C37221(PayPointBottomSheetDialog payPointBottomSheetDialog) {
                                super(0);
                                this.this$0 = payPointBottomSheetDialog;
                            }

                            /* JADX INFO: Access modifiers changed from: private */
                            /* renamed from: invoke$lambda-0, reason: not valid java name */
                            public static final void m5781invoke$lambda0(View view) {
                            }

                            @Override // kotlin.jvm.functions.Function0
                            public /* bridge */ /* synthetic */ Unit invoke() {
                                invoke2();
                                return Unit.INSTANCE;
                            }

                            /* renamed from: invoke, reason: avoid collision after fix types in other method */
                            public final void invoke2() {
                                XAlertDialog dialog;
                                String str;
                                dialog = this.this$0.getDialog();
                                str = this.this$0.tips;
                                dialog.setMsg(str).setNegativeButton("取消", null).setPositiveButton("已支付", ViewOnClickListenerC1026q.f651c).show();
                            }
                        }

                        {
                            super(1);
                        }

                        @Override // kotlin.jvm.functions.Function1
                        public /* bridge */ /* synthetic */ Unit invoke(PayBean payBean) {
                            invoke2(payBean);
                            return Unit.INSTANCE;
                        }

                        /* renamed from: invoke, reason: avoid collision after fix types in other method */
                        public final void invoke2(@NotNull PayBean buyResponse) {
                            Activity activity;
                            Intrinsics.checkNotNullParameter(buyResponse, "it");
                            activity = PayPointBottomSheetDialog.this.context;
                            C37221 after = new C37221(PayPointBottomSheetDialog.this);
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
                    });
                }
            }
        }, 1);
        C2354n.m2376A1(getTv_service(), "如有疑问，请咨询", "在线客服", new Function1<String, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.PayPointBottomSheetDialog$initDefaultShow$5
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
                context = PayPointBottomSheetDialog.this.context;
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
        setOnDismissListener(new DialogInterface.OnDismissListener() { // from class: b.a.a.a.t.e.p
            @Override // android.content.DialogInterface.OnDismissListener
            public final void onDismiss(DialogInterface dialogInterface) {
                PayPointBottomSheetDialog.m5780init$lambda2(PayPointBottomSheetDialog.this, dialogInterface);
            }
        });
    }

    public final void setRechargeShowData(@Nullable List<? extends RechargeBean.ProductsBean.PaymentsBean> payments, @Nullable RechargeBean.ProductsBean vipGroup, @Nullable String tips) {
        this.vipGroup = vipGroup;
        this.tips = tips;
        C4195m.m4793Z(getRvPayments()).m3939q(payments == null ? null : CollectionsKt___CollectionsKt.toMutableList((Collection) payments));
        if (vipGroup == null) {
            return;
        }
        TextView tv_name_price = getTv_name_price();
        StringBuilder m586H = C1499a.m586H("支付");
        m586H.append(this.context.getString(R.string.payment_price, new Object[]{vipGroup.priceZero}));
        m586H.append("购买");
        m586H.append((Object) vipGroup.num);
        m586H.append("金币");
        tv_name_price.setText(m586H.toString());
        getTvPay().setText(vipGroup.button_text);
    }
}
