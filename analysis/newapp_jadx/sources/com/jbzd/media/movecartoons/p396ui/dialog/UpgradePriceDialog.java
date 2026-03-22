package com.jbzd.media.movecartoons.p396ui.dialog;

import android.app.Dialog;
import android.content.Context;
import android.graphics.Color;
import android.os.Bundle;
import android.text.style.AbsoluteSizeSpan;
import android.text.style.ForegroundColorSpan;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.view.WindowManager;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.appcompat.app.AlertDialog;
import androidx.fragment.app.DialogFragment;
import com.jbzd.media.movecartoons.p396ui.index.home.child.VideoListActivity;
import com.jbzd.media.movecartoons.p396ui.vip.BuyActivity;
import com.qnmd.adnnm.da0yzo.R;
import io.github.armcha.autolink.AutoLinkTextView;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p006a.p007a.p008a.p009a.C0840d;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p429g.p430a.p431a.p432a.C4326a;
import p429g.p430a.p431a.p432a.C4330e;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000D\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0002\b\b\n\u0002\u0010\u000b\n\u0002\b\u0007\n\u0002\u0018\u0002\n\u0002\b\r\u0018\u00002\u00020\u0001BE\u0012\u0006\u0010\u0019\u001a\u00020\u0018\u0012\u0006\u0010%\u001a\u00020\u000f\u0012\u0006\u0010\u001c\u001a\u00020\u000f\u0012\u0006\u0010\u001f\u001a\u00020\u000f\u0012\u0006\u0010\u0010\u001a\u00020\u000f\u0012\u0006\u0010'\u001a\u00020\u000f\u0012\f\u0010!\u001a\b\u0012\u0004\u0012\u00020\f0 ¢\u0006\u0004\b+\u0010,J\u000f\u0010\u0003\u001a\u00020\u0002H\u0002¢\u0006\u0004\b\u0003\u0010\u0004J\u0019\u0010\b\u001a\u00020\u00072\b\u0010\u0006\u001a\u0004\u0018\u00010\u0005H\u0016¢\u0006\u0004\b\b\u0010\tJ!\u0010\r\u001a\u00020\f2\u0006\u0010\u000b\u001a\u00020\n2\b\u0010\u0006\u001a\u0004\u0018\u00010\u0005H\u0016¢\u0006\u0004\b\r\u0010\u000eR\u0016\u0010\u0010\u001a\u00020\u000f8\u0002@\u0002X\u0082\u0004¢\u0006\u0006\n\u0004\b\u0010\u0010\u0011R%\u0010\u0017\u001a\n \u0012*\u0004\u0018\u00010\n0\n8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u0013\u0010\u0014\u001a\u0004\b\u0015\u0010\u0016R\u0019\u0010\u0019\u001a\u00020\u00188\u0006@\u0006¢\u0006\f\n\u0004\b\u0019\u0010\u001a\u001a\u0004\b\u0019\u0010\u001bR\u0019\u0010\u001c\u001a\u00020\u000f8\u0006@\u0006¢\u0006\f\n\u0004\b\u001c\u0010\u0011\u001a\u0004\b\u001d\u0010\u001eR\u0016\u0010\u001f\u001a\u00020\u000f8\u0002@\u0002X\u0082\u0004¢\u0006\u0006\n\u0004\b\u001f\u0010\u0011R\u001f\u0010!\u001a\b\u0012\u0004\u0012\u00020\f0 8\u0006@\u0006¢\u0006\f\n\u0004\b!\u0010\"\u001a\u0004\b#\u0010$R\u0019\u0010%\u001a\u00020\u000f8\u0006@\u0006¢\u0006\f\n\u0004\b%\u0010\u0011\u001a\u0004\b&\u0010\u001eR\u0016\u0010'\u001a\u00020\u000f8\u0002@\u0002X\u0082\u0004¢\u0006\u0006\n\u0004\b'\u0010\u0011R\u001d\u0010*\u001a\u00020\u00028B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b(\u0010\u0014\u001a\u0004\b)\u0010\u0004¨\u0006-"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/dialog/UpgradePriceDialog;", "Landroidx/fragment/app/DialogFragment;", "Landroidx/appcompat/app/AlertDialog;", "createDialog", "()Landroidx/appcompat/app/AlertDialog;", "Landroid/os/Bundle;", "savedInstanceState", "Landroid/app/Dialog;", "onCreateDialog", "(Landroid/os/Bundle;)Landroid/app/Dialog;", "Landroid/view/View;", "view", "", "onViewCreated", "(Landroid/view/View;Landroid/os/Bundle;)V", "", "price", "Ljava/lang/String;", "kotlin.jvm.PlatformType", "contentView$delegate", "Lkotlin/Lazy;", "getContentView", "()Landroid/view/View;", "contentView", "", "isPreviewEnd", "Z", "()Z", "content", "getContent", "()Ljava/lang/String;", "btnText", "Lkotlin/Function0;", "upgrade", "Lkotlin/jvm/functions/Function0;", "getUpgrade", "()Lkotlin/jvm/functions/Function0;", VideoListActivity.KEY_TITLE, "getTitle", "buyPrice", "alertDialog$delegate", "getAlertDialog", "alertDialog", "<init>", "(ZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lkotlin/jvm/functions/Function0;)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class UpgradePriceDialog extends DialogFragment {

    /* renamed from: alertDialog$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy alertDialog;

    @NotNull
    private final String btnText;

    @NotNull
    private final String buyPrice;

    @NotNull
    private final String content;

    /* renamed from: contentView$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy contentView;
    private final boolean isPreviewEnd;

    @NotNull
    private final String price;

    @NotNull
    private final String title;

    @NotNull
    private final Function0<Unit> upgrade;

    public UpgradePriceDialog(boolean z, @NotNull String title, @NotNull String content, @NotNull String btnText, @NotNull String price, @NotNull String buyPrice, @NotNull Function0<Unit> upgrade) {
        Intrinsics.checkNotNullParameter(title, "title");
        Intrinsics.checkNotNullParameter(content, "content");
        Intrinsics.checkNotNullParameter(btnText, "btnText");
        Intrinsics.checkNotNullParameter(price, "price");
        Intrinsics.checkNotNullParameter(buyPrice, "buyPrice");
        Intrinsics.checkNotNullParameter(upgrade, "upgrade");
        this.isPreviewEnd = z;
        this.title = title;
        this.content = content;
        this.btnText = btnText;
        this.price = price;
        this.buyPrice = buyPrice;
        this.upgrade = upgrade;
        this.contentView = LazyKt__LazyJVMKt.lazy(new Function0<View>() { // from class: com.jbzd.media.movecartoons.ui.dialog.UpgradePriceDialog$contentView$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            public final View invoke() {
                return LayoutInflater.from(UpgradePriceDialog.this.getContext()).inflate(R.layout.dialog_upgrade_price, (ViewGroup) null);
            }
        });
        this.alertDialog = LazyKt__LazyJVMKt.lazy(new Function0<AlertDialog>() { // from class: com.jbzd.media.movecartoons.ui.dialog.UpgradePriceDialog$alertDialog$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final AlertDialog invoke() {
                AlertDialog createDialog;
                createDialog = UpgradePriceDialog.this.createDialog();
                return createDialog;
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final AlertDialog createDialog() {
        AlertDialog create = new AlertDialog.Builder(requireContext(), R.style.dialog_center).setView(getContentView()).setCancelable(false).create();
        Intrinsics.checkNotNullExpressionValue(create, "Builder(requireContext(), R.style.dialog_center)\n            .setView(contentView)\n            .setCancelable(false)\n            .create()");
        TextView textView = (TextView) getContentView().findViewById(R.id.btn_left);
        TextView textView2 = (TextView) getContentView().findViewById(R.id.btn_right);
        C2354n.m2374A(textView, 0L, new Function1<TextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.UpgradePriceDialog$createDialog$1
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(TextView textView3) {
                invoke2(textView3);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(TextView textView3) {
                UpgradePriceDialog.this.getUpgrade().invoke();
                UpgradePriceDialog.this.dismissAllowingStateLoss();
            }
        }, 1);
        C2354n.m2374A(textView2, 0L, new Function1<TextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.UpgradePriceDialog$createDialog$2
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(TextView textView3) {
                invoke2(textView3);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(TextView textView3) {
                BuyActivity.Companion companion = BuyActivity.INSTANCE;
                Context requireContext = UpgradePriceDialog.this.requireContext();
                Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
                companion.start(requireContext);
                UpgradePriceDialog.this.dismissAllowingStateLoss();
            }
        }, 1);
        AutoLinkTextView autoLinkTextView = (AutoLinkTextView) getContentView().findViewById(R.id.tv_tips);
        TextView textView3 = (TextView) getContentView().findViewById(R.id.tv_title);
        TextView textView4 = (TextView) getContentView().findViewById(R.id.tv_price);
        TextView textView5 = (TextView) getContentView().findViewById(R.id.tv_buy_price);
        TextView textView6 = (TextView) getContentView().findViewById(R.id.tv_vip_buy_cancel);
        TextView textView7 = (TextView) getContentView().findViewById(R.id.tv_buy_tips);
        TextView textView8 = (TextView) getContentView().findViewById(R.id.tv_vip_buy);
        textView3.setText(this.title);
        textView7.setText(this.content);
        textView4.setText(this.content);
        textView5.setText(this.buyPrice);
        C2354n.m2374A(textView6, 0L, new Function1<TextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.UpgradePriceDialog$createDialog$3
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(TextView textView9) {
                invoke2(textView9);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(TextView textView9) {
                UpgradePriceDialog.this.dismissAllowingStateLoss();
            }
        }, 1);
        C2354n.m2374A(textView8, 0L, new Function1<TextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.UpgradePriceDialog$createDialog$4
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(TextView textView9) {
                invoke2(textView9);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(TextView textView9) {
                String str;
                str = UpgradePriceDialog.this.btnText;
                if (Intrinsics.areEqual(str, "need_vip")) {
                    BuyActivity.Companion companion = BuyActivity.INSTANCE;
                    Context requireContext = UpgradePriceDialog.this.requireContext();
                    Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
                    companion.start(requireContext);
                } else {
                    UpgradePriceDialog.this.getUpgrade().invoke();
                }
                UpgradePriceDialog.this.dismissAllowingStateLoss();
            }
        }, 1);
        textView.setText("金币购买");
        textView2.setText("开通会员");
        if (this.isPreviewEnd) {
            textView4.setTextColor(-1);
            textView5.setVisibility(8);
            ((ImageView) getContentView().findViewById(R.id.iv_close)).setVisibility(8);
            C2354n.m2374A(textView2, 0L, new Function1<TextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.UpgradePriceDialog$createDialog$5
                {
                    super(1);
                }

                @Override // kotlin.jvm.functions.Function1
                public /* bridge */ /* synthetic */ Unit invoke(TextView textView9) {
                    invoke2(textView9);
                    return Unit.INSTANCE;
                }

                /* renamed from: invoke, reason: avoid collision after fix types in other method */
                public final void invoke2(TextView textView9) {
                    BuyActivity.Companion companion = BuyActivity.INSTANCE;
                    Context requireContext = UpgradePriceDialog.this.requireContext();
                    Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
                    companion.start(requireContext);
                    UpgradePriceDialog.this.dismissAllowingStateLoss();
                }
            }, 1);
        } else {
            textView5.setVisibility(8);
            textView.setVisibility(0);
            textView2.setVisibility(0);
            ((ImageView) getContentView().findViewById(R.id.iv_close)).setVisibility(0);
            C2354n.m2374A(getContentView().findViewById(R.id.iv_close), 0L, new Function1<ImageView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.UpgradePriceDialog$createDialog$6
                {
                    super(1);
                }

                @Override // kotlin.jvm.functions.Function1
                public /* bridge */ /* synthetic */ Unit invoke(ImageView imageView) {
                    invoke2(imageView);
                    return Unit.INSTANCE;
                }

                /* renamed from: invoke, reason: avoid collision after fix types in other method */
                public final void invoke2(ImageView imageView) {
                    UpgradePriceDialog.this.dismissAllowingStateLoss();
                }
            }, 1);
        }
        if (Intrinsics.areEqual(this.btnText, "need_vip")) {
            textView.setVisibility(8);
            textView8.setText("购买VIP");
        } else {
            textView3.setText("支持原创 支持作者");
            textView.setVisibility(0);
            textView8.setText("立即购买");
        }
        C4330e c4330e = new C4330e("(https?|ftp|file)://[-a-zA-Z0-9+&@#/%?=~_|!:,.;]*[-a-zA-Z0-9+&@#/%=~_|]");
        autoLinkTextView.m4937a(c4330e);
        autoLinkTextView.m4938b(c4330e, new ForegroundColorSpan(Color.argb(255, 230, 2, 23)), new AbsoluteSizeSpan(15, true));
        autoLinkTextView.m4939c(new Function1<C4326a, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.UpgradePriceDialog$createDialog$7
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(C4326a c4326a) {
                invoke2(c4326a);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull C4326a it) {
                Intrinsics.checkNotNullParameter(it, "it");
                C0840d.a aVar = C0840d.f235a;
                Context requireContext = UpgradePriceDialog.this.requireContext();
                Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
                C0840d.a.m174d(aVar, requireContext, it.f11174c, null, null, 12);
            }
        });
        autoLinkTextView.setText(this.content);
        Window window = create.getWindow();
        if (window != null) {
            window.setDimAmount(0.8f);
        }
        WindowManager.LayoutParams attributes = window == null ? null : window.getAttributes();
        if (attributes != null) {
            attributes.windowAnimations = R.style.BottomShowAnimation;
        }
        return create;
    }

    private final AlertDialog getAlertDialog() {
        return (AlertDialog) this.alertDialog.getValue();
    }

    private final View getContentView() {
        return (View) this.contentView.getValue();
    }

    public void _$_clearFindViewByIdCache() {
    }

    @NotNull
    public final String getContent() {
        return this.content;
    }

    @NotNull
    public final String getTitle() {
        return this.title;
    }

    @NotNull
    public final Function0<Unit> getUpgrade() {
        return this.upgrade;
    }

    /* renamed from: isPreviewEnd, reason: from getter */
    public final boolean getIsPreviewEnd() {
        return this.isPreviewEnd;
    }

    @Override // androidx.fragment.app.DialogFragment
    @NotNull
    public Dialog onCreateDialog(@Nullable Bundle savedInstanceState) {
        return getAlertDialog();
    }

    @Override // androidx.fragment.app.Fragment
    public void onViewCreated(@NotNull View view, @Nullable Bundle savedInstanceState) {
        Intrinsics.checkNotNullParameter(view, "view");
        super.onViewCreated(view, savedInstanceState);
    }
}
