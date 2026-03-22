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

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000<\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0002\b\b\n\u0002\u0018\u0002\n\u0002\b\u000f\u0018\u00002\u00020\u0001B-\u0012\u0006\u0010#\u001a\u00020\u000f\u0012\u0006\u0010\u0010\u001a\u00020\u000f\u0012\u0006\u0010\"\u001a\u00020\u000f\u0012\f\u0010\u0019\u001a\b\u0012\u0004\u0012\u00020\f0\u0018¢\u0006\u0004\b%\u0010&J\u000f\u0010\u0003\u001a\u00020\u0002H\u0002¢\u0006\u0004\b\u0003\u0010\u0004J\u0019\u0010\b\u001a\u00020\u00072\b\u0010\u0006\u001a\u0004\u0018\u00010\u0005H\u0016¢\u0006\u0004\b\b\u0010\tJ!\u0010\r\u001a\u00020\f2\u0006\u0010\u000b\u001a\u00020\n2\b\u0010\u0006\u001a\u0004\u0018\u00010\u0005H\u0016¢\u0006\u0004\b\r\u0010\u000eR\u0019\u0010\u0010\u001a\u00020\u000f8\u0006@\u0006¢\u0006\f\n\u0004\b\u0010\u0010\u0011\u001a\u0004\b\u0012\u0010\u0013R\u001d\u0010\u0017\u001a\u00020\u00028B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u0014\u0010\u0015\u001a\u0004\b\u0016\u0010\u0004R\u001f\u0010\u0019\u001a\b\u0012\u0004\u0012\u00020\f0\u00188\u0006@\u0006¢\u0006\f\n\u0004\b\u0019\u0010\u001a\u001a\u0004\b\u001b\u0010\u001cR%\u0010!\u001a\n \u001d*\u0004\u0018\u00010\n0\n8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u001e\u0010\u0015\u001a\u0004\b\u001f\u0010 R\u0016\u0010\"\u001a\u00020\u000f8\u0002@\u0002X\u0082\u0004¢\u0006\u0006\n\u0004\b\"\u0010\u0011R\u0019\u0010#\u001a\u00020\u000f8\u0006@\u0006¢\u0006\f\n\u0004\b#\u0010\u0011\u001a\u0004\b$\u0010\u0013¨\u0006'"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/dialog/UpgradeVipDialog;", "Landroidx/fragment/app/DialogFragment;", "Landroidx/appcompat/app/AlertDialog;", "createDialog", "()Landroidx/appcompat/app/AlertDialog;", "Landroid/os/Bundle;", "savedInstanceState", "Landroid/app/Dialog;", "onCreateDialog", "(Landroid/os/Bundle;)Landroid/app/Dialog;", "Landroid/view/View;", "view", "", "onViewCreated", "(Landroid/view/View;Landroid/os/Bundle;)V", "", "content", "Ljava/lang/String;", "getContent", "()Ljava/lang/String;", "alertDialog$delegate", "Lkotlin/Lazy;", "getAlertDialog", "alertDialog", "Lkotlin/Function0;", "upgrade", "Lkotlin/jvm/functions/Function0;", "getUpgrade", "()Lkotlin/jvm/functions/Function0;", "kotlin.jvm.PlatformType", "contentView$delegate", "getContentView", "()Landroid/view/View;", "contentView", "btnText", VideoListActivity.KEY_TITLE, "getTitle", "<init>", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lkotlin/jvm/functions/Function0;)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class UpgradeVipDialog extends DialogFragment {

    /* renamed from: alertDialog$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy alertDialog;

    @NotNull
    private final String btnText;

    @NotNull
    private final String content;

    /* renamed from: contentView$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy contentView;

    @NotNull
    private final String title;

    @NotNull
    private final Function0<Unit> upgrade;

    public UpgradeVipDialog(@NotNull String title, @NotNull String content, @NotNull String btnText, @NotNull Function0<Unit> upgrade) {
        Intrinsics.checkNotNullParameter(title, "title");
        Intrinsics.checkNotNullParameter(content, "content");
        Intrinsics.checkNotNullParameter(btnText, "btnText");
        Intrinsics.checkNotNullParameter(upgrade, "upgrade");
        this.title = title;
        this.content = content;
        this.btnText = btnText;
        this.upgrade = upgrade;
        this.contentView = LazyKt__LazyJVMKt.lazy(new Function0<View>() { // from class: com.jbzd.media.movecartoons.ui.dialog.UpgradeVipDialog$contentView$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            public final View invoke() {
                return LayoutInflater.from(UpgradeVipDialog.this.getContext()).inflate(R.layout.dialog_upgrade_vip, (ViewGroup) null);
            }
        });
        this.alertDialog = LazyKt__LazyJVMKt.lazy(new Function0<AlertDialog>() { // from class: com.jbzd.media.movecartoons.ui.dialog.UpgradeVipDialog$alertDialog$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final AlertDialog invoke() {
                AlertDialog createDialog;
                createDialog = UpgradeVipDialog.this.createDialog();
                return createDialog;
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final AlertDialog createDialog() {
        AlertDialog create = new AlertDialog.Builder(requireContext(), R.style.dialog_center).setView(getContentView()).setCancelable(false).create();
        Intrinsics.checkNotNullExpressionValue(create, "Builder(requireContext(), R.style.dialog_center)\n            .setView(contentView).setCancelable(false)\n            .create()");
        TextView textView = (TextView) getContentView().findViewById(R.id.btn);
        C2354n.m2374A(textView, 0L, new Function1<TextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.UpgradeVipDialog$createDialog$1
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(TextView textView2) {
                invoke2(textView2);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(TextView textView2) {
                UpgradeVipDialog.this.getUpgrade().invoke();
            }
        }, 1);
        textView.setText(this.btnText);
        AutoLinkTextView autoLinkTextView = (AutoLinkTextView) getContentView().findViewById(R.id.tv_tips);
        TextView textView2 = (TextView) getContentView().findViewById(R.id.tv_title);
        C2354n.m2374A(getContentView().findViewById(R.id.iv_close), 0L, new Function1<ImageView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.UpgradeVipDialog$createDialog$2
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
                UpgradeVipDialog.this.dismissAllowingStateLoss();
            }
        }, 1);
        ((ImageView) getContentView().findViewById(R.id.iv_close)).setVisibility((Intrinsics.areEqual(this.btnText, "立即开通") || Intrinsics.areEqual(this.btnText, "去升级")) ? 0 : 8);
        C4330e c4330e = new C4330e("(https?|ftp|file)://[-a-zA-Z0-9+&@#/%?=~_|!:,.;]*[-a-zA-Z0-9+&@#/%=~_|]");
        autoLinkTextView.m4937a(c4330e);
        autoLinkTextView.m4938b(c4330e, new ForegroundColorSpan(Color.argb(255, 230, 2, 23)), new AbsoluteSizeSpan(15, true));
        autoLinkTextView.m4939c(new Function1<C4326a, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.UpgradeVipDialog$createDialog$4
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
                Context requireContext = UpgradeVipDialog.this.requireContext();
                Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
                C0840d.a.m174d(aVar, requireContext, it.f11174c, null, null, 12);
            }
        });
        autoLinkTextView.setText(this.content);
        textView2.setText(this.title);
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
