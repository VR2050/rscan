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
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.appcompat.app.AlertDialog;
import androidx.fragment.app.DialogFragment;
import com.qnmd.adnnm.da0yzo.R;
import io.github.armcha.autolink.AutoLinkTextView;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p006a.p007a.p008a.p009a.C0840d;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p429g.p430a.p431a.p432a.C4326a;
import p429g.p430a.p431a.p432a.C4330e;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000D\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0002\b\n\n\u0002\u0010\u000b\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0010\u0018\u00002\u00020\u0001BK\u0012\u0006\u0010\u0014\u001a\u00020\u000f\u0012\u0006\u0010\u001b\u001a\u00020\u001a\u0012\u0006\u0010\u0010\u001a\u00020\u000f\u0012\f\u0010*\u001a\b\u0012\u0004\u0012\u00020\f0\u001e\u0012\f\u0010(\u001a\b\u0012\u0004\u0012\u00020\f0\u001e\u0012\u000e\b\u0002\u0010\u001f\u001a\b\u0012\u0004\u0012\u00020\f0\u001e¢\u0006\u0004\b,\u0010-J\u000f\u0010\u0003\u001a\u00020\u0002H\u0002¢\u0006\u0004\b\u0003\u0010\u0004J\u0019\u0010\b\u001a\u00020\u00072\b\u0010\u0006\u001a\u0004\u0018\u00010\u0005H\u0016¢\u0006\u0004\b\b\u0010\tJ!\u0010\r\u001a\u00020\f2\u0006\u0010\u000b\u001a\u00020\n2\b\u0010\u0006\u001a\u0004\u0018\u00010\u0005H\u0016¢\u0006\u0004\b\r\u0010\u000eR\u0019\u0010\u0010\u001a\u00020\u000f8\u0006@\u0006¢\u0006\f\n\u0004\b\u0010\u0010\u0011\u001a\u0004\b\u0012\u0010\u0013R\u0019\u0010\u0014\u001a\u00020\u000f8\u0006@\u0006¢\u0006\f\n\u0004\b\u0014\u0010\u0011\u001a\u0004\b\u0015\u0010\u0013R\u001d\u0010\u0019\u001a\u00020\u00028B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u0016\u0010\u0017\u001a\u0004\b\u0018\u0010\u0004R\u0019\u0010\u001b\u001a\u00020\u001a8\u0006@\u0006¢\u0006\f\n\u0004\b\u001b\u0010\u001c\u001a\u0004\b\u001b\u0010\u001dR\u001f\u0010\u001f\u001a\b\u0012\u0004\u0012\u00020\f0\u001e8\u0006@\u0006¢\u0006\f\n\u0004\b\u001f\u0010 \u001a\u0004\b!\u0010\"R%\u0010'\u001a\n #*\u0004\u0018\u00010\n0\n8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b$\u0010\u0017\u001a\u0004\b%\u0010&R\u001f\u0010(\u001a\b\u0012\u0004\u0012\u00020\f0\u001e8\u0006@\u0006¢\u0006\f\n\u0004\b(\u0010 \u001a\u0004\b)\u0010\"R\u001f\u0010*\u001a\b\u0012\u0004\u0012\u00020\f0\u001e8\u0006@\u0006¢\u0006\f\n\u0004\b*\u0010 \u001a\u0004\b+\u0010\"¨\u0006."}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/dialog/UpdateDialog;", "Landroidx/fragment/app/DialogFragment;", "Landroidx/appcompat/app/AlertDialog;", "createDialog", "()Landroidx/appcompat/app/AlertDialog;", "Landroid/os/Bundle;", "savedInstanceState", "Landroid/app/Dialog;", "onCreateDialog", "(Landroid/os/Bundle;)Landroid/app/Dialog;", "Landroid/view/View;", "view", "", "onViewCreated", "(Landroid/view/View;Landroid/os/Bundle;)V", "", "content", "Ljava/lang/String;", "getContent", "()Ljava/lang/String;", "newVersion", "getNewVersion", "alertDialog$delegate", "Lkotlin/Lazy;", "getAlertDialog", "alertDialog", "", "isMandatoryUpdate", "Z", "()Z", "Lkotlin/Function0;", "cancelBlock", "Lkotlin/jvm/functions/Function0;", "getCancelBlock", "()Lkotlin/jvm/functions/Function0;", "kotlin.jvm.PlatformType", "contentView$delegate", "getContentView", "()Landroid/view/View;", "contentView", "confirmBlock", "getConfirmBlock", "officialBlock", "getOfficialBlock", "<init>", "(Ljava/lang/String;ZLjava/lang/String;Lkotlin/jvm/functions/Function0;Lkotlin/jvm/functions/Function0;Lkotlin/jvm/functions/Function0;)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class UpdateDialog extends DialogFragment {

    /* renamed from: alertDialog$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy alertDialog;

    @NotNull
    private final Function0<Unit> cancelBlock;

    @NotNull
    private final Function0<Unit> confirmBlock;

    @NotNull
    private final String content;

    /* renamed from: contentView$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy contentView;
    private final boolean isMandatoryUpdate;

    @NotNull
    private final String newVersion;

    @NotNull
    private final Function0<Unit> officialBlock;

    public /* synthetic */ UpdateDialog(String str, boolean z, String str2, Function0 function0, Function0 function02, Function0 function03, int i2, DefaultConstructorMarker defaultConstructorMarker) {
        this(str, z, str2, function0, function02, (i2 & 32) != 0 ? new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.UpdateDialog.1
            @Override // kotlin.jvm.functions.Function0
            public /* bridge */ /* synthetic */ Unit invoke() {
                invoke2();
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2() {
            }
        } : function03);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final AlertDialog createDialog() {
        AlertDialog m624j0 = C1499a.m624j0(new AlertDialog.Builder(requireContext(), R.style.dialog_center), getContentView(), "Builder(requireContext(), R.style.dialog_center)\n            .setView(contentView)\n            .create()");
        TextView textView = (TextView) getContentView().findViewById(R.id.btnCancel);
        C2354n.m2374A(textView, 0L, new Function1<TextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.UpdateDialog$createDialog$1$1
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
                UpdateDialog.this.getOfficialBlock().invoke();
            }
        }, 1);
        textView.setVisibility(getIsMandatoryUpdate() ? 8 : 0);
        if (!getIsMandatoryUpdate()) {
            ((TextView) getContentView().findViewById(R.id.btnCancel)).setText("官网更新");
        }
        ImageView imageView = (ImageView) getContentView().findViewById(R.id.iv_close);
        Intrinsics.checkNotNullExpressionValue(imageView, "");
        imageView.setVisibility(getIsMandatoryUpdate() ^ true ? 0 : 8);
        C2354n.m2374A(imageView, 0L, new Function1<ImageView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.UpdateDialog$createDialog$2$1
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(ImageView imageView2) {
                invoke2(imageView2);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(ImageView imageView2) {
                UpdateDialog.this.dismissAllowingStateLoss();
                UpdateDialog.this.getCancelBlock().invoke();
            }
        }, 1);
        C2354n.m2374A(getContentView().findViewById(R.id.btnUpdate), 0L, new Function1<TextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.UpdateDialog$createDialog$3
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
                UpdateDialog.this.dismissAllowingStateLoss();
                UpdateDialog.this.getConfirmBlock().invoke();
            }
        }, 1);
        C2354n.m2374A(getContentView().findViewById(R.id.btnAccount), 0L, new Function1<LinearLayout, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.UpdateDialog$createDialog$4
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(LinearLayout linearLayout) {
                invoke2(linearLayout);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(LinearLayout linearLayout) {
                new IdcardDialog().show(UpdateDialog.this.getChildFragmentManager(), "SaveIdcardDialog");
            }
        }, 1);
        AutoLinkTextView autoLinkTextView = (AutoLinkTextView) getContentView().findViewById(R.id.tvTips);
        C4330e c4330e = new C4330e("(https?|ftp|file)://[-a-zA-Z0-9+&@#/%?=~_|!:,.;]*[-a-zA-Z0-9+&@#/%=~_|]");
        autoLinkTextView.m4937a(c4330e);
        autoLinkTextView.m4938b(c4330e, new ForegroundColorSpan(Color.argb(255, 230, 2, 23)), new AbsoluteSizeSpan(15, true));
        autoLinkTextView.m4939c(new Function1<C4326a, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.UpdateDialog$createDialog$5
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
                Context requireContext = UpdateDialog.this.requireContext();
                Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
                C0840d.a.m174d(aVar, requireContext, it.f11174c, null, null, 12);
            }
        });
        autoLinkTextView.setText(this.content);
        Window window = m624j0.getWindow();
        if (window != null) {
            window.setDimAmount(0.8f);
        }
        WindowManager.LayoutParams attributes = window == null ? null : window.getAttributes();
        if (attributes != null) {
            attributes.windowAnimations = R.style.BottomShowAnimation;
        }
        m624j0.setCancelable(false);
        m624j0.setCanceledOnTouchOutside(false);
        setCancelable(false);
        return m624j0;
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
    public final Function0<Unit> getCancelBlock() {
        return this.cancelBlock;
    }

    @NotNull
    public final Function0<Unit> getConfirmBlock() {
        return this.confirmBlock;
    }

    @NotNull
    public final String getContent() {
        return this.content;
    }

    @NotNull
    public final String getNewVersion() {
        return this.newVersion;
    }

    @NotNull
    public final Function0<Unit> getOfficialBlock() {
        return this.officialBlock;
    }

    /* renamed from: isMandatoryUpdate, reason: from getter */
    public final boolean getIsMandatoryUpdate() {
        return this.isMandatoryUpdate;
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

    public UpdateDialog(@NotNull String newVersion, boolean z, @NotNull String content, @NotNull Function0<Unit> officialBlock, @NotNull Function0<Unit> confirmBlock, @NotNull Function0<Unit> cancelBlock) {
        Intrinsics.checkNotNullParameter(newVersion, "newVersion");
        Intrinsics.checkNotNullParameter(content, "content");
        Intrinsics.checkNotNullParameter(officialBlock, "officialBlock");
        Intrinsics.checkNotNullParameter(confirmBlock, "confirmBlock");
        Intrinsics.checkNotNullParameter(cancelBlock, "cancelBlock");
        this.newVersion = newVersion;
        this.isMandatoryUpdate = z;
        this.content = content;
        this.officialBlock = officialBlock;
        this.confirmBlock = confirmBlock;
        this.cancelBlock = cancelBlock;
        this.contentView = LazyKt__LazyJVMKt.lazy(new Function0<View>() { // from class: com.jbzd.media.movecartoons.ui.dialog.UpdateDialog$contentView$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            public final View invoke() {
                return LayoutInflater.from(UpdateDialog.this.getContext()).inflate(R.layout.dialog_update, (ViewGroup) null);
            }
        });
        this.alertDialog = LazyKt__LazyJVMKt.lazy(new Function0<AlertDialog>() { // from class: com.jbzd.media.movecartoons.ui.dialog.UpdateDialog$alertDialog$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final AlertDialog invoke() {
                AlertDialog createDialog;
                createDialog = UpdateDialog.this.createDialog();
                return createDialog;
            }
        });
    }
}
