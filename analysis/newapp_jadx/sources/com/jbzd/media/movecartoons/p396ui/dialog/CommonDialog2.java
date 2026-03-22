package com.jbzd.media.movecartoons.p396ui.dialog;

import android.app.Dialog;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.appcompat.app.AlertDialog;
import androidx.fragment.app.DialogFragment;
import com.jbzd.media.movecartoons.p396ui.index.home.child.VideoListActivity;
import com.jbzd.media.movecartoons.view.GradientRoundCornerButton;
import com.qnmd.adnnm.da0yzo.R;
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
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000J\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0004\n\u0002\u0010\u000e\n\u0002\b\u0006\n\u0002\u0010\b\n\u0002\b\b\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0010\u000b\n\u0002\b\r\u0018\u00002\u00020\u0001Bk\u0012\u0006\u0010\u0015\u001a\u00020\u0010\u0012\b\b\u0002\u0010(\u001a\u00020'\u0012\u0006\u0010\u001e\u001a\u00020\u0010\u0012\b\b\u0002\u0010\u0018\u001a\u00020\u0017\u0012\u0006\u0010\u001c\u001a\u00020\u0010\u0012\u0006\u0010\u0011\u001a\u00020\u0010\u0012\u000e\b\u0002\u0010.\u001a\b\u0012\u0004\u0012\u00020\u000b0\n\u0012\u000e\b\u0002\u00100\u001a\b\u0012\u0004\u0012\u00020\u000b0\n\u0012\u000e\b\u0002\u0010\f\u001a\b\u0012\u0004\u0012\u00020\u000b0\n¢\u0006\u0004\b2\u00103J\u000f\u0010\u0003\u001a\u00020\u0002H\u0002¢\u0006\u0004\b\u0003\u0010\u0004J\u0019\u0010\b\u001a\u00020\u00072\b\u0010\u0006\u001a\u0004\u0018\u00010\u0005H\u0016¢\u0006\u0004\b\b\u0010\tR\u001f\u0010\f\u001a\b\u0012\u0004\u0012\u00020\u000b0\n8\u0006@\u0006¢\u0006\f\n\u0004\b\f\u0010\r\u001a\u0004\b\u000e\u0010\u000fR\u0019\u0010\u0011\u001a\u00020\u00108\u0006@\u0006¢\u0006\f\n\u0004\b\u0011\u0010\u0012\u001a\u0004\b\u0013\u0010\u0014R\u0019\u0010\u0015\u001a\u00020\u00108\u0006@\u0006¢\u0006\f\n\u0004\b\u0015\u0010\u0012\u001a\u0004\b\u0016\u0010\u0014R\u0019\u0010\u0018\u001a\u00020\u00178\u0006@\u0006¢\u0006\f\n\u0004\b\u0018\u0010\u0019\u001a\u0004\b\u001a\u0010\u001bR\u0019\u0010\u001c\u001a\u00020\u00108\u0006@\u0006¢\u0006\f\n\u0004\b\u001c\u0010\u0012\u001a\u0004\b\u001d\u0010\u0014R\u0019\u0010\u001e\u001a\u00020\u00108\u0006@\u0006¢\u0006\f\n\u0004\b\u001e\u0010\u0012\u001a\u0004\b\u001f\u0010\u0014R%\u0010&\u001a\n !*\u0004\u0018\u00010 0 8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\"\u0010#\u001a\u0004\b$\u0010%R\u0019\u0010(\u001a\u00020'8\u0006@\u0006¢\u0006\f\n\u0004\b(\u0010)\u001a\u0004\b(\u0010*R\u001d\u0010-\u001a\u00020\u00028B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b+\u0010#\u001a\u0004\b,\u0010\u0004R\u001f\u0010.\u001a\b\u0012\u0004\u0012\u00020\u000b0\n8\u0006@\u0006¢\u0006\f\n\u0004\b.\u0010\r\u001a\u0004\b/\u0010\u000fR\u001f\u00100\u001a\b\u0012\u0004\u0012\u00020\u000b0\n8\u0006@\u0006¢\u0006\f\n\u0004\b0\u0010\r\u001a\u0004\b1\u0010\u000f¨\u00064"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/dialog/CommonDialog2;", "Landroidx/fragment/app/DialogFragment;", "Landroidx/appcompat/app/AlertDialog;", "createDialog", "()Landroidx/appcompat/app/AlertDialog;", "Landroid/os/Bundle;", "savedInstanceState", "Landroid/app/Dialog;", "onCreateDialog", "(Landroid/os/Bundle;)Landroid/app/Dialog;", "Lkotlin/Function0;", "", "onClose", "Lkotlin/jvm/functions/Function0;", "getOnClose", "()Lkotlin/jvm/functions/Function0;", "", "okText", "Ljava/lang/String;", "getOkText", "()Ljava/lang/String;", VideoListActivity.KEY_TITLE, "getTitle", "", "contentGravity", "I", "getContentGravity", "()I", "cancelText", "getCancelText", "content", "getContent", "Landroid/view/View;", "kotlin.jvm.PlatformType", "contentView$delegate", "Lkotlin/Lazy;", "getContentView", "()Landroid/view/View;", "contentView", "", "isShowClose", "Z", "()Z", "alertDialog$delegate", "getAlertDialog", "alertDialog", "onCancel", "getOnCancel", "onOk", "getOnOk", "<init>", "(Ljava/lang/String;ZLjava/lang/String;ILjava/lang/String;Ljava/lang/String;Lkotlin/jvm/functions/Function0;Lkotlin/jvm/functions/Function0;Lkotlin/jvm/functions/Function0;)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class CommonDialog2 extends DialogFragment {

    /* renamed from: alertDialog$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy alertDialog;

    @NotNull
    private final String cancelText;

    @NotNull
    private final String content;
    private final int contentGravity;

    /* renamed from: contentView$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy contentView;
    private final boolean isShowClose;

    @NotNull
    private final String okText;

    @NotNull
    private final Function0<Unit> onCancel;

    @NotNull
    private final Function0<Unit> onClose;

    @NotNull
    private final Function0<Unit> onOk;

    @NotNull
    private final String title;

    public /* synthetic */ CommonDialog2(String str, boolean z, String str2, int i2, String str3, String str4, Function0 function0, Function0 function02, Function0 function03, int i3, DefaultConstructorMarker defaultConstructorMarker) {
        this(str, (i3 & 2) != 0 ? true : z, str2, (i3 & 8) != 0 ? 17 : i2, str3, str4, (i3 & 64) != 0 ? new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.CommonDialog2.1
            @Override // kotlin.jvm.functions.Function0
            public /* bridge */ /* synthetic */ Unit invoke() {
                invoke2();
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2() {
            }
        } : function0, (i3 & 128) != 0 ? new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.CommonDialog2.2
            @Override // kotlin.jvm.functions.Function0
            public /* bridge */ /* synthetic */ Unit invoke() {
                invoke2();
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2() {
            }
        } : function02, (i3 & 256) != 0 ? new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.CommonDialog2.3
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
        ImageView imageView = (ImageView) getContentView().findViewById(R.id.iv_close);
        TextView textView = (TextView) getContentView().findViewById(R.id.tv_title);
        TextView textView2 = (TextView) getContentView().findViewById(R.id.tv_content);
        textView2.setGravity(getContentGravity());
        GradientRoundCornerButton gradientRoundCornerButton = (GradientRoundCornerButton) getContentView().findViewById(R.id.btn_cancel);
        GradientRoundCornerButton gradientRoundCornerButton2 = (GradientRoundCornerButton) getContentView().findViewById(R.id.btn_ok);
        textView.setText(this.title);
        textView2.setText(this.content);
        gradientRoundCornerButton.setText(this.cancelText);
        gradientRoundCornerButton2.setText(this.okText);
        imageView.setVisibility(getIsShowClose() ? 0 : 4);
        C2354n.m2374A(imageView, 0L, new Function1<ImageView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.CommonDialog2$createDialog$1$1
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
                CommonDialog2.this.dismissAllowingStateLoss();
                CommonDialog2.this.getOnClose().invoke();
            }
        }, 1);
        C2354n.m2374A(gradientRoundCornerButton, 0L, new Function1<GradientRoundCornerButton, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.CommonDialog2$createDialog$2
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(GradientRoundCornerButton gradientRoundCornerButton3) {
                invoke2(gradientRoundCornerButton3);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(GradientRoundCornerButton gradientRoundCornerButton3) {
                CommonDialog2.this.getOnCancel().invoke();
            }
        }, 1);
        C2354n.m2374A(gradientRoundCornerButton2, 0L, new Function1<GradientRoundCornerButton, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.CommonDialog2$createDialog$3
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(GradientRoundCornerButton gradientRoundCornerButton3) {
                invoke2(gradientRoundCornerButton3);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(GradientRoundCornerButton gradientRoundCornerButton3) {
                CommonDialog2.this.getOnOk().invoke();
            }
        }, 1);
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
    public final String getCancelText() {
        return this.cancelText;
    }

    @NotNull
    public final String getContent() {
        return this.content;
    }

    public final int getContentGravity() {
        return this.contentGravity;
    }

    @NotNull
    public final String getOkText() {
        return this.okText;
    }

    @NotNull
    public final Function0<Unit> getOnCancel() {
        return this.onCancel;
    }

    @NotNull
    public final Function0<Unit> getOnClose() {
        return this.onClose;
    }

    @NotNull
    public final Function0<Unit> getOnOk() {
        return this.onOk;
    }

    @NotNull
    public final String getTitle() {
        return this.title;
    }

    /* renamed from: isShowClose, reason: from getter */
    public final boolean getIsShowClose() {
        return this.isShowClose;
    }

    @Override // androidx.fragment.app.DialogFragment
    @NotNull
    public Dialog onCreateDialog(@Nullable Bundle savedInstanceState) {
        return getAlertDialog();
    }

    public CommonDialog2(@NotNull String title, boolean z, @NotNull String content, int i2, @NotNull String cancelText, @NotNull String okText, @NotNull Function0<Unit> onCancel, @NotNull Function0<Unit> onOk, @NotNull Function0<Unit> onClose) {
        Intrinsics.checkNotNullParameter(title, "title");
        Intrinsics.checkNotNullParameter(content, "content");
        Intrinsics.checkNotNullParameter(cancelText, "cancelText");
        Intrinsics.checkNotNullParameter(okText, "okText");
        Intrinsics.checkNotNullParameter(onCancel, "onCancel");
        Intrinsics.checkNotNullParameter(onOk, "onOk");
        Intrinsics.checkNotNullParameter(onClose, "onClose");
        this.title = title;
        this.isShowClose = z;
        this.content = content;
        this.contentGravity = i2;
        this.cancelText = cancelText;
        this.okText = okText;
        this.onCancel = onCancel;
        this.onOk = onOk;
        this.onClose = onClose;
        this.contentView = LazyKt__LazyJVMKt.lazy(new Function0<View>() { // from class: com.jbzd.media.movecartoons.ui.dialog.CommonDialog2$contentView$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            public final View invoke() {
                return LayoutInflater.from(CommonDialog2.this.getContext()).inflate(R.layout.dialog_common2, (ViewGroup) null);
            }
        });
        this.alertDialog = LazyKt__LazyJVMKt.lazy(new Function0<AlertDialog>() { // from class: com.jbzd.media.movecartoons.ui.dialog.CommonDialog2$alertDialog$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final AlertDialog invoke() {
                AlertDialog createDialog;
                createDialog = CommonDialog2.this.createDialog();
                return createDialog;
            }
        });
    }
}
