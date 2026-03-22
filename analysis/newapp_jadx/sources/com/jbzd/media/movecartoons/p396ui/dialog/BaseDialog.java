package com.jbzd.media.movecartoons.p396ui.dialog;

import android.app.AlertDialog;
import android.app.Dialog;
import android.content.DialogInterface;
import android.graphics.Color;
import android.os.Bundle;
import android.view.KeyEvent;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.view.WindowManager;
import android.widget.EditText;
import android.widget.RelativeLayout;
import android.widget.TextView;
import androidx.cardview.widget.CardView;
import androidx.core.app.NotificationCompat;
import androidx.fragment.app.DialogFragment;
import com.jbzd.media.movecartoons.p396ui.dialog.BaseDialog;
import com.jbzd.media.movecartoons.p396ui.index.home.child.VideoListActivity;
import com.qnmd.adnnm.da0yzo.R;
import java.util.Objects;
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
import p005b.p199l.p200a.p201a.p250p1.C2354n;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000p\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0010\u000e\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0010\u000b\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\b-\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\b\u0007\u0018\u00002\u00020\u0001BÞ\u0001\u0012\u0006\u0010F\u001a\u00020\u0012\u0012\u0006\u0010B\u001a\u00020\u0012\u0012\n\b\u0002\u0010D\u001a\u0004\u0018\u00010\u0012\u0012#\b\u0002\u0010+\u001a\u001d\u0012\u0013\u0012\u00110\u0012¢\u0006\f\b(\u0012\b\b)\u0012\u0004\b\b(*\u0012\u0004\u0012\u00020\t0'\u0012\n\b\u0002\u0010[\u001a\u0004\u0018\u00010\u0012\u0012\u000e\b\u0002\u0010=\u001a\b\u0012\u0004\u0012\u00020\t0/\u0012\n\b\u0002\u0010N\u001a\u0004\u0018\u00010\u0012\u0012\u000e\b\u0002\u0010R\u001a\b\u0012\u0004\u0012\u00020\t0/\u0012\n\b\u0002\u0010T\u001a\u0004\u0018\u00010\u0012\u0012\u000e\b\u0002\u00100\u001a\b\u0012\u0004\u0012\u00020\t0/\u0012\n\b\u0002\u0010\u0013\u001a\u0004\u0018\u00010\u0012\u0012\u000e\b\u0002\u0010V\u001a\b\u0012\u0004\u0012\u00020\t0/\u0012\b\b\u0002\u0010#\u001a\u00020\"\u0012\n\b\u0002\u0010b\u001a\u0004\u0018\u00010\u0012\u0012\u000e\b\u0002\u0010P\u001a\b\u0012\u0004\u0012\u00020\t0/¢\u0006\u0004\bi\u0010jJ\u0019\u0010\u0005\u001a\u00020\u00042\b\u0010\u0003\u001a\u0004\u0018\u00010\u0002H\u0016¢\u0006\u0004\b\u0005\u0010\u0006J\u0017\u0010\n\u001a\u00020\t2\u0006\u0010\b\u001a\u00020\u0007H\u0016¢\u0006\u0004\b\n\u0010\u000bR\u001d\u0010\u0011\u001a\u00020\f8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\r\u0010\u000e\u001a\u0004\b\u000f\u0010\u0010R\u001b\u0010\u0013\u001a\u0004\u0018\u00010\u00128\u0006@\u0006¢\u0006\f\n\u0004\b\u0013\u0010\u0014\u001a\u0004\b\u0015\u0010\u0016R\u001d\u0010\u001b\u001a\u00020\u00178F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u0018\u0010\u000e\u001a\u0004\b\u0019\u0010\u001aR%\u0010!\u001a\n \u001d*\u0004\u0018\u00010\u001c0\u001c8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u001e\u0010\u000e\u001a\u0004\b\u001f\u0010 R\u0019\u0010#\u001a\u00020\"8\u0006@\u0006¢\u0006\f\n\u0004\b#\u0010$\u001a\u0004\b%\u0010&R4\u0010+\u001a\u001d\u0012\u0013\u0012\u00110\u0012¢\u0006\f\b(\u0012\b\b)\u0012\u0004\b\b(*\u0012\u0004\u0012\u00020\t0'8\u0006@\u0006¢\u0006\f\n\u0004\b+\u0010,\u001a\u0004\b-\u0010.R\u001f\u00100\u001a\b\u0012\u0004\u0012\u00020\t0/8\u0006@\u0006¢\u0006\f\n\u0004\b0\u00101\u001a\u0004\b2\u00103R\u001d\u00106\u001a\u00020\u00178F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b4\u0010\u000e\u001a\u0004\b5\u0010\u001aR\u001d\u00109\u001a\u00020\u001c8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b7\u0010\u000e\u001a\u0004\b8\u0010 R\u001d\u0010<\u001a\u00020\u00178F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b:\u0010\u000e\u001a\u0004\b;\u0010\u001aR\u001f\u0010=\u001a\b\u0012\u0004\u0012\u00020\t0/8\u0006@\u0006¢\u0006\f\n\u0004\b=\u00101\u001a\u0004\b>\u00103R\u001d\u0010A\u001a\u00020\u00178F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b?\u0010\u000e\u001a\u0004\b@\u0010\u001aR\u0019\u0010B\u001a\u00020\u00128\u0006@\u0006¢\u0006\f\n\u0004\bB\u0010\u0014\u001a\u0004\bC\u0010\u0016R\u001b\u0010D\u001a\u0004\u0018\u00010\u00128\u0006@\u0006¢\u0006\f\n\u0004\bD\u0010\u0014\u001a\u0004\bE\u0010\u0016R\u0019\u0010F\u001a\u00020\u00128\u0006@\u0006¢\u0006\f\n\u0004\bF\u0010\u0014\u001a\u0004\bG\u0010\u0016R\u001d\u0010J\u001a\u00020\u00178F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bH\u0010\u000e\u001a\u0004\bI\u0010\u001aR\u001d\u0010M\u001a\u00020\u00178F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bK\u0010\u000e\u001a\u0004\bL\u0010\u001aR\u001b\u0010N\u001a\u0004\u0018\u00010\u00128\u0006@\u0006¢\u0006\f\n\u0004\bN\u0010\u0014\u001a\u0004\bO\u0010\u0016R\u001f\u0010P\u001a\b\u0012\u0004\u0012\u00020\t0/8\u0006@\u0006¢\u0006\f\n\u0004\bP\u00101\u001a\u0004\bQ\u00103R\u001f\u0010R\u001a\b\u0012\u0004\u0012\u00020\t0/8\u0006@\u0006¢\u0006\f\n\u0004\bR\u00101\u001a\u0004\bS\u00103R\u001b\u0010T\u001a\u0004\u0018\u00010\u00128\u0006@\u0006¢\u0006\f\n\u0004\bT\u0010\u0014\u001a\u0004\bU\u0010\u0016R\u001f\u0010V\u001a\b\u0012\u0004\u0012\u00020\t0/8\u0006@\u0006¢\u0006\f\n\u0004\bV\u00101\u001a\u0004\bW\u00103R\u001d\u0010Z\u001a\u00020\u00178F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bX\u0010\u000e\u001a\u0004\bY\u0010\u001aR\u001b\u0010[\u001a\u0004\u0018\u00010\u00128\u0006@\u0006¢\u0006\f\n\u0004\b[\u0010\u0014\u001a\u0004\b\\\u0010\u0016R\u001d\u0010a\u001a\u00020]8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b^\u0010\u000e\u001a\u0004\b_\u0010`R\u001b\u0010b\u001a\u0004\u0018\u00010\u00128\u0006@\u0006¢\u0006\f\n\u0004\bb\u0010\u0014\u001a\u0004\bc\u0010\u0016R\u001d\u0010h\u001a\u00020d8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\be\u0010\u000e\u001a\u0004\bf\u0010g¨\u0006k"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/dialog/BaseDialog;", "Landroidx/fragment/app/DialogFragment;", "Landroid/os/Bundle;", "savedInstanceState", "Landroid/app/Dialog;", "onCreateDialog", "(Landroid/os/Bundle;)Landroid/app/Dialog;", "Landroid/content/DialogInterface;", "dialog", "", "onDismiss", "(Landroid/content/DialogInterface;)V", "Landroid/widget/EditText;", "edut$delegate", "Lkotlin/Lazy;", "getEdut", "()Landroid/widget/EditText;", "edut", "", "subTitle", "Ljava/lang/String;", "getSubTitle", "()Ljava/lang/String;", "Landroid/widget/TextView;", "tv_title$delegate", "getTv_title", "()Landroid/widget/TextView;", "tv_title", "Landroid/view/View;", "kotlin.jvm.PlatformType", "contentView$delegate", "getContentView", "()Landroid/view/View;", "contentView", "", "cancelable", "Z", "getCancelable", "()Z", "Lkotlin/Function1;", "Lkotlin/ParameterName;", "name", "reslut", "enterBlock", "Lkotlin/jvm/functions/Function1;", "getEnterBlock", "()Lkotlin/jvm/functions/Function1;", "Lkotlin/Function0;", "negativeBlock", "Lkotlin/jvm/functions/Function0;", "getNegativeBlock", "()Lkotlin/jvm/functions/Function0;", "tv_msg$delegate", "getTv_msg", "tv_msg", "ll_buttons$delegate", "getLl_buttons", "ll_buttons", "btn_bottom_menu$delegate", "getBtn_bottom_menu", "btn_bottom_menu", "positiveBlock", "getPositiveBlock", "btn_positive$delegate", "getBtn_positive", "btn_positive", NotificationCompat.CATEGORY_MESSAGE, "getMsg", "editHintStr", "getEditHintStr", VideoListActivity.KEY_TITLE, "getTitle", "tv_subTitle$delegate", "getTv_subTitle", "tv_subTitle", "btn_positive2$delegate", "getBtn_positive2", "btn_positive2", "positiveText2", "getPositiveText2", "bottomMenuBlock", "getBottomMenuBlock", "positiveBlock2", "getPositiveBlock2", "negativeText", "getNegativeText", "dismissBlock", "getDismissBlock", "btn_negative$delegate", "getBtn_negative", "btn_negative", "positiveText", "getPositiveText", "Landroidx/cardview/widget/CardView;", "card_content$delegate", "getCard_content", "()Landroidx/cardview/widget/CardView;", "card_content", "bottomMenuText", "getBottomMenuText", "Landroid/widget/RelativeLayout;", "rl_edit$delegate", "getRl_edit", "()Landroid/widget/RelativeLayout;", "rl_edit", "<init>", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lkotlin/jvm/functions/Function1;Ljava/lang/String;Lkotlin/jvm/functions/Function0;Ljava/lang/String;Lkotlin/jvm/functions/Function0;Ljava/lang/String;Lkotlin/jvm/functions/Function0;Ljava/lang/String;Lkotlin/jvm/functions/Function0;ZLjava/lang/String;Lkotlin/jvm/functions/Function0;)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class BaseDialog extends DialogFragment {

    @NotNull
    private final Function0<Unit> bottomMenuBlock;

    @Nullable
    private final String bottomMenuText;

    /* renamed from: btn_bottom_menu$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy btn_bottom_menu;

    /* renamed from: btn_negative$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy btn_negative;

    /* renamed from: btn_positive$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy btn_positive;

    /* renamed from: btn_positive2$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy btn_positive2;
    private final boolean cancelable;

    /* renamed from: card_content$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy card_content;

    /* renamed from: contentView$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy contentView;

    @NotNull
    private final Function0<Unit> dismissBlock;

    @Nullable
    private final String editHintStr;

    /* renamed from: edut$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy edut;

    @NotNull
    private final Function1<String, Unit> enterBlock;

    /* renamed from: ll_buttons$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy ll_buttons;

    @NotNull
    private final String msg;

    @NotNull
    private final Function0<Unit> negativeBlock;

    @Nullable
    private final String negativeText;

    @NotNull
    private final Function0<Unit> positiveBlock;

    @NotNull
    private final Function0<Unit> positiveBlock2;

    @Nullable
    private final String positiveText;

    @Nullable
    private final String positiveText2;

    /* renamed from: rl_edit$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy rl_edit;

    @Nullable
    private final String subTitle;

    @NotNull
    private final String title;

    /* renamed from: tv_msg$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_msg;

    /* renamed from: tv_subTitle$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_subTitle;

    /* renamed from: tv_title$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_title;

    public /* synthetic */ BaseDialog(String str, String str2, String str3, Function1 function1, String str4, Function0 function0, String str5, Function0 function02, String str6, Function0 function03, String str7, Function0 function04, boolean z, String str8, Function0 function05, int i2, DefaultConstructorMarker defaultConstructorMarker) {
        this(str, str2, (i2 & 4) != 0 ? null : str3, (i2 & 8) != 0 ? new Function1<String, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.BaseDialog.1
            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(String str9) {
                invoke2(str9);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull String it) {
                Intrinsics.checkNotNullParameter(it, "it");
            }
        } : function1, (i2 & 16) != 0 ? null : str4, (i2 & 32) != 0 ? new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.BaseDialog.2
            @Override // kotlin.jvm.functions.Function0
            public /* bridge */ /* synthetic */ Unit invoke() {
                invoke2();
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2() {
            }
        } : function0, (i2 & 64) != 0 ? null : str5, (i2 & 128) != 0 ? new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.BaseDialog.3
            @Override // kotlin.jvm.functions.Function0
            public /* bridge */ /* synthetic */ Unit invoke() {
                invoke2();
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2() {
            }
        } : function02, (i2 & 256) != 0 ? null : str6, (i2 & 512) != 0 ? new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.BaseDialog.4
            @Override // kotlin.jvm.functions.Function0
            public /* bridge */ /* synthetic */ Unit invoke() {
                invoke2();
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2() {
            }
        } : function03, (i2 & 1024) != 0 ? null : str7, (i2 & 2048) != 0 ? new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.BaseDialog.5
            @Override // kotlin.jvm.functions.Function0
            public /* bridge */ /* synthetic */ Unit invoke() {
                invoke2();
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2() {
            }
        } : function04, (i2 & 4096) != 0 ? true : z, (i2 & 8192) != 0 ? null : str8, (i2 & 16384) != 0 ? new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.BaseDialog.6
            @Override // kotlin.jvm.functions.Function0
            public /* bridge */ /* synthetic */ Unit invoke() {
                invoke2();
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2() {
            }
        } : function05);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: onCreateDialog$lambda-6, reason: not valid java name */
    public static final boolean m5769onCreateDialog$lambda6(BaseDialog this$0, DialogInterface dialogInterface, int i2, KeyEvent keyEvent) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        if (i2 == 4) {
            return !this$0.getCancelable();
        }
        return false;
    }

    public void _$_clearFindViewByIdCache() {
    }

    @NotNull
    public final Function0<Unit> getBottomMenuBlock() {
        return this.bottomMenuBlock;
    }

    @Nullable
    public final String getBottomMenuText() {
        return this.bottomMenuText;
    }

    @NotNull
    public final TextView getBtn_bottom_menu() {
        return (TextView) this.btn_bottom_menu.getValue();
    }

    @NotNull
    public final TextView getBtn_negative() {
        return (TextView) this.btn_negative.getValue();
    }

    @NotNull
    public final TextView getBtn_positive() {
        return (TextView) this.btn_positive.getValue();
    }

    @NotNull
    public final TextView getBtn_positive2() {
        return (TextView) this.btn_positive2.getValue();
    }

    public final boolean getCancelable() {
        return this.cancelable;
    }

    @NotNull
    public final CardView getCard_content() {
        return (CardView) this.card_content.getValue();
    }

    public final View getContentView() {
        return (View) this.contentView.getValue();
    }

    @NotNull
    public final Function0<Unit> getDismissBlock() {
        return this.dismissBlock;
    }

    @Nullable
    public final String getEditHintStr() {
        return this.editHintStr;
    }

    @NotNull
    public final EditText getEdut() {
        return (EditText) this.edut.getValue();
    }

    @NotNull
    public final Function1<String, Unit> getEnterBlock() {
        return this.enterBlock;
    }

    @NotNull
    public final View getLl_buttons() {
        return (View) this.ll_buttons.getValue();
    }

    @NotNull
    public final String getMsg() {
        return this.msg;
    }

    @NotNull
    public final Function0<Unit> getNegativeBlock() {
        return this.negativeBlock;
    }

    @Nullable
    public final String getNegativeText() {
        return this.negativeText;
    }

    @NotNull
    public final Function0<Unit> getPositiveBlock() {
        return this.positiveBlock;
    }

    @NotNull
    public final Function0<Unit> getPositiveBlock2() {
        return this.positiveBlock2;
    }

    @Nullable
    public final String getPositiveText() {
        return this.positiveText;
    }

    @Nullable
    public final String getPositiveText2() {
        return this.positiveText2;
    }

    @NotNull
    public final RelativeLayout getRl_edit() {
        return (RelativeLayout) this.rl_edit.getValue();
    }

    @Nullable
    public final String getSubTitle() {
        return this.subTitle;
    }

    @NotNull
    public final String getTitle() {
        return this.title;
    }

    @NotNull
    public final TextView getTv_msg() {
        return (TextView) this.tv_msg.getValue();
    }

    @NotNull
    public final TextView getTv_subTitle() {
        return (TextView) this.tv_subTitle.getValue();
    }

    @NotNull
    public final TextView getTv_title() {
        return (TextView) this.tv_title.getValue();
    }

    @Override // androidx.fragment.app.DialogFragment
    @NotNull
    public Dialog onCreateDialog(@Nullable Bundle savedInstanceState) {
        getTv_title().setText(this.title);
        getTv_msg().setText(this.msg);
        if (this.positiveText != null) {
            getLl_buttons().setVisibility(0);
            getBtn_positive().setVisibility(0);
            getBtn_positive().setText(getPositiveText());
            C2354n.m2374A(getBtn_positive(), 0L, new Function1<TextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.BaseDialog$onCreateDialog$1$1
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
                    Intrinsics.checkNotNullParameter(it, "it");
                    if (BaseDialog.this.getEditHintStr() != null) {
                        BaseDialog baseDialog = BaseDialog.this;
                        baseDialog.getEnterBlock().invoke(baseDialog.getEdut().getText().toString());
                    }
                    BaseDialog.this.dismiss();
                    BaseDialog.this.getPositiveBlock().invoke();
                }
            }, 1);
        }
        if (this.negativeText != null) {
            getLl_buttons().setVisibility(0);
            getBtn_negative().setVisibility(0);
            getBtn_negative().setText(getNegativeText());
            C2354n.m2374A(getBtn_negative(), 0L, new Function1<TextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.BaseDialog$onCreateDialog$2$1
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
                    Intrinsics.checkNotNullParameter(it, "it");
                    BaseDialog.this.dismiss();
                    BaseDialog.this.getNegativeBlock().invoke();
                }
            }, 1);
        }
        if (this.positiveText2 != null) {
            getLl_buttons().setVisibility(0);
            getBtn_positive2().setVisibility(0);
            getBtn_positive2().setText(getPositiveText2());
            C2354n.m2374A(getBtn_positive2(), 0L, new Function1<TextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.BaseDialog$onCreateDialog$3$1
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
                    Intrinsics.checkNotNullParameter(it, "it");
                    BaseDialog.this.dismiss();
                    BaseDialog.this.getPositiveBlock2().invoke();
                }
            }, 1);
        }
        String str = this.editHintStr;
        if (str != null) {
            getRl_edit().setVisibility(0);
            getEdut().setHint(str);
            getEdut().setHintTextColor(Color.parseColor("#a2abc5"));
        }
        String str2 = this.subTitle;
        if (str2 != null) {
            getTv_subTitle().setText(str2);
            getTv_subTitle().setVisibility(0);
        }
        String str3 = this.bottomMenuText;
        if (str3 != null) {
            getBtn_bottom_menu().setVisibility(0);
            getBtn_bottom_menu().setText(str3);
            C2354n.m2374A(getBtn_bottom_menu(), 0L, new Function1<TextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.BaseDialog$onCreateDialog$6$1
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
                    Intrinsics.checkNotNullParameter(it, "it");
                    BaseDialog.this.getBottomMenuBlock().invoke();
                }
            }, 1);
        }
        AlertDialog dialog = new AlertDialog.Builder(getContext(), R.style.dialog_center).setView(getContentView()).setCancelable(this.cancelable).setOnKeyListener(new DialogInterface.OnKeyListener() { // from class: b.a.a.a.t.e.e
            @Override // android.content.DialogInterface.OnKeyListener
            public final boolean onKey(DialogInterface dialogInterface, int i2, KeyEvent keyEvent) {
                boolean m5769onCreateDialog$lambda6;
                m5769onCreateDialog$lambda6 = BaseDialog.m5769onCreateDialog$lambda6(BaseDialog.this, dialogInterface, i2, keyEvent);
                return m5769onCreateDialog$lambda6;
            }
        }).create();
        dialog.setCanceledOnTouchOutside(this.cancelable);
        Window window = dialog.getWindow();
        WindowManager.LayoutParams attributes = window == null ? null : window.getAttributes();
        if (attributes != null) {
            attributes.windowAnimations = R.style.BottomShowAnimation;
        }
        Intrinsics.checkNotNullExpressionValue(dialog, "dialog");
        return dialog;
    }

    @Override // androidx.fragment.app.DialogFragment, android.content.DialogInterface.OnDismissListener
    public void onDismiss(@NotNull DialogInterface dialog) {
        Intrinsics.checkNotNullParameter(dialog, "dialog");
        super.onDismiss(dialog);
        this.dismissBlock.invoke();
    }

    /* JADX WARN: Multi-variable type inference failed */
    public BaseDialog(@NotNull String title, @NotNull String msg, @Nullable String str, @NotNull Function1<? super String, Unit> enterBlock, @Nullable String str2, @NotNull Function0<Unit> positiveBlock, @Nullable String str3, @NotNull Function0<Unit> positiveBlock2, @Nullable String str4, @NotNull Function0<Unit> negativeBlock, @Nullable String str5, @NotNull Function0<Unit> dismissBlock, boolean z, @Nullable String str6, @NotNull Function0<Unit> bottomMenuBlock) {
        Intrinsics.checkNotNullParameter(title, "title");
        Intrinsics.checkNotNullParameter(msg, "msg");
        Intrinsics.checkNotNullParameter(enterBlock, "enterBlock");
        Intrinsics.checkNotNullParameter(positiveBlock, "positiveBlock");
        Intrinsics.checkNotNullParameter(positiveBlock2, "positiveBlock2");
        Intrinsics.checkNotNullParameter(negativeBlock, "negativeBlock");
        Intrinsics.checkNotNullParameter(dismissBlock, "dismissBlock");
        Intrinsics.checkNotNullParameter(bottomMenuBlock, "bottomMenuBlock");
        this.title = title;
        this.msg = msg;
        this.editHintStr = str;
        this.enterBlock = enterBlock;
        this.positiveText = str2;
        this.positiveBlock = positiveBlock;
        this.positiveText2 = str3;
        this.positiveBlock2 = positiveBlock2;
        this.negativeText = str4;
        this.negativeBlock = negativeBlock;
        this.subTitle = str5;
        this.dismissBlock = dismissBlock;
        this.cancelable = z;
        this.bottomMenuText = str6;
        this.bottomMenuBlock = bottomMenuBlock;
        this.contentView = LazyKt__LazyJVMKt.lazy(new Function0<View>() { // from class: com.jbzd.media.movecartoons.ui.dialog.BaseDialog$contentView$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            public final View invoke() {
                return LayoutInflater.from(BaseDialog.this.getContext()).inflate(R.layout.dialog_layout, (ViewGroup) null);
            }
        });
        this.tv_title = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.dialog.BaseDialog$tv_title$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final TextView invoke() {
                View findViewById = BaseDialog.this.getContentView().findViewById(R.id.tv_title);
                Objects.requireNonNull(findViewById, "null cannot be cast to non-null type android.widget.TextView");
                return (TextView) findViewById;
            }
        });
        this.tv_subTitle = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.dialog.BaseDialog$tv_subTitle$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final TextView invoke() {
                View findViewById = BaseDialog.this.getContentView().findViewById(R.id.tv_subTitle);
                Objects.requireNonNull(findViewById, "null cannot be cast to non-null type android.widget.TextView");
                return (TextView) findViewById;
            }
        });
        this.card_content = LazyKt__LazyJVMKt.lazy(new Function0<CardView>() { // from class: com.jbzd.media.movecartoons.ui.dialog.BaseDialog$card_content$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final CardView invoke() {
                View findViewById = BaseDialog.this.getContentView().findViewById(R.id.card_content);
                Objects.requireNonNull(findViewById, "null cannot be cast to non-null type androidx.cardview.widget.CardView");
                return (CardView) findViewById;
            }
        });
        this.tv_msg = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.dialog.BaseDialog$tv_msg$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final TextView invoke() {
                View findViewById = BaseDialog.this.getContentView().findViewById(R.id.tv_msg);
                Objects.requireNonNull(findViewById, "null cannot be cast to non-null type android.widget.TextView");
                return (TextView) findViewById;
            }
        });
        this.btn_negative = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.dialog.BaseDialog$btn_negative$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final TextView invoke() {
                View findViewById = BaseDialog.this.getContentView().findViewById(R.id.btn_negative);
                Objects.requireNonNull(findViewById, "null cannot be cast to non-null type android.widget.TextView");
                return (TextView) findViewById;
            }
        });
        this.btn_positive = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.dialog.BaseDialog$btn_positive$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final TextView invoke() {
                View findViewById = BaseDialog.this.getContentView().findViewById(R.id.btn_positive);
                Objects.requireNonNull(findViewById, "null cannot be cast to non-null type android.widget.TextView");
                return (TextView) findViewById;
            }
        });
        this.btn_positive2 = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.dialog.BaseDialog$btn_positive2$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final TextView invoke() {
                View findViewById = BaseDialog.this.getContentView().findViewById(R.id.btn_positive2);
                Objects.requireNonNull(findViewById, "null cannot be cast to non-null type android.widget.TextView");
                return (TextView) findViewById;
            }
        });
        this.ll_buttons = LazyKt__LazyJVMKt.lazy(new Function0<View>() { // from class: com.jbzd.media.movecartoons.ui.dialog.BaseDialog$ll_buttons$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final View invoke() {
                View findViewById = BaseDialog.this.getContentView().findViewById(R.id.ll_buttons);
                Objects.requireNonNull(findViewById, "null cannot be cast to non-null type android.view.View");
                return findViewById;
            }
        });
        this.rl_edit = LazyKt__LazyJVMKt.lazy(new Function0<RelativeLayout>() { // from class: com.jbzd.media.movecartoons.ui.dialog.BaseDialog$rl_edit$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final RelativeLayout invoke() {
                View findViewById = BaseDialog.this.getContentView().findViewById(R.id.rl_edit);
                Objects.requireNonNull(findViewById, "null cannot be cast to non-null type android.widget.RelativeLayout");
                return (RelativeLayout) findViewById;
            }
        });
        this.edut = LazyKt__LazyJVMKt.lazy(new Function0<EditText>() { // from class: com.jbzd.media.movecartoons.ui.dialog.BaseDialog$edut$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final EditText invoke() {
                View findViewById = BaseDialog.this.getContentView().findViewById(R.id.edit);
                Objects.requireNonNull(findViewById, "null cannot be cast to non-null type android.widget.EditText");
                return (EditText) findViewById;
            }
        });
        this.btn_bottom_menu = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.dialog.BaseDialog$btn_bottom_menu$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final TextView invoke() {
                View findViewById = BaseDialog.this.getContentView().findViewById(R.id.btn_bottom_menu);
                Objects.requireNonNull(findViewById, "null cannot be cast to non-null type android.widget.TextView");
                return (TextView) findViewById;
            }
        });
    }
}
