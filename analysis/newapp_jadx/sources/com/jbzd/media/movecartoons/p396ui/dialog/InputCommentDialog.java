package com.jbzd.media.movecartoons.p396ui.dialog;

import android.app.Dialog;
import android.content.DialogInterface;
import android.os.Bundle;
import android.os.Handler;
import android.os.ResultReceiver;
import android.text.TextUtils;
import android.view.KeyEvent;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.inputmethod.InputMethodManager;
import android.widget.TextView;
import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.widget.AppCompatEditText;
import androidx.fragment.app.DialogFragment;
import com.jbzd.media.movecartoons.p396ui.dialog.InputCommentDialog;
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
import p005b.p006a.p007a.p008a.p009a.ActionModeCallbackC0872t;
import p005b.p006a.p007a.p008a.p009a.ViewOnLongClickListenerC0870r;
import p005b.p006a.p007a.p008a.p009a.ViewOnTouchListenerC0871s;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p327w.p330b.C2827a;
import p005b.p327w.p330b.p337d.C2861e;
import p426f.p427a.p428a.C4325a;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u00006\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\u0010\u000e\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\u0007\u0018\u00002\u00020\u0001B4\u0012!\u0010\u0014\u001a\u001d\u0012\u0013\u0012\u00110\u000f¢\u0006\f\b\u0010\u0012\b\b\u0011\u0012\u0004\b\b(\u0012\u0012\u0004\u0012\u00020\u00130\u000e\u0012\b\b\u0002\u0010\u0016\u001a\u00020\u000f¢\u0006\u0004\b\u0018\u0010\u0019J\u000f\u0010\u0003\u001a\u00020\u0002H\u0002¢\u0006\u0004\b\u0003\u0010\u0004J\u0019\u0010\b\u001a\u00020\u00072\b\u0010\u0006\u001a\u0004\u0018\u00010\u0005H\u0016¢\u0006\u0004\b\b\u0010\tR\u001d\u0010\r\u001a\u00020\u00028B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\n\u0010\u000b\u001a\u0004\b\f\u0010\u0004R1\u0010\u0014\u001a\u001d\u0012\u0013\u0012\u00110\u000f¢\u0006\f\b\u0010\u0012\b\b\u0011\u0012\u0004\b\b(\u0012\u0012\u0004\u0012\u00020\u00130\u000e8\u0002@\u0002X\u0082\u0004¢\u0006\u0006\n\u0004\b\u0014\u0010\u0015R\u0016\u0010\u0016\u001a\u00020\u000f8\u0002@\u0002X\u0082\u0004¢\u0006\u0006\n\u0004\b\u0016\u0010\u0017¨\u0006\u001a"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/dialog/InputCommentDialog;", "Landroidx/fragment/app/DialogFragment;", "Landroidx/appcompat/app/AlertDialog;", "createDialog", "()Landroidx/appcompat/app/AlertDialog;", "Landroid/os/Bundle;", "savedInstanceState", "Landroid/app/Dialog;", "onCreateDialog", "(Landroid/os/Bundle;)Landroid/app/Dialog;", "alertDialog$delegate", "Lkotlin/Lazy;", "getAlertDialog", "alertDialog", "Lkotlin/Function1;", "", "Lkotlin/ParameterName;", "name", "inputText", "", "submitBlock", "Lkotlin/jvm/functions/Function1;", "hintText", "Ljava/lang/String;", "<init>", "(Lkotlin/jvm/functions/Function1;Ljava/lang/String;)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class InputCommentDialog extends DialogFragment {

    /* renamed from: alertDialog$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy alertDialog;

    @NotNull
    private final String hintText;

    @NotNull
    private final Function1<String, Unit> submitBlock;

    public /* synthetic */ InputCommentDialog(Function1 function1, String str, int i2, DefaultConstructorMarker defaultConstructorMarker) {
        this(function1, (i2 & 2) != 0 ? "留下您的评论" : str);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final AlertDialog createDialog() {
        View inflate = LayoutInflater.from(getContext()).inflate(R.layout.dialog_input_comment, (ViewGroup) null);
        View findViewById = inflate.findViewById(R.id.ed_input);
        Objects.requireNonNull(findViewById, "null cannot be cast to non-null type androidx.appcompat.widget.AppCompatEditText");
        final AppCompatEditText appCompatEditText = (AppCompatEditText) findViewById;
        View findViewById2 = inflate.findViewById(R.id.itv_confirm_post);
        Objects.requireNonNull(findViewById2, "null cannot be cast to non-null type android.view.View");
        appCompatEditText.setHint(this.hintText);
        appCompatEditText.setOnEditorActionListener(new TextView.OnEditorActionListener() { // from class: b.a.a.a.t.e.j
            @Override // android.widget.TextView.OnEditorActionListener
            public final boolean onEditorAction(TextView textView, int i2, KeyEvent keyEvent) {
                boolean m5774createDialog$lambda0;
                m5774createDialog$lambda0 = InputCommentDialog.m5774createDialog$lambda0(AppCompatEditText.this, this, textView, i2, keyEvent);
                return m5774createDialog$lambda0;
            }
        });
        C2354n.m2374A(findViewById2, 0L, new Function1<View, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.InputCommentDialog$createDialog$2
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
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
                Function1 function1;
                Intrinsics.checkNotNullParameter(it, "it");
                if (TextUtils.isEmpty(String.valueOf(AppCompatEditText.this.getText()))) {
                    C4325a.m4904g(this.requireContext(), "输入不能为空").show();
                    return;
                }
                C2861e.m3306d(AppCompatEditText.this);
                function1 = this.submitBlock;
                function1.invoke(String.valueOf(AppCompatEditText.this.getText()));
                AppCompatEditText.this.setText("");
                this.dismiss();
            }
        }, 1);
        appCompatEditText.setHint(this.hintText);
        appCompatEditText.setText("");
        InputMethodManager inputMethodManager = (InputMethodManager) C2827a.f7670a.getSystemService("input_method");
        if (inputMethodManager != null) {
            appCompatEditText.setFocusable(true);
            appCompatEditText.setFocusableInTouchMode(true);
            appCompatEditText.requestFocus();
            final Handler handler = new Handler();
            inputMethodManager.showSoftInput(appCompatEditText, 0, new ResultReceiver(handler) { // from class: com.qunidayede.supportlibrary.utils.KeyboardUtils$1
                @Override // android.os.ResultReceiver
                public void onReceiveResult(int i2, Bundle bundle) {
                    InputMethodManager inputMethodManager2;
                    if ((i2 == 1 || i2 == 3) && (inputMethodManager2 = (InputMethodManager) C2827a.f7670a.getSystemService("input_method")) != null) {
                        inputMethodManager2.toggleSoftInput(0, 0);
                    }
                }
            });
            inputMethodManager.toggleSoftInput(2, 1);
        }
        try {
            appCompatEditText.setOnLongClickListener(new ViewOnLongClickListenerC0870r());
            appCompatEditText.setLongClickable(false);
            appCompatEditText.setOnTouchListener(new ViewOnTouchListenerC0871s(appCompatEditText));
            appCompatEditText.setCustomSelectionActionModeCallback(new ActionModeCallbackC0872t());
        } catch (Exception e2) {
            e2.printStackTrace();
        }
        AlertDialog create = new AlertDialog.Builder(requireContext(), 2131951873).setOnDismissListener(new DialogInterface.OnDismissListener() { // from class: b.a.a.a.t.e.k
            @Override // android.content.DialogInterface.OnDismissListener
            public final void onDismiss(DialogInterface dialogInterface) {
                InputCommentDialog.m5775createDialog$lambda1(AppCompatEditText.this, dialogInterface);
            }
        }).setView(inflate).create();
        Intrinsics.checkNotNullExpressionValue(create, "Builder(requireContext(), R.style.Dialog_FullScreen_BottomIn)\n            .setOnDismissListener {\n                KeyboardUtils.hideSoftInput(ed_input)\n            }\n            .setView(contentView)\n            .create()");
        return create;
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: createDialog$lambda-0, reason: not valid java name */
    public static final boolean m5774createDialog$lambda0(AppCompatEditText ed_input, InputCommentDialog this$0, TextView textView, int i2, KeyEvent keyEvent) {
        Intrinsics.checkNotNullParameter(ed_input, "$ed_input");
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        if (i2 != 4 && i2 != 6 && (keyEvent == null || 66 != keyEvent.getKeyCode() || keyEvent.getAction() != 0)) {
            return true;
        }
        if (TextUtils.isEmpty(String.valueOf(ed_input.getText()))) {
            C4325a.m4904g(this$0.requireContext(), "输入不能为空").show();
            return true;
        }
        C2861e.m3306d(ed_input);
        this$0.submitBlock.invoke(String.valueOf(ed_input.getText()));
        ed_input.setText("");
        this$0.dismiss();
        return true;
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: createDialog$lambda-1, reason: not valid java name */
    public static final void m5775createDialog$lambda1(AppCompatEditText ed_input, DialogInterface dialogInterface) {
        Intrinsics.checkNotNullParameter(ed_input, "$ed_input");
        C2861e.m3306d(ed_input);
    }

    private final AlertDialog getAlertDialog() {
        return (AlertDialog) this.alertDialog.getValue();
    }

    public void _$_clearFindViewByIdCache() {
    }

    @Override // androidx.fragment.app.DialogFragment
    @NotNull
    public Dialog onCreateDialog(@Nullable Bundle savedInstanceState) {
        return getAlertDialog();
    }

    /* JADX WARN: Multi-variable type inference failed */
    public InputCommentDialog(@NotNull Function1<? super String, Unit> submitBlock, @NotNull String hintText) {
        Intrinsics.checkNotNullParameter(submitBlock, "submitBlock");
        Intrinsics.checkNotNullParameter(hintText, "hintText");
        this.submitBlock = submitBlock;
        this.hintText = hintText;
        this.alertDialog = LazyKt__LazyJVMKt.lazy(new Function0<AlertDialog>() { // from class: com.jbzd.media.movecartoons.ui.dialog.InputCommentDialog$alertDialog$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final AlertDialog invoke() {
                AlertDialog createDialog;
                createDialog = InputCommentDialog.this.createDialog();
                return createDialog;
            }
        });
    }
}
