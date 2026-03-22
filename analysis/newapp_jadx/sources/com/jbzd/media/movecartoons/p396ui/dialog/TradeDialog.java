package com.jbzd.media.movecartoons.p396ui.dialog;

import android.app.Dialog;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.view.WindowManager;
import android.widget.ImageView;
import android.widget.RadioButton;
import android.widget.RadioGroup;
import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.widget.AppCompatEditText;
import androidx.fragment.app.DialogFragment;
import com.jbzd.media.movecartoons.p396ui.dialog.TradeDialog;
import com.jbzd.media.movecartoons.view.GradientRoundCornerButton;
import com.qnmd.adnnm.da0yzo.R;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt__StringsKt;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p426f.p427a.p428a.C4325a;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000J\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\n\n\u0002\u0010\b\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\u0010\u000e\n\u0002\b\n\u0018\u0000 *2\u00020\u0001:\u0001*B5\u0012\u0018\u0010\"\u001a\u0014\u0012\u0004\u0012\u00020\u001c\u0012\u0004\u0012\u00020!\u0012\u0004\u0012\u00020\u00050 \u0012\b\b\u0002\u0010&\u001a\u00020\u001c\u0012\b\b\u0002\u0010'\u001a\u00020\u001c¢\u0006\u0004\b(\u0010)J\u000f\u0010\u0003\u001a\u00020\u0002H\u0002¢\u0006\u0004\b\u0003\u0010\u0004J\u000f\u0010\u0006\u001a\u00020\u0005H\u0002¢\u0006\u0004\b\u0006\u0010\u0007J\u000f\u0010\b\u001a\u00020\u0005H\u0016¢\u0006\u0004\b\b\u0010\u0007J\u0019\u0010\f\u001a\u00020\u000b2\b\u0010\n\u001a\u0004\u0018\u00010\tH\u0016¢\u0006\u0004\b\f\u0010\rR\u0016\u0010\u000f\u001a\u00020\u000e8\u0002@\u0002X\u0082.¢\u0006\u0006\n\u0004\b\u000f\u0010\u0010R%\u0010\u0017\u001a\n \u0012*\u0004\u0018\u00010\u00110\u00118B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u0013\u0010\u0014\u001a\u0004\b\u0015\u0010\u0016R\u0016\u0010\u0018\u001a\u00020\u000e8\u0002@\u0002X\u0082.¢\u0006\u0006\n\u0004\b\u0018\u0010\u0010R\u001d\u0010\u001b\u001a\u00020\u00028B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u0019\u0010\u0014\u001a\u0004\b\u001a\u0010\u0004R\u0016\u0010\u001d\u001a\u00020\u001c8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\u001d\u0010\u001eR\u0016\u0010\u001f\u001a\u00020\u001c8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\u001f\u0010\u001eR+\u0010\"\u001a\u0014\u0012\u0004\u0012\u00020\u001c\u0012\u0004\u0012\u00020!\u0012\u0004\u0012\u00020\u00050 8\u0006@\u0006¢\u0006\f\n\u0004\b\"\u0010#\u001a\u0004\b$\u0010%¨\u0006+"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/dialog/TradeDialog;", "Landroidx/fragment/app/DialogFragment;", "Landroidx/appcompat/app/AlertDialog;", "createDialog", "()Landroidx/appcompat/app/AlertDialog;", "", "updateUi", "()V", "onResume", "Landroid/os/Bundle;", "savedInstanceState", "Landroid/app/Dialog;", "onCreateDialog", "(Landroid/os/Bundle;)Landroid/app/Dialog;", "Landroid/widget/RadioButton;", "rbDone", "Landroid/widget/RadioButton;", "Landroid/view/View;", "kotlin.jvm.PlatformType", "contentView$delegate", "Lkotlin/Lazy;", "getContentView", "()Landroid/view/View;", "contentView", "rbCancel", "alertDialog$delegate", "getAlertDialog", "alertDialog", "", "mSelectedType", "I", "mOnlyShowButton", "Lkotlin/Function2;", "", "submit", "Lkotlin/jvm/functions/Function2;", "getSubmit", "()Lkotlin/jvm/functions/Function2;", "selectedType", "onlyShowButton", "<init>", "(Lkotlin/jvm/functions/Function2;II)V", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class TradeDialog extends DialogFragment {
    public static final int TYPE_SUBMIT_TRADE_CANCEL = 7;
    public static final int TYPE_SUBMIT_TRADE_DELETE = -1;

    @NotNull
    public static final String TYPE_SUBMIT_TRADE_DELETE_TEXT = "目前无法删除，请联系客服";
    public static final int TYPE_SUBMIT_TRADE_DONE = 6;
    private static final int TYPE_TRADE_NONE = 0;

    /* renamed from: alertDialog$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy alertDialog;

    /* renamed from: contentView$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy contentView;
    private int mOnlyShowButton;
    private int mSelectedType;
    private RadioButton rbCancel;
    private RadioButton rbDone;

    @NotNull
    private final Function2<Integer, String, Unit> submit;

    public /* synthetic */ TradeDialog(Function2 function2, int i2, int i3, int i4, DefaultConstructorMarker defaultConstructorMarker) {
        this(function2, (i4 & 2) != 0 ? 0 : i2, (i4 & 4) != 0 ? 0 : i3);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final AlertDialog createDialog() {
        AlertDialog m624j0 = C1499a.m624j0(new AlertDialog.Builder(requireContext(), R.style.dialog_center), getContentView(), "Builder(requireContext(), R.style.dialog_center)\n            .setView(contentView)\n            .create()");
        ImageView imageView = (ImageView) getContentView().findViewById(R.id.iv_close);
        RadioGroup radioGroup = (RadioGroup) getContentView().findViewById(R.id.rg_trade);
        View findViewById = getContentView().findViewById(R.id.rb_done);
        Intrinsics.checkNotNullExpressionValue(findViewById, "contentView.findViewById<RadioButton>(R.id.rb_done)");
        this.rbDone = (RadioButton) findViewById;
        View findViewById2 = getContentView().findViewById(R.id.rb_cancel);
        Intrinsics.checkNotNullExpressionValue(findViewById2, "contentView.findViewById<RadioButton>(R.id.rb_cancel)");
        this.rbCancel = (RadioButton) findViewById2;
        final AppCompatEditText appCompatEditText = (AppCompatEditText) getContentView().findViewById(R.id.et_memo);
        GradientRoundCornerButton gradientRoundCornerButton = (GradientRoundCornerButton) getContentView().findViewById(R.id.btn_submit_aichangeface_video);
        C2354n.m2374A(imageView, 0L, new Function1<ImageView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.TradeDialog$createDialog$1
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
                TradeDialog.this.dismissAllowingStateLoss();
            }
        }, 1);
        radioGroup.setOnCheckedChangeListener(new RadioGroup.OnCheckedChangeListener() { // from class: b.a.a.a.t.e.f0
            @Override // android.widget.RadioGroup.OnCheckedChangeListener
            public final void onCheckedChanged(RadioGroup radioGroup2, int i2) {
                TradeDialog.m5796createDialog$lambda0(TradeDialog.this, radioGroup2, i2);
            }
        });
        C2354n.m2374A(gradientRoundCornerButton, 0L, new Function1<GradientRoundCornerButton, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.TradeDialog$createDialog$3
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(GradientRoundCornerButton gradientRoundCornerButton2) {
                invoke2(gradientRoundCornerButton2);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(GradientRoundCornerButton gradientRoundCornerButton2) {
                int i2;
                int i3;
                i2 = TradeDialog.this.mSelectedType;
                if (i2 == 0) {
                    C4325a.m4905h(TradeDialog.this.requireContext(), "请先选择\"取消交易\"或\"交易完成\"\"", 1).show();
                    return;
                }
                String obj = StringsKt__StringsKt.trim((CharSequence) String.valueOf(appCompatEditText.getText())).toString();
                Function2<Integer, String, Unit> submit = TradeDialog.this.getSubmit();
                i3 = TradeDialog.this.mSelectedType;
                submit.invoke(Integer.valueOf(i3), obj);
                TradeDialog.this.dismissAllowingStateLoss();
            }
        }, 1);
        Window window = m624j0.getWindow();
        if (window != null) {
            window.setDimAmount(0.0f);
        }
        WindowManager.LayoutParams attributes = window == null ? null : window.getAttributes();
        if (attributes != null) {
            attributes.windowAnimations = R.style.BottomShowAnimation;
        }
        return m624j0;
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: createDialog$lambda-0, reason: not valid java name */
    public static final void m5796createDialog$lambda0(TradeDialog this$0, RadioGroup radioGroup, int i2) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        switch (i2) {
            case R.id.rb_cancel /* 2131363020 */:
                this$0.mSelectedType = 7;
                break;
            case R.id.rb_done /* 2131363021 */:
                this$0.mSelectedType = 6;
                break;
        }
    }

    private final AlertDialog getAlertDialog() {
        return (AlertDialog) this.alertDialog.getValue();
    }

    private final View getContentView() {
        return (View) this.contentView.getValue();
    }

    private final void updateUi() {
        int i2 = this.mOnlyShowButton;
        if (i2 == 6) {
            RadioButton radioButton = this.rbCancel;
            if (radioButton == null) {
                Intrinsics.throwUninitializedPropertyAccessException("rbCancel");
                throw null;
            }
            radioButton.setVisibility(8);
        } else if (i2 == 7) {
            RadioButton radioButton2 = this.rbDone;
            if (radioButton2 == null) {
                Intrinsics.throwUninitializedPropertyAccessException("rbDone");
                throw null;
            }
            radioButton2.setVisibility(8);
        }
        int i3 = this.mSelectedType;
        if (i3 == 6) {
            RadioButton radioButton3 = this.rbDone;
            if (radioButton3 != null) {
                radioButton3.setChecked(true);
                return;
            } else {
                Intrinsics.throwUninitializedPropertyAccessException("rbDone");
                throw null;
            }
        }
        if (i3 != 7) {
            return;
        }
        RadioButton radioButton4 = this.rbCancel;
        if (radioButton4 != null) {
            radioButton4.setChecked(true);
        } else {
            Intrinsics.throwUninitializedPropertyAccessException("rbCancel");
            throw null;
        }
    }

    public void _$_clearFindViewByIdCache() {
    }

    @NotNull
    public final Function2<Integer, String, Unit> getSubmit() {
        return this.submit;
    }

    @Override // androidx.fragment.app.DialogFragment
    @NotNull
    public Dialog onCreateDialog(@Nullable Bundle savedInstanceState) {
        return getAlertDialog();
    }

    @Override // androidx.fragment.app.Fragment
    public void onResume() {
        super.onResume();
        updateUi();
    }

    /* JADX WARN: Multi-variable type inference failed */
    public TradeDialog(@NotNull Function2<? super Integer, ? super String, Unit> submit, int i2, int i3) {
        Intrinsics.checkNotNullParameter(submit, "submit");
        this.submit = submit;
        this.mSelectedType = i2;
        this.mOnlyShowButton = i3;
        this.contentView = LazyKt__LazyJVMKt.lazy(new Function0<View>() { // from class: com.jbzd.media.movecartoons.ui.dialog.TradeDialog$contentView$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            public final View invoke() {
                return LayoutInflater.from(TradeDialog.this.getContext()).inflate(R.layout.dialog_trade, (ViewGroup) null);
            }
        });
        this.alertDialog = LazyKt__LazyJVMKt.lazy(new Function0<AlertDialog>() { // from class: com.jbzd.media.movecartoons.ui.dialog.TradeDialog$alertDialog$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final AlertDialog invoke() {
                AlertDialog createDialog;
                createDialog = TradeDialog.this.createDialog();
                return createDialog;
            }
        });
    }
}
