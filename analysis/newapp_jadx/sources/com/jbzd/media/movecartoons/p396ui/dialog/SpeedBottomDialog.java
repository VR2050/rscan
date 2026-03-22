package com.jbzd.media.movecartoons.p396ui.dialog;

import android.app.Dialog;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.view.WindowManager;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.core.content.ContextCompat;
import com.google.android.material.bottomsheet.BottomSheetDialogFragment;
import com.qnmd.adnnm.da0yzo.R;
import java.util.List;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.collections.CollectionsKt__CollectionsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000N\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\t\n\u0002\u0010\u000e\n\u0002\b\r\n\u0002\u0018\u0002\n\u0002\b\u0011\n\u0002\u0018\u0002\n\u0002\b\u0014\u0018\u00002\u00020\u0001Bg\u0012\u0006\u0010\u001e\u001a\u00020\u001d\u0012\u0006\u0010)\u001a\u00020\u001d\u0012\u000e\b\u0002\u00102\u001a\b\u0012\u0004\u0012\u00020\u00040\u000e\u0012\u000e\b\u0002\u0010M\u001a\b\u0012\u0004\u0012\u00020\u00040\u000e\u0012\u000e\b\u0002\u0010%\u001a\b\u0012\u0004\u0012\u00020\u00040\u000e\u0012\u000e\b\u0002\u0010\u000f\u001a\b\u0012\u0004\u0012\u00020\u00040\u000e\u0012\u000e\b\u0002\u0010'\u001a\b\u0012\u0004\u0012\u00020\u00040\u000e¢\u0006\u0004\bO\u0010PJ\u0017\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u0003\u001a\u00020\u0002H\u0002¢\u0006\u0004\b\u0005\u0010\u0006J\u0019\u0010\t\u001a\u00020\u00042\b\u0010\b\u001a\u0004\u0018\u00010\u0007H\u0016¢\u0006\u0004\b\t\u0010\nJ\u0019\u0010\f\u001a\u00020\u000b2\b\u0010\b\u001a\u0004\u0018\u00010\u0007H\u0016¢\u0006\u0004\b\f\u0010\rR\u001f\u0010\u000f\u001a\b\u0012\u0004\u0012\u00020\u00040\u000e8\u0006@\u0006¢\u0006\f\n\u0004\b\u000f\u0010\u0010\u001a\u0004\b\u0011\u0010\u0012R\"\u0010\u0014\u001a\u00020\u00138\u0006@\u0006X\u0086.¢\u0006\u0012\n\u0004\b\u0014\u0010\u0015\u001a\u0004\b\u0016\u0010\u0017\"\u0004\b\u0018\u0010\u0019R\"\u0010\u001a\u001a\u00020\u00138\u0006@\u0006X\u0086.¢\u0006\u0012\n\u0004\b\u001a\u0010\u0015\u001a\u0004\b\u001b\u0010\u0017\"\u0004\b\u001c\u0010\u0019R\u0019\u0010\u001e\u001a\u00020\u001d8\u0006@\u0006¢\u0006\f\n\u0004\b\u001e\u0010\u001f\u001a\u0004\b \u0010!R\"\u0010\"\u001a\u00020\u00138\u0006@\u0006X\u0086.¢\u0006\u0012\n\u0004\b\"\u0010\u0015\u001a\u0004\b#\u0010\u0017\"\u0004\b$\u0010\u0019R\u001f\u0010%\u001a\b\u0012\u0004\u0012\u00020\u00040\u000e8\u0006@\u0006¢\u0006\f\n\u0004\b%\u0010\u0010\u001a\u0004\b&\u0010\u0012R\u001f\u0010'\u001a\b\u0012\u0004\u0012\u00020\u00040\u000e8\u0006@\u0006¢\u0006\f\n\u0004\b'\u0010\u0010\u001a\u0004\b(\u0010\u0012R\u0019\u0010)\u001a\u00020\u001d8\u0006@\u0006¢\u0006\f\n\u0004\b)\u0010\u001f\u001a\u0004\b*\u0010!R\"\u0010,\u001a\u00020+8\u0006@\u0006X\u0086.¢\u0006\u0012\n\u0004\b,\u0010-\u001a\u0004\b.\u0010/\"\u0004\b0\u00101R\u001f\u00102\u001a\b\u0012\u0004\u0012\u00020\u00040\u000e8\u0006@\u0006¢\u0006\f\n\u0004\b2\u0010\u0010\u001a\u0004\b3\u0010\u0012R\"\u00104\u001a\u00020+8\u0006@\u0006X\u0086.¢\u0006\u0012\n\u0004\b4\u0010-\u001a\u0004\b5\u0010/\"\u0004\b6\u00101R\"\u00107\u001a\u00020\u00138\u0006@\u0006X\u0086.¢\u0006\u0012\n\u0004\b7\u0010\u0015\u001a\u0004\b8\u0010\u0017\"\u0004\b9\u0010\u0019R\"\u0010:\u001a\u00020+8\u0006@\u0006X\u0086.¢\u0006\u0012\n\u0004\b:\u0010-\u001a\u0004\b;\u0010/\"\u0004\b<\u00101R\"\u0010>\u001a\u00020=8\u0006@\u0006X\u0086.¢\u0006\u0012\n\u0004\b>\u0010?\u001a\u0004\b@\u0010A\"\u0004\bB\u0010CR\"\u0010D\u001a\u00020+8\u0006@\u0006X\u0086.¢\u0006\u0012\n\u0004\bD\u0010-\u001a\u0004\bE\u0010/\"\u0004\bF\u00101R\"\u0010G\u001a\u00020\u00138\u0006@\u0006X\u0086.¢\u0006\u0012\n\u0004\bG\u0010\u0015\u001a\u0004\bH\u0010\u0017\"\u0004\bI\u0010\u0019R\"\u0010J\u001a\u00020+8\u0006@\u0006X\u0086.¢\u0006\u0012\n\u0004\bJ\u0010-\u001a\u0004\bK\u0010/\"\u0004\bL\u00101R\u001f\u0010M\u001a\b\u0012\u0004\u0012\u00020\u00040\u000e8\u0006@\u0006¢\u0006\f\n\u0004\bM\u0010\u0010\u001a\u0004\bN\u0010\u0012¨\u0006Q"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/dialog/SpeedBottomDialog;", "Lcom/google/android/material/bottomsheet/BottomSheetDialogFragment;", "Landroid/view/View;", "contentView", "", "initContentView", "(Landroid/view/View;)V", "Landroid/os/Bundle;", "savedInstanceState", "onCreate", "(Landroid/os/Bundle;)V", "Landroid/app/Dialog;", "onCreateDialog", "(Landroid/os/Bundle;)Landroid/app/Dialog;", "Lkotlin/Function0;", "btn4Block", "Lkotlin/jvm/functions/Function0;", "getBtn4Block", "()Lkotlin/jvm/functions/Function0;", "Landroid/widget/TextView;", "describe1", "Landroid/widget/TextView;", "getDescribe1", "()Landroid/widget/TextView;", "setDescribe1", "(Landroid/widget/TextView;)V", "describe4", "getDescribe4", "setDescribe4", "", "themeMode", "Ljava/lang/String;", "getThemeMode", "()Ljava/lang/String;", "describe3", "getDescribe3", "setDescribe3", "btn3Block", "getBtn3Block", "btn5Block", "getBtn5Block", "mode", "getMode", "Landroid/widget/LinearLayout;", "btn1", "Landroid/widget/LinearLayout;", "getBtn1", "()Landroid/widget/LinearLayout;", "setBtn1", "(Landroid/widget/LinearLayout;)V", "btn1Block", "getBtn1Block", "btn4", "getBtn4", "setBtn4", "describe5", "getDescribe5", "setDescribe5", "btn2", "getBtn2", "setBtn2", "Landroid/widget/ImageView;", "close", "Landroid/widget/ImageView;", "getClose", "()Landroid/widget/ImageView;", "setClose", "(Landroid/widget/ImageView;)V", "btn5", "getBtn5", "setBtn5", "describe2", "getDescribe2", "setDescribe2", "btn3", "getBtn3", "setBtn3", "btn2Block", "getBtn2Block", "<init>", "(Ljava/lang/String;Ljava/lang/String;Lkotlin/jvm/functions/Function0;Lkotlin/jvm/functions/Function0;Lkotlin/jvm/functions/Function0;Lkotlin/jvm/functions/Function0;Lkotlin/jvm/functions/Function0;)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class SpeedBottomDialog extends BottomSheetDialogFragment {
    public LinearLayout btn1;

    @NotNull
    private final Function0<Unit> btn1Block;
    public LinearLayout btn2;

    @NotNull
    private final Function0<Unit> btn2Block;
    public LinearLayout btn3;

    @NotNull
    private final Function0<Unit> btn3Block;
    public LinearLayout btn4;

    @NotNull
    private final Function0<Unit> btn4Block;
    public LinearLayout btn5;

    @NotNull
    private final Function0<Unit> btn5Block;
    public ImageView close;
    public TextView describe1;
    public TextView describe2;
    public TextView describe3;
    public TextView describe4;
    public TextView describe5;

    @NotNull
    private final String mode;

    @NotNull
    private final String themeMode;

    public /* synthetic */ SpeedBottomDialog(String str, String str2, Function0 function0, Function0 function02, Function0 function03, Function0 function04, Function0 function05, int i2, DefaultConstructorMarker defaultConstructorMarker) {
        this(str, str2, (i2 & 4) != 0 ? new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.SpeedBottomDialog.1
            @Override // kotlin.jvm.functions.Function0
            public /* bridge */ /* synthetic */ Unit invoke() {
                invoke2();
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2() {
            }
        } : function0, (i2 & 8) != 0 ? new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.SpeedBottomDialog.2
            @Override // kotlin.jvm.functions.Function0
            public /* bridge */ /* synthetic */ Unit invoke() {
                invoke2();
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2() {
            }
        } : function02, (i2 & 16) != 0 ? new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.SpeedBottomDialog.3
            @Override // kotlin.jvm.functions.Function0
            public /* bridge */ /* synthetic */ Unit invoke() {
                invoke2();
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2() {
            }
        } : function03, (i2 & 32) != 0 ? new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.SpeedBottomDialog.4
            @Override // kotlin.jvm.functions.Function0
            public /* bridge */ /* synthetic */ Unit invoke() {
                invoke2();
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2() {
            }
        } : function04, (i2 & 64) != 0 ? new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.SpeedBottomDialog.5
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

    private final void initContentView(View contentView) {
        View findViewById = contentView.findViewById(R.id.speed_btn1);
        Intrinsics.checkNotNullExpressionValue(findViewById, "contentView.findViewById(R.id.speed_btn1)");
        setBtn1((LinearLayout) findViewById);
        View findViewById2 = contentView.findViewById(R.id.speed_btn2);
        Intrinsics.checkNotNullExpressionValue(findViewById2, "contentView.findViewById(R.id.speed_btn2)");
        setBtn2((LinearLayout) findViewById2);
        View findViewById3 = contentView.findViewById(R.id.speed_btn3);
        Intrinsics.checkNotNullExpressionValue(findViewById3, "contentView.findViewById(R.id.speed_btn3)");
        setBtn3((LinearLayout) findViewById3);
        View findViewById4 = contentView.findViewById(R.id.speed_btn4);
        Intrinsics.checkNotNullExpressionValue(findViewById4, "contentView.findViewById(R.id.speed_btn4)");
        setBtn4((LinearLayout) findViewById4);
        View findViewById5 = contentView.findViewById(R.id.speed_btn5);
        Intrinsics.checkNotNullExpressionValue(findViewById5, "contentView.findViewById(R.id.speed_btn5)");
        setBtn5((LinearLayout) findViewById5);
        View findViewById6 = contentView.findViewById(R.id.speed_describe1);
        Intrinsics.checkNotNullExpressionValue(findViewById6, "contentView.findViewById(R.id.speed_describe1)");
        setDescribe1((TextView) findViewById6);
        View findViewById7 = contentView.findViewById(R.id.speed_describe2);
        Intrinsics.checkNotNullExpressionValue(findViewById7, "contentView.findViewById(R.id.speed_describe2)");
        setDescribe2((TextView) findViewById7);
        View findViewById8 = contentView.findViewById(R.id.speed_describe3);
        Intrinsics.checkNotNullExpressionValue(findViewById8, "contentView.findViewById(R.id.speed_describe3)");
        setDescribe3((TextView) findViewById8);
        View findViewById9 = contentView.findViewById(R.id.speed_describe4);
        Intrinsics.checkNotNullExpressionValue(findViewById9, "contentView.findViewById(R.id.speed_describe4)");
        setDescribe4((TextView) findViewById9);
        View findViewById10 = contentView.findViewById(R.id.speed_describe5);
        Intrinsics.checkNotNullExpressionValue(findViewById10, "contentView.findViewById(R.id.speed_describe5)");
        setDescribe5((TextView) findViewById10);
        View findViewById11 = contentView.findViewById(R.id.close);
        Intrinsics.checkNotNullExpressionValue(findViewById11, "contentView.findViewById(R.id.close)");
        setClose((ImageView) findViewById11);
        int i2 = 0;
        List listOf = CollectionsKt__CollectionsKt.listOf((Object[]) new TextView[]{getDescribe1(), getDescribe2(), getDescribe3(), getDescribe4(), getDescribe5()});
        int size = listOf.size() - 1;
        if (size >= 0) {
            int i3 = 0;
            while (true) {
                int i4 = i3 + 1;
                TextView textView = (TextView) listOf.get(i3);
                if (Intrinsics.areEqual(String.valueOf(i3), this.mode)) {
                    textView.setTextColor(ContextCompat.getColor(requireContext(), R.color.color_gold_main));
                }
                if (i4 > size) {
                    break;
                } else {
                    i3 = i4;
                }
            }
        }
        List listOf2 = CollectionsKt__CollectionsKt.listOf((Object[]) new TextView[]{getDescribe1(), getDescribe2(), getDescribe3(), getDescribe4(), getDescribe5()});
        int size2 = listOf2.size() - 1;
        if (size2 >= 0) {
            while (true) {
                int i5 = i2 + 1;
                TextView textView2 = (TextView) listOf2.get(i2);
                if (Intrinsics.areEqual(String.valueOf(i2), this.mode)) {
                    textView2.setTextColor(ContextCompat.getColor(requireContext(), R.color.color_gold_main));
                }
                if (i5 > size2) {
                    break;
                } else {
                    i2 = i5;
                }
            }
        }
        C2354n.m2374A(getBtn1(), 0L, new Function1<LinearLayout, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.SpeedBottomDialog$initContentView$1
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(LinearLayout linearLayout) {
                invoke2(linearLayout);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull LinearLayout it) {
                Intrinsics.checkNotNullParameter(it, "it");
                SpeedBottomDialog.this.dismissAllowingStateLoss();
                SpeedBottomDialog.this.getBtn1Block().invoke();
            }
        }, 1);
        C2354n.m2374A(getBtn2(), 0L, new Function1<LinearLayout, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.SpeedBottomDialog$initContentView$2
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(LinearLayout linearLayout) {
                invoke2(linearLayout);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull LinearLayout it) {
                Intrinsics.checkNotNullParameter(it, "it");
                SpeedBottomDialog.this.dismissAllowingStateLoss();
                SpeedBottomDialog.this.getBtn2Block().invoke();
            }
        }, 1);
        C2354n.m2374A(getBtn3(), 0L, new Function1<LinearLayout, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.SpeedBottomDialog$initContentView$3
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(LinearLayout linearLayout) {
                invoke2(linearLayout);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull LinearLayout it) {
                Intrinsics.checkNotNullParameter(it, "it");
                SpeedBottomDialog.this.dismissAllowingStateLoss();
                SpeedBottomDialog.this.getBtn3Block().invoke();
            }
        }, 1);
        C2354n.m2374A(getBtn4(), 0L, new Function1<LinearLayout, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.SpeedBottomDialog$initContentView$4
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(LinearLayout linearLayout) {
                invoke2(linearLayout);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull LinearLayout it) {
                Intrinsics.checkNotNullParameter(it, "it");
                SpeedBottomDialog.this.dismissAllowingStateLoss();
                SpeedBottomDialog.this.getBtn4Block().invoke();
            }
        }, 1);
        C2354n.m2374A(getBtn5(), 0L, new Function1<LinearLayout, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.SpeedBottomDialog$initContentView$5
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(LinearLayout linearLayout) {
                invoke2(linearLayout);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull LinearLayout it) {
                Intrinsics.checkNotNullParameter(it, "it");
                SpeedBottomDialog.this.dismissAllowingStateLoss();
                SpeedBottomDialog.this.getBtn5Block().invoke();
            }
        }, 1);
        C2354n.m2374A(getClose(), 0L, new Function1<ImageView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.SpeedBottomDialog$initContentView$6
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
                SpeedBottomDialog.this.dismissAllowingStateLoss();
            }
        }, 1);
    }

    public void _$_clearFindViewByIdCache() {
    }

    @NotNull
    public final LinearLayout getBtn1() {
        LinearLayout linearLayout = this.btn1;
        if (linearLayout != null) {
            return linearLayout;
        }
        Intrinsics.throwUninitializedPropertyAccessException("btn1");
        throw null;
    }

    @NotNull
    public final Function0<Unit> getBtn1Block() {
        return this.btn1Block;
    }

    @NotNull
    public final LinearLayout getBtn2() {
        LinearLayout linearLayout = this.btn2;
        if (linearLayout != null) {
            return linearLayout;
        }
        Intrinsics.throwUninitializedPropertyAccessException("btn2");
        throw null;
    }

    @NotNull
    public final Function0<Unit> getBtn2Block() {
        return this.btn2Block;
    }

    @NotNull
    public final LinearLayout getBtn3() {
        LinearLayout linearLayout = this.btn3;
        if (linearLayout != null) {
            return linearLayout;
        }
        Intrinsics.throwUninitializedPropertyAccessException("btn3");
        throw null;
    }

    @NotNull
    public final Function0<Unit> getBtn3Block() {
        return this.btn3Block;
    }

    @NotNull
    public final LinearLayout getBtn4() {
        LinearLayout linearLayout = this.btn4;
        if (linearLayout != null) {
            return linearLayout;
        }
        Intrinsics.throwUninitializedPropertyAccessException("btn4");
        throw null;
    }

    @NotNull
    public final Function0<Unit> getBtn4Block() {
        return this.btn4Block;
    }

    @NotNull
    public final LinearLayout getBtn5() {
        LinearLayout linearLayout = this.btn5;
        if (linearLayout != null) {
            return linearLayout;
        }
        Intrinsics.throwUninitializedPropertyAccessException("btn5");
        throw null;
    }

    @NotNull
    public final Function0<Unit> getBtn5Block() {
        return this.btn5Block;
    }

    @NotNull
    public final ImageView getClose() {
        ImageView imageView = this.close;
        if (imageView != null) {
            return imageView;
        }
        Intrinsics.throwUninitializedPropertyAccessException("close");
        throw null;
    }

    @NotNull
    public final TextView getDescribe1() {
        TextView textView = this.describe1;
        if (textView != null) {
            return textView;
        }
        Intrinsics.throwUninitializedPropertyAccessException("describe1");
        throw null;
    }

    @NotNull
    public final TextView getDescribe2() {
        TextView textView = this.describe2;
        if (textView != null) {
            return textView;
        }
        Intrinsics.throwUninitializedPropertyAccessException("describe2");
        throw null;
    }

    @NotNull
    public final TextView getDescribe3() {
        TextView textView = this.describe3;
        if (textView != null) {
            return textView;
        }
        Intrinsics.throwUninitializedPropertyAccessException("describe3");
        throw null;
    }

    @NotNull
    public final TextView getDescribe4() {
        TextView textView = this.describe4;
        if (textView != null) {
            return textView;
        }
        Intrinsics.throwUninitializedPropertyAccessException("describe4");
        throw null;
    }

    @NotNull
    public final TextView getDescribe5() {
        TextView textView = this.describe5;
        if (textView != null) {
            return textView;
        }
        Intrinsics.throwUninitializedPropertyAccessException("describe5");
        throw null;
    }

    @NotNull
    public final String getMode() {
        return this.mode;
    }

    @NotNull
    public final String getThemeMode() {
        return this.themeMode;
    }

    @Override // androidx.fragment.app.DialogFragment, androidx.fragment.app.Fragment
    public void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setStyle(0, R.style.dialog_center);
    }

    @Override // com.google.android.material.bottomsheet.BottomSheetDialogFragment, androidx.appcompat.app.AppCompatDialogFragment, androidx.fragment.app.DialogFragment
    @NotNull
    public Dialog onCreateDialog(@Nullable Bundle savedInstanceState) {
        Dialog onCreateDialog = super.onCreateDialog(savedInstanceState);
        Intrinsics.checkNotNullExpressionValue(onCreateDialog, "super.onCreateDialog(savedInstanceState)");
        View contentView = LayoutInflater.from(getContext()).inflate(R.layout.dialog_speed_bottom_light, (ViewGroup) null);
        onCreateDialog.setContentView(contentView);
        Intrinsics.checkNotNullExpressionValue(contentView, "contentView");
        initContentView(contentView);
        Window window = onCreateDialog.getWindow();
        if (window != null) {
            window.setDimAmount(0.5f);
        }
        WindowManager.LayoutParams attributes = window != null ? window.getAttributes() : null;
        if (attributes != null) {
            attributes.windowAnimations = 2131951873;
        }
        return onCreateDialog;
    }

    public final void setBtn1(@NotNull LinearLayout linearLayout) {
        Intrinsics.checkNotNullParameter(linearLayout, "<set-?>");
        this.btn1 = linearLayout;
    }

    public final void setBtn2(@NotNull LinearLayout linearLayout) {
        Intrinsics.checkNotNullParameter(linearLayout, "<set-?>");
        this.btn2 = linearLayout;
    }

    public final void setBtn3(@NotNull LinearLayout linearLayout) {
        Intrinsics.checkNotNullParameter(linearLayout, "<set-?>");
        this.btn3 = linearLayout;
    }

    public final void setBtn4(@NotNull LinearLayout linearLayout) {
        Intrinsics.checkNotNullParameter(linearLayout, "<set-?>");
        this.btn4 = linearLayout;
    }

    public final void setBtn5(@NotNull LinearLayout linearLayout) {
        Intrinsics.checkNotNullParameter(linearLayout, "<set-?>");
        this.btn5 = linearLayout;
    }

    public final void setClose(@NotNull ImageView imageView) {
        Intrinsics.checkNotNullParameter(imageView, "<set-?>");
        this.close = imageView;
    }

    public final void setDescribe1(@NotNull TextView textView) {
        Intrinsics.checkNotNullParameter(textView, "<set-?>");
        this.describe1 = textView;
    }

    public final void setDescribe2(@NotNull TextView textView) {
        Intrinsics.checkNotNullParameter(textView, "<set-?>");
        this.describe2 = textView;
    }

    public final void setDescribe3(@NotNull TextView textView) {
        Intrinsics.checkNotNullParameter(textView, "<set-?>");
        this.describe3 = textView;
    }

    public final void setDescribe4(@NotNull TextView textView) {
        Intrinsics.checkNotNullParameter(textView, "<set-?>");
        this.describe4 = textView;
    }

    public final void setDescribe5(@NotNull TextView textView) {
        Intrinsics.checkNotNullParameter(textView, "<set-?>");
        this.describe5 = textView;
    }

    public SpeedBottomDialog(@NotNull String themeMode, @NotNull String mode, @NotNull Function0<Unit> btn1Block, @NotNull Function0<Unit> btn2Block, @NotNull Function0<Unit> btn3Block, @NotNull Function0<Unit> btn4Block, @NotNull Function0<Unit> btn5Block) {
        Intrinsics.checkNotNullParameter(themeMode, "themeMode");
        Intrinsics.checkNotNullParameter(mode, "mode");
        Intrinsics.checkNotNullParameter(btn1Block, "btn1Block");
        Intrinsics.checkNotNullParameter(btn2Block, "btn2Block");
        Intrinsics.checkNotNullParameter(btn3Block, "btn3Block");
        Intrinsics.checkNotNullParameter(btn4Block, "btn4Block");
        Intrinsics.checkNotNullParameter(btn5Block, "btn5Block");
        this.themeMode = themeMode;
        this.mode = mode;
        this.btn1Block = btn1Block;
        this.btn2Block = btn2Block;
        this.btn3Block = btn3Block;
        this.btn4Block = btn4Block;
        this.btn5Block = btn5Block;
    }
}
