package com.jbzd.media.movecartoons.p396ui.dialog;

import android.app.Dialog;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.view.WindowManager;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.core.content.ContextCompat;
import com.google.android.material.bottomsheet.BottomSheetDialogFragment;
import com.jbzd.media.movecartoons.p396ui.index.home.HomeDataHelper;
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

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000F\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0010\u000e\n\u0002\b\f\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\b%\u0018\u00002\u00020\u0001Bw\u0012\u0006\u0010>\u001a\u00020\u0017\u0012\u0006\u00108\u001a\u00020\u0017\u0012\u0006\u0010\u0018\u001a\u00020\u0017\u0012\u0006\u0010\u001c\u001a\u00020\u0017\u0012\u000e\b\u0002\u0010,\u001a\b\u0012\u0004\u0012\u00020\u00040+\u0012\u000e\b\u0002\u0010L\u001a\b\u0012\u0004\u0012\u00020\u00040+\u0012\u000e\b\u0002\u00100\u001a\b\u0012\u0004\u0012\u00020\u00040+\u0012\u000e\b\u0002\u0010:\u001a\b\u0012\u0004\u0012\u00020\u00040+\u0012\u000e\b\u0002\u0010<\u001a\b\u0012\u0004\u0012\u00020\u00040+¢\u0006\u0004\bN\u0010OJ\u0017\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u0003\u001a\u00020\u0002H\u0002¢\u0006\u0004\b\u0005\u0010\u0006J\u0019\u0010\t\u001a\u00020\u00042\b\u0010\b\u001a\u0004\u0018\u00010\u0007H\u0016¢\u0006\u0004\b\t\u0010\nJ\u0019\u0010\f\u001a\u00020\u000b2\b\u0010\b\u001a\u0004\u0018\u00010\u0007H\u0016¢\u0006\u0004\b\f\u0010\rJ\u000f\u0010\u000e\u001a\u00020\u0004H\u0016¢\u0006\u0004\b\u000e\u0010\u000fR\"\u0010\u0011\u001a\u00020\u00108\u0006@\u0006X\u0086.¢\u0006\u0012\n\u0004\b\u0011\u0010\u0012\u001a\u0004\b\u0013\u0010\u0014\"\u0004\b\u0015\u0010\u0016R\u0019\u0010\u0018\u001a\u00020\u00178\u0006@\u0006¢\u0006\f\n\u0004\b\u0018\u0010\u0019\u001a\u0004\b\u001a\u0010\u001bR\u0019\u0010\u001c\u001a\u00020\u00178\u0006@\u0006¢\u0006\f\n\u0004\b\u001c\u0010\u0019\u001a\u0004\b\u001d\u0010\u001bR\"\u0010\u001e\u001a\u00020\u00108\u0006@\u0006X\u0086.¢\u0006\u0012\n\u0004\b\u001e\u0010\u0012\u001a\u0004\b\u001f\u0010\u0014\"\u0004\b \u0010\u0016R\"\u0010!\u001a\u00020\u00108\u0006@\u0006X\u0086.¢\u0006\u0012\n\u0004\b!\u0010\u0012\u001a\u0004\b\"\u0010\u0014\"\u0004\b#\u0010\u0016R\"\u0010%\u001a\u00020$8\u0006@\u0006X\u0086.¢\u0006\u0012\n\u0004\b%\u0010&\u001a\u0004\b'\u0010(\"\u0004\b)\u0010*R\u001f\u0010,\u001a\b\u0012\u0004\u0012\u00020\u00040+8\u0006@\u0006¢\u0006\f\n\u0004\b,\u0010-\u001a\u0004\b.\u0010/R\u001f\u00100\u001a\b\u0012\u0004\u0012\u00020\u00040+8\u0006@\u0006¢\u0006\f\n\u0004\b0\u0010-\u001a\u0004\b1\u0010/R\"\u00102\u001a\u00020\u00108\u0006@\u0006X\u0086.¢\u0006\u0012\n\u0004\b2\u0010\u0012\u001a\u0004\b3\u0010\u0014\"\u0004\b4\u0010\u0016R\"\u00105\u001a\u00020\u00108\u0006@\u0006X\u0086.¢\u0006\u0012\n\u0004\b5\u0010\u0012\u001a\u0004\b6\u0010\u0014\"\u0004\b7\u0010\u0016R\u0019\u00108\u001a\u00020\u00178\u0006@\u0006¢\u0006\f\n\u0004\b8\u0010\u0019\u001a\u0004\b9\u0010\u001bR\u001f\u0010:\u001a\b\u0012\u0004\u0012\u00020\u00040+8\u0006@\u0006¢\u0006\f\n\u0004\b:\u0010-\u001a\u0004\b;\u0010/R\u001f\u0010<\u001a\b\u0012\u0004\u0012\u00020\u00040+8\u0006@\u0006¢\u0006\f\n\u0004\b<\u0010-\u001a\u0004\b=\u0010/R\u0019\u0010>\u001a\u00020\u00178\u0006@\u0006¢\u0006\f\n\u0004\b>\u0010\u0019\u001a\u0004\b?\u0010\u001bR\"\u0010@\u001a\u00020\u00108\u0006@\u0006X\u0086.¢\u0006\u0012\n\u0004\b@\u0010\u0012\u001a\u0004\bA\u0010\u0014\"\u0004\bB\u0010\u0016R\"\u0010C\u001a\u00020\u00108\u0006@\u0006X\u0086.¢\u0006\u0012\n\u0004\bC\u0010\u0012\u001a\u0004\bD\u0010\u0014\"\u0004\bE\u0010\u0016R\"\u0010F\u001a\u00020\u00108\u0006@\u0006X\u0086.¢\u0006\u0012\n\u0004\bF\u0010\u0012\u001a\u0004\bG\u0010\u0014\"\u0004\bH\u0010\u0016R\"\u0010I\u001a\u00020\u00108\u0006@\u0006X\u0086.¢\u0006\u0012\n\u0004\bI\u0010\u0012\u001a\u0004\bJ\u0010\u0014\"\u0004\bK\u0010\u0016R\u001f\u0010L\u001a\b\u0012\u0004\u0012\u00020\u00040+8\u0006@\u0006¢\u0006\f\n\u0004\bL\u0010-\u001a\u0004\bM\u0010/¨\u0006P"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/dialog/TimingBottomDialog;", "Lcom/google/android/material/bottomsheet/BottomSheetDialogFragment;", "Landroid/view/View;", "contentView", "", "initContentView", "(Landroid/view/View;)V", "Landroid/os/Bundle;", "savedInstanceState", "onCreate", "(Landroid/os/Bundle;)V", "Landroid/app/Dialog;", "onCreateDialog", "(Landroid/os/Bundle;)Landroid/app/Dialog;", "onDestroy", "()V", "Landroid/widget/TextView;", "btn4_time", "Landroid/widget/TextView;", "getBtn4_time", "()Landroid/widget/TextView;", "setBtn4_time", "(Landroid/widget/TextView;)V", "", "during", "Ljava/lang/String;", "getDuring", "()Ljava/lang/String;", "countdown", "getCountdown", "timing_btn3", "getTiming_btn3", "setTiming_btn3", "btn5_time", "getBtn5_time", "setBtn5_time", "Landroid/widget/ImageView;", "close", "Landroid/widget/ImageView;", "getClose", "()Landroid/widget/ImageView;", "setClose", "(Landroid/widget/ImageView;)V", "Lkotlin/Function0;", "btn1Block", "Lkotlin/jvm/functions/Function0;", "getBtn1Block", "()Lkotlin/jvm/functions/Function0;", "btn3Block", "getBtn3Block", "timing_btn1", "getTiming_btn1", "setTiming_btn1", "timing_btn2", "getTiming_btn2", "setTiming_btn2", "mode", "getMode", "btn4Block", "getBtn4Block", "btn5Block", "getBtn5Block", "themeMode", "getThemeMode", "timing_btn4", "getTiming_btn4", "setTiming_btn4", "timing_btn5", "getTiming_btn5", "setTiming_btn5", "btn3_time", "getBtn3_time", "setBtn3_time", "btn2_time", "getBtn2_time", "setBtn2_time", "btn2Block", "getBtn2Block", "<init>", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lkotlin/jvm/functions/Function0;Lkotlin/jvm/functions/Function0;Lkotlin/jvm/functions/Function0;Lkotlin/jvm/functions/Function0;Lkotlin/jvm/functions/Function0;)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class TimingBottomDialog extends BottomSheetDialogFragment {

    @NotNull
    private final Function0<Unit> btn1Block;

    @NotNull
    private final Function0<Unit> btn2Block;
    public TextView btn2_time;

    @NotNull
    private final Function0<Unit> btn3Block;
    public TextView btn3_time;

    @NotNull
    private final Function0<Unit> btn4Block;
    public TextView btn4_time;

    @NotNull
    private final Function0<Unit> btn5Block;
    public TextView btn5_time;
    public ImageView close;

    @NotNull
    private final String countdown;

    @NotNull
    private final String during;

    @NotNull
    private final String mode;

    @NotNull
    private final String themeMode;
    public TextView timing_btn1;
    public TextView timing_btn2;
    public TextView timing_btn3;
    public TextView timing_btn4;
    public TextView timing_btn5;

    public /* synthetic */ TimingBottomDialog(String str, String str2, String str3, String str4, Function0 function0, Function0 function02, Function0 function03, Function0 function04, Function0 function05, int i2, DefaultConstructorMarker defaultConstructorMarker) {
        this(str, str2, str3, str4, (i2 & 16) != 0 ? new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.TimingBottomDialog.1
            @Override // kotlin.jvm.functions.Function0
            public /* bridge */ /* synthetic */ Unit invoke() {
                invoke2();
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2() {
            }
        } : function0, (i2 & 32) != 0 ? new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.TimingBottomDialog.2
            @Override // kotlin.jvm.functions.Function0
            public /* bridge */ /* synthetic */ Unit invoke() {
                invoke2();
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2() {
            }
        } : function02, (i2 & 64) != 0 ? new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.TimingBottomDialog.3
            @Override // kotlin.jvm.functions.Function0
            public /* bridge */ /* synthetic */ Unit invoke() {
                invoke2();
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2() {
            }
        } : function03, (i2 & 128) != 0 ? new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.TimingBottomDialog.4
            @Override // kotlin.jvm.functions.Function0
            public /* bridge */ /* synthetic */ Unit invoke() {
                invoke2();
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2() {
            }
        } : function04, (i2 & 256) != 0 ? new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.TimingBottomDialog.5
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

    /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue
    java.lang.NullPointerException: Cannot invoke "java.util.List.iterator()" because the return value of "jadx.core.dex.visitors.regions.SwitchOverStringVisitor$SwitchData.getNewCases()" is null
    	at jadx.core.dex.visitors.regions.SwitchOverStringVisitor.restoreSwitchOverString(SwitchOverStringVisitor.java:109)
    	at jadx.core.dex.visitors.regions.SwitchOverStringVisitor.visitRegion(SwitchOverStringVisitor.java:66)
    	at jadx.core.dex.visitors.regions.DepthRegionTraversal.traverseIterativeStepInternal(DepthRegionTraversal.java:77)
    	at jadx.core.dex.visitors.regions.DepthRegionTraversal.traverseIterativeStepInternal(DepthRegionTraversal.java:82)
    	at jadx.core.dex.visitors.regions.DepthRegionTraversal.traverseIterative(DepthRegionTraversal.java:31)
    	at jadx.core.dex.visitors.regions.SwitchOverStringVisitor.visit(SwitchOverStringVisitor.java:60)
     */
    private final void initContentView(View contentView) {
        View findViewById = contentView.findViewById(R.id.timing_btn1);
        Intrinsics.checkNotNullExpressionValue(findViewById, "contentView.findViewById(R.id.timing_btn1)");
        setTiming_btn1((TextView) findViewById);
        View findViewById2 = contentView.findViewById(R.id.timing_btn2);
        Intrinsics.checkNotNullExpressionValue(findViewById2, "contentView.findViewById(R.id.timing_btn2)");
        setTiming_btn2((TextView) findViewById2);
        View findViewById3 = contentView.findViewById(R.id.timing_btn3);
        Intrinsics.checkNotNullExpressionValue(findViewById3, "contentView.findViewById(R.id.timing_btn3)");
        setTiming_btn3((TextView) findViewById3);
        View findViewById4 = contentView.findViewById(R.id.timing_btn4);
        Intrinsics.checkNotNullExpressionValue(findViewById4, "contentView.findViewById(R.id.timing_btn4)");
        setTiming_btn4((TextView) findViewById4);
        View findViewById5 = contentView.findViewById(R.id.timing_btn5);
        Intrinsics.checkNotNullExpressionValue(findViewById5, "contentView.findViewById(R.id.timing_btn5)");
        setTiming_btn5((TextView) findViewById5);
        View findViewById6 = contentView.findViewById(R.id.btn2_time);
        Intrinsics.checkNotNullExpressionValue(findViewById6, "contentView.findViewById(R.id.btn2_time)");
        setBtn2_time((TextView) findViewById6);
        View findViewById7 = contentView.findViewById(R.id.btn3_time);
        Intrinsics.checkNotNullExpressionValue(findViewById7, "contentView.findViewById(R.id.btn3_time)");
        setBtn3_time((TextView) findViewById7);
        View findViewById8 = contentView.findViewById(R.id.btn4_time);
        Intrinsics.checkNotNullExpressionValue(findViewById8, "contentView.findViewById(R.id.btn4_time)");
        setBtn4_time((TextView) findViewById8);
        View findViewById9 = contentView.findViewById(R.id.btn5_time);
        Intrinsics.checkNotNullExpressionValue(findViewById9, "contentView.findViewById(R.id.btn5_time)");
        setBtn5_time((TextView) findViewById9);
        View findViewById10 = contentView.findViewById(R.id.close);
        Intrinsics.checkNotNullExpressionValue(findViewById10, "contentView.findViewById(R.id.close)");
        setClose((ImageView) findViewById10);
        List listOf = CollectionsKt__CollectionsKt.listOf((Object[]) new TextView[]{getTiming_btn1(), getTiming_btn2(), getTiming_btn3(), getTiming_btn4(), getTiming_btn5()});
        int size = listOf.size() - 1;
        if (size >= 0) {
            int i2 = 0;
            while (true) {
                int i3 = i2 + 1;
                TextView textView = (TextView) listOf.get(i2);
                if (Intrinsics.areEqual(String.valueOf(i2), this.mode)) {
                    textView.setTextColor(ContextCompat.getColor(requireContext(), R.color.color_gold_main));
                }
                if (i3 > size) {
                    break;
                } else {
                    i2 = i3;
                }
            }
        }
        getBtn2_time().setText(this.during);
        getBtn3_time().setText(this.countdown);
        getBtn4_time().setText(this.countdown);
        getBtn5_time().setText(this.countdown);
        String str = this.mode;
        switch (str.hashCode()) {
            case 50:
                if (str.equals("2")) {
                    getBtn3_time().setVisibility(0);
                    getBtn4_time().setVisibility(4);
                    getBtn5_time().setVisibility(4);
                    break;
                }
                break;
            case 51:
                if (str.equals("3")) {
                    getBtn4_time().setVisibility(0);
                    getBtn3_time().setVisibility(4);
                    getBtn5_time().setVisibility(4);
                    break;
                }
                break;
            case 52:
                if (str.equals(HomeDataHelper.type_tag)) {
                    getBtn5_time().setVisibility(0);
                    getBtn3_time().setVisibility(4);
                    getBtn4_time().setVisibility(4);
                    break;
                }
                break;
        }
        C2354n.m2374A(getTiming_btn1(), 0L, new Function1<TextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.TimingBottomDialog$initContentView$1
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(TextView textView2) {
                invoke2(textView2);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull TextView it) {
                Intrinsics.checkNotNullParameter(it, "it");
                TimingBottomDialog.this.getBtn1Block().invoke();
                TimingBottomDialog.this.dismissAllowingStateLoss();
            }
        }, 1);
        C2354n.m2374A(getTiming_btn2(), 0L, new Function1<TextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.TimingBottomDialog$initContentView$2
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(TextView textView2) {
                invoke2(textView2);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull TextView it) {
                Intrinsics.checkNotNullParameter(it, "it");
                TimingBottomDialog.this.getBtn2Block().invoke();
                TimingBottomDialog.this.dismissAllowingStateLoss();
            }
        }, 1);
        C2354n.m2374A(getTiming_btn3(), 0L, new Function1<TextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.TimingBottomDialog$initContentView$3
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(TextView textView2) {
                invoke2(textView2);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull TextView it) {
                Intrinsics.checkNotNullParameter(it, "it");
                TimingBottomDialog.this.getBtn3Block().invoke();
                TimingBottomDialog.this.dismissAllowingStateLoss();
            }
        }, 1);
        C2354n.m2374A(getTiming_btn4(), 0L, new Function1<TextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.TimingBottomDialog$initContentView$4
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(TextView textView2) {
                invoke2(textView2);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull TextView it) {
                Intrinsics.checkNotNullParameter(it, "it");
                TimingBottomDialog.this.getBtn4Block().invoke();
                TimingBottomDialog.this.dismissAllowingStateLoss();
            }
        }, 1);
        C2354n.m2374A(getTiming_btn5(), 0L, new Function1<TextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.TimingBottomDialog$initContentView$5
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(TextView textView2) {
                invoke2(textView2);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull TextView it) {
                Intrinsics.checkNotNullParameter(it, "it");
                TimingBottomDialog.this.getBtn5Block().invoke();
                TimingBottomDialog.this.dismissAllowingStateLoss();
            }
        }, 1);
        C2354n.m2374A(getClose(), 0L, new Function1<ImageView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.TimingBottomDialog$initContentView$6
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
                TimingBottomDialog.this.dismissAllowingStateLoss();
            }
        }, 1);
    }

    public void _$_clearFindViewByIdCache() {
    }

    @NotNull
    public final Function0<Unit> getBtn1Block() {
        return this.btn1Block;
    }

    @NotNull
    public final Function0<Unit> getBtn2Block() {
        return this.btn2Block;
    }

    @NotNull
    public final TextView getBtn2_time() {
        TextView textView = this.btn2_time;
        if (textView != null) {
            return textView;
        }
        Intrinsics.throwUninitializedPropertyAccessException("btn2_time");
        throw null;
    }

    @NotNull
    public final Function0<Unit> getBtn3Block() {
        return this.btn3Block;
    }

    @NotNull
    public final TextView getBtn3_time() {
        TextView textView = this.btn3_time;
        if (textView != null) {
            return textView;
        }
        Intrinsics.throwUninitializedPropertyAccessException("btn3_time");
        throw null;
    }

    @NotNull
    public final Function0<Unit> getBtn4Block() {
        return this.btn4Block;
    }

    @NotNull
    public final TextView getBtn4_time() {
        TextView textView = this.btn4_time;
        if (textView != null) {
            return textView;
        }
        Intrinsics.throwUninitializedPropertyAccessException("btn4_time");
        throw null;
    }

    @NotNull
    public final Function0<Unit> getBtn5Block() {
        return this.btn5Block;
    }

    @NotNull
    public final TextView getBtn5_time() {
        TextView textView = this.btn5_time;
        if (textView != null) {
            return textView;
        }
        Intrinsics.throwUninitializedPropertyAccessException("btn5_time");
        throw null;
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
    public final String getCountdown() {
        return this.countdown;
    }

    @NotNull
    public final String getDuring() {
        return this.during;
    }

    @NotNull
    public final String getMode() {
        return this.mode;
    }

    @NotNull
    public final String getThemeMode() {
        return this.themeMode;
    }

    @NotNull
    public final TextView getTiming_btn1() {
        TextView textView = this.timing_btn1;
        if (textView != null) {
            return textView;
        }
        Intrinsics.throwUninitializedPropertyAccessException("timing_btn1");
        throw null;
    }

    @NotNull
    public final TextView getTiming_btn2() {
        TextView textView = this.timing_btn2;
        if (textView != null) {
            return textView;
        }
        Intrinsics.throwUninitializedPropertyAccessException("timing_btn2");
        throw null;
    }

    @NotNull
    public final TextView getTiming_btn3() {
        TextView textView = this.timing_btn3;
        if (textView != null) {
            return textView;
        }
        Intrinsics.throwUninitializedPropertyAccessException("timing_btn3");
        throw null;
    }

    @NotNull
    public final TextView getTiming_btn4() {
        TextView textView = this.timing_btn4;
        if (textView != null) {
            return textView;
        }
        Intrinsics.throwUninitializedPropertyAccessException("timing_btn4");
        throw null;
    }

    @NotNull
    public final TextView getTiming_btn5() {
        TextView textView = this.timing_btn5;
        if (textView != null) {
            return textView;
        }
        Intrinsics.throwUninitializedPropertyAccessException("timing_btn5");
        throw null;
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
        View contentView = LayoutInflater.from(getContext()).inflate(R.layout.dialog_timing_bottom_light, (ViewGroup) null);
        onCreateDialog.setContentView(contentView);
        Intrinsics.checkNotNullExpressionValue(contentView, "contentView");
        initContentView(contentView);
        Window window = onCreateDialog.getWindow();
        if (window != null) {
            window.setDimAmount(0.5f);
        }
        WindowManager.LayoutParams attributes = window != null ? window.getAttributes() : null;
        if (attributes != null) {
            attributes.windowAnimations = R.style.BottomShowAnimation;
        }
        return onCreateDialog;
    }

    @Override // androidx.fragment.app.Fragment
    public void onDestroy() {
        super.onDestroy();
    }

    public final void setBtn2_time(@NotNull TextView textView) {
        Intrinsics.checkNotNullParameter(textView, "<set-?>");
        this.btn2_time = textView;
    }

    public final void setBtn3_time(@NotNull TextView textView) {
        Intrinsics.checkNotNullParameter(textView, "<set-?>");
        this.btn3_time = textView;
    }

    public final void setBtn4_time(@NotNull TextView textView) {
        Intrinsics.checkNotNullParameter(textView, "<set-?>");
        this.btn4_time = textView;
    }

    public final void setBtn5_time(@NotNull TextView textView) {
        Intrinsics.checkNotNullParameter(textView, "<set-?>");
        this.btn5_time = textView;
    }

    public final void setClose(@NotNull ImageView imageView) {
        Intrinsics.checkNotNullParameter(imageView, "<set-?>");
        this.close = imageView;
    }

    public final void setTiming_btn1(@NotNull TextView textView) {
        Intrinsics.checkNotNullParameter(textView, "<set-?>");
        this.timing_btn1 = textView;
    }

    public final void setTiming_btn2(@NotNull TextView textView) {
        Intrinsics.checkNotNullParameter(textView, "<set-?>");
        this.timing_btn2 = textView;
    }

    public final void setTiming_btn3(@NotNull TextView textView) {
        Intrinsics.checkNotNullParameter(textView, "<set-?>");
        this.timing_btn3 = textView;
    }

    public final void setTiming_btn4(@NotNull TextView textView) {
        Intrinsics.checkNotNullParameter(textView, "<set-?>");
        this.timing_btn4 = textView;
    }

    public final void setTiming_btn5(@NotNull TextView textView) {
        Intrinsics.checkNotNullParameter(textView, "<set-?>");
        this.timing_btn5 = textView;
    }

    public TimingBottomDialog(@NotNull String themeMode, @NotNull String mode, @NotNull String during, @NotNull String countdown, @NotNull Function0<Unit> btn1Block, @NotNull Function0<Unit> btn2Block, @NotNull Function0<Unit> btn3Block, @NotNull Function0<Unit> btn4Block, @NotNull Function0<Unit> btn5Block) {
        Intrinsics.checkNotNullParameter(themeMode, "themeMode");
        Intrinsics.checkNotNullParameter(mode, "mode");
        Intrinsics.checkNotNullParameter(during, "during");
        Intrinsics.checkNotNullParameter(countdown, "countdown");
        Intrinsics.checkNotNullParameter(btn1Block, "btn1Block");
        Intrinsics.checkNotNullParameter(btn2Block, "btn2Block");
        Intrinsics.checkNotNullParameter(btn3Block, "btn3Block");
        Intrinsics.checkNotNullParameter(btn4Block, "btn4Block");
        Intrinsics.checkNotNullParameter(btn5Block, "btn5Block");
        this.themeMode = themeMode;
        this.mode = mode;
        this.during = during;
        this.countdown = countdown;
        this.btn1Block = btn1Block;
        this.btn2Block = btn2Block;
        this.btn3Block = btn3Block;
        this.btn4Block = btn4Block;
        this.btn5Block = btn5Block;
    }
}
