package com.jbzd.media.movecartoons.p396ui.dialog;

import android.annotation.SuppressLint;
import android.app.Dialog;
import android.content.Context;
import android.os.Bundle;
import android.util.Base64;
import android.view.LayoutInflater;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.view.WindowManager;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.widget.AppCompatEditText;
import androidx.fragment.app.DialogFragment;
import androidx.lifecycle.Observer;
import com.jbzd.media.movecartoons.bean.response.PicVefBean;
import com.jbzd.media.movecartoons.p396ui.dialog.RobotDialog;
import com.jbzd.media.movecartoons.p396ui.splash.SplashViewMode;
import com.qnmd.adnnm.da0yzo.R;
import java.util.ArrayList;
import java.util.Iterator;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.collections.CollectionsKt__IterablesKt;
import kotlin.collections.CollectionsKt___CollectionsKt;
import kotlin.collections.IntIterator;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.random.Random;
import kotlin.ranges.IntRange;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p143g.p144a.p147m.p156v.p157c.C1721z;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p327w.p330b.p336c.C2851b;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000T\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010\u0007\n\u0002\b\u0003\n\u0002\u0010\u000e\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0011\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\n\u0018\u00002\u00020\u0001B5\u0012\u0006\u00106\u001a\u00020/\u0012\u0006\u0010\u0019\u001a\u00020\u0018\u0012\u0006\u0010\u0014\u001a\u00020\u0013\u0012\u0014\b\u0002\u0010+\u001a\u000e\u0012\u0004\u0012\u00020\u0013\u0012\u0004\u0012\u00020\f0*¢\u0006\u0004\b7\u00108J\u000f\u0010\u0003\u001a\u00020\u0002H\u0002¢\u0006\u0004\b\u0003\u0010\u0004J\u0019\u0010\b\u001a\u00020\u00072\b\u0010\u0006\u001a\u0004\u0018\u00010\u0005H\u0016¢\u0006\u0004\b\b\u0010\tJ!\u0010\r\u001a\u00020\f2\u0006\u0010\u000b\u001a\u00020\n2\b\u0010\u0006\u001a\u0004\u0018\u00010\u0005H\u0016¢\u0006\u0004\b\r\u0010\u000eJ\u001d\u0010\u0011\u001a\u00020\f*\u00020\n2\b\b\u0002\u0010\u0010\u001a\u00020\u000fH\u0007¢\u0006\u0004\b\u0011\u0010\u0012R\u0019\u0010\u0014\u001a\u00020\u00138\u0006@\u0006¢\u0006\f\n\u0004\b\u0014\u0010\u0015\u001a\u0004\b\u0016\u0010\u0017R\u0019\u0010\u0019\u001a\u00020\u00188\u0006@\u0006¢\u0006\f\n\u0004\b\u0019\u0010\u001a\u001a\u0004\b\u001b\u0010\u001cR\u001d\u0010 \u001a\u00020\u00028B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u001d\u0010\u001e\u001a\u0004\b\u001f\u0010\u0004R\"\u0010!\u001a\u00020\u00138\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b!\u0010\u0015\u001a\u0004\b\"\u0010\u0017\"\u0004\b#\u0010$R%\u0010)\u001a\n %*\u0004\u0018\u00010\n0\n8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b&\u0010\u001e\u001a\u0004\b'\u0010(R%\u0010+\u001a\u000e\u0012\u0004\u0012\u00020\u0013\u0012\u0004\u0012\u00020\f0*8\u0006@\u0006¢\u0006\f\n\u0004\b+\u0010,\u001a\u0004\b-\u0010.R\"\u00100\u001a\u00020/8\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b0\u00101\u001a\u0004\b2\u00103\"\u0004\b4\u00105¨\u00069"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/dialog/RobotDialog;", "Landroidx/fragment/app/DialogFragment;", "Landroidx/appcompat/app/AlertDialog;", "createDialog", "()Landroidx/appcompat/app/AlertDialog;", "Landroid/os/Bundle;", "savedInstanceState", "Landroid/app/Dialog;", "onCreateDialog", "(Landroid/os/Bundle;)Landroid/app/Dialog;", "Landroid/view/View;", "view", "", "onViewCreated", "(Landroid/view/View;Landroid/os/Bundle;)V", "", "pressedAlpha", "fadeWhenTouch", "(Landroid/view/View;F)V", "", "content", "Ljava/lang/String;", "getContent", "()Ljava/lang/String;", "Lcom/jbzd/media/movecartoons/ui/splash/SplashViewMode;", "viewModel", "Lcom/jbzd/media/movecartoons/ui/splash/SplashViewMode;", "getViewModel", "()Lcom/jbzd/media/movecartoons/ui/splash/SplashViewMode;", "alertDialog$delegate", "Lkotlin/Lazy;", "getAlertDialog", "alertDialog", "chapchaKey", "getChapchaKey", "setChapchaKey", "(Ljava/lang/String;)V", "kotlin.jvm.PlatformType", "contentView$delegate", "getContentView", "()Landroid/view/View;", "contentView", "Lkotlin/Function1;", "submit", "Lkotlin/jvm/functions/Function1;", "getSubmit", "()Lkotlin/jvm/functions/Function1;", "Landroid/content/Context;", "mContext", "Landroid/content/Context;", "getMContext", "()Landroid/content/Context;", "setMContext", "(Landroid/content/Context;)V", "context", "<init>", "(Landroid/content/Context;Lcom/jbzd/media/movecartoons/ui/splash/SplashViewMode;Ljava/lang/String;Lkotlin/jvm/functions/Function1;)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class RobotDialog extends DialogFragment {

    /* renamed from: alertDialog$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy alertDialog;

    @NotNull
    private String chapchaKey;

    @NotNull
    private final String content;

    /* renamed from: contentView$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy contentView;

    @NotNull
    private Context mContext;

    @NotNull
    private final Function1<String, Unit> submit;

    @NotNull
    private final SplashViewMode viewModel;

    public /* synthetic */ RobotDialog(Context context, SplashViewMode splashViewMode, String str, Function1 function1, int i2, DefaultConstructorMarker defaultConstructorMarker) {
        this(context, splashViewMode, str, (i2 & 8) != 0 ? new Function1<String, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.RobotDialog.1
            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(String str2) {
                invoke2(str2);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull String it) {
                Intrinsics.checkNotNullParameter(it, "it");
            }
        } : function1);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final AlertDialog createDialog() {
        final ImageView imageView = (ImageView) getContentView().findViewById(R.id.iv_close);
        final ImageView imageView2 = (ImageView) getContentView().findViewById(R.id.iv_picVef);
        final AppCompatEditText appCompatEditText = (AppCompatEditText) getContentView().findViewById(R.id.edit_robot_code);
        final TextView textView = (TextView) getContentView().findViewById(R.id.tv_robotcode_change);
        final TextView textView2 = (TextView) getContentView().findViewById(R.id.tv_robotcode_sure);
        AlertDialog create = new AlertDialog.Builder(requireContext(), R.style.TopScaleDialogStyle).setView(getContentView()).setCancelable(false).create();
        Intrinsics.checkNotNullExpressionValue(create, "Builder(requireContext(), R.style.TopScaleDialogStyle)\n            .setView(contentView)\n            .setCancelable(false)\n            .create()");
        SplashViewMode splashViewMode = this.viewModel;
        IntRange intRange = new IntRange(1, 32);
        ArrayList arrayList = new ArrayList(CollectionsKt__IterablesKt.collectionSizeOrDefault(intRange, 10));
        Iterator<Integer> it = intRange.iterator();
        while (it.hasNext()) {
            ((IntIterator) it).nextInt();
            arrayList.add(Character.valueOf("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ".charAt(Random.INSTANCE.nextInt(36))));
        }
        setChapchaKey(CollectionsKt___CollectionsKt.joinToString$default(arrayList, "", null, null, 0, null, null, 62, null));
        SplashViewMode.systemCaptcha$default(getViewModel(), getChapchaKey(), false, 2, null);
        splashViewMode.getPicVefBean().observeForever(new Observer() { // from class: b.a.a.a.t.e.u
            @Override // androidx.lifecycle.Observer
            public final void onChanged(Object obj) {
                RobotDialog.m5784createDialog$lambda1$lambda0(RobotDialog.this, imageView2, imageView, textView, textView2, appCompatEditText, (PicVefBean) obj);
            }
        });
        Window window = create.getWindow();
        if (window != null) {
            window.setDimAmount(0.8f);
        }
        WindowManager.LayoutParams attributes = window != null ? window.getAttributes() : null;
        if (attributes != null) {
            attributes.windowAnimations = R.style.BottomShowAnimation;
        }
        return create;
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: createDialog$lambda-1$lambda-0, reason: not valid java name */
    public static final void m5784createDialog$lambda1$lambda0(final RobotDialog this$0, ImageView iv_picVef, ImageView imageView, TextView textView, TextView textView2, final AppCompatEditText appCompatEditText, PicVefBean picVefBean) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        byte[] decode = Base64.decode(picVefBean == null ? null : picVefBean.getBase64WithoutHead(), 0);
        Intrinsics.checkNotNullExpressionValue(decode, "decode(it?.base64WithoutHead, Base64.DEFAULT)");
        ((C2851b) ((C2851b) C2354n.m2455a2(this$0.getMContext()).mo770c().mo764Y(decode)).m1077G(new C1721z(12), true)).m757R(iv_picVef);
        C2354n.m2377B(imageView, 0L, new Function1<ImageView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.RobotDialog$createDialog$1$1$1
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
                RobotDialog.this.dismissAllowingStateLoss();
            }
        }, 1);
        Intrinsics.checkNotNullExpressionValue(iv_picVef, "iv_picVef");
        fadeWhenTouch$default(this$0, iv_picVef, 0.0f, 1, null);
        C2354n.m2377B(iv_picVef, 0L, new Function1<ImageView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.RobotDialog$createDialog$1$1$2
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
                SplashViewMode.systemCaptcha$default(RobotDialog.this.getViewModel(), RobotDialog.this.getChapchaKey(), false, 2, null);
            }
        }, 1);
        C2354n.m2377B(textView, 0L, new Function1<TextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.RobotDialog$createDialog$1$1$3
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
                SplashViewMode.systemCaptcha$default(RobotDialog.this.getViewModel(), RobotDialog.this.getChapchaKey(), false, 2, null);
            }
        }, 1);
        C2354n.m2377B(textView2, 0L, new Function1<TextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.RobotDialog$createDialog$1$1$4
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
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
                if (Intrinsics.areEqual(String.valueOf(AppCompatEditText.this.getText()), "")) {
                    C2354n.m2525w0("请输入验证码");
                    return;
                }
                this$0.getSubmit().invoke(String.valueOf(AppCompatEditText.this.getText()));
                this$0.getViewModel().requestSystemInfoNew(this$0.getChapchaKey(), String.valueOf(AppCompatEditText.this.getText()));
                this$0.dismiss();
            }
        }, 1);
    }

    public static /* synthetic */ void fadeWhenTouch$default(RobotDialog robotDialog, View view, float f2, int i2, Object obj) {
        if ((i2 & 1) != 0) {
            f2 = 0.7f;
        }
        robotDialog.fadeWhenTouch(view, f2);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: fadeWhenTouch$lambda-3, reason: not valid java name */
    public static final boolean m5785fadeWhenTouch$lambda3(float f2, View view, MotionEvent motionEvent) {
        Integer valueOf = motionEvent == null ? null : Integer.valueOf(motionEvent.getAction());
        if (valueOf != null && valueOf.intValue() == 0) {
            if (view == null) {
                return false;
            }
            view.setAlpha(f2);
            return false;
        }
        if (valueOf != null && valueOf.intValue() == 1) {
            if (view == null) {
                return false;
            }
            view.setAlpha(1.0f);
            return false;
        }
        if (valueOf == null || valueOf.intValue() != 3 || view == null) {
            return false;
        }
        view.setAlpha(1.0f);
        return false;
    }

    private final AlertDialog getAlertDialog() {
        return (AlertDialog) this.alertDialog.getValue();
    }

    private final View getContentView() {
        return (View) this.contentView.getValue();
    }

    public void _$_clearFindViewByIdCache() {
    }

    @SuppressLint({"ClickableViewAccessibility"})
    public final void fadeWhenTouch(@NotNull View view, final float f2) {
        Intrinsics.checkNotNullParameter(view, "<this>");
        view.setOnTouchListener(new View.OnTouchListener() { // from class: b.a.a.a.t.e.t
            @Override // android.view.View.OnTouchListener
            public final boolean onTouch(View view2, MotionEvent motionEvent) {
                boolean m5785fadeWhenTouch$lambda3;
                m5785fadeWhenTouch$lambda3 = RobotDialog.m5785fadeWhenTouch$lambda3(f2, view2, motionEvent);
                return m5785fadeWhenTouch$lambda3;
            }
        });
    }

    @NotNull
    public final String getChapchaKey() {
        return this.chapchaKey;
    }

    @NotNull
    public final String getContent() {
        return this.content;
    }

    @NotNull
    public final Context getMContext() {
        return this.mContext;
    }

    @NotNull
    public final Function1<String, Unit> getSubmit() {
        return this.submit;
    }

    @NotNull
    public final SplashViewMode getViewModel() {
        return this.viewModel;
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

    public final void setChapchaKey(@NotNull String str) {
        Intrinsics.checkNotNullParameter(str, "<set-?>");
        this.chapchaKey = str;
    }

    public final void setMContext(@NotNull Context context) {
        Intrinsics.checkNotNullParameter(context, "<set-?>");
        this.mContext = context;
    }

    /* JADX WARN: Multi-variable type inference failed */
    public RobotDialog(@NotNull final Context context, @NotNull SplashViewMode viewModel, @NotNull String content, @NotNull Function1<? super String, Unit> submit) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(viewModel, "viewModel");
        Intrinsics.checkNotNullParameter(content, "content");
        Intrinsics.checkNotNullParameter(submit, "submit");
        this.viewModel = viewModel;
        this.content = content;
        this.submit = submit;
        this.chapchaKey = "";
        this.mContext = context;
        this.contentView = LazyKt__LazyJVMKt.lazy(new Function0<View>() { // from class: com.jbzd.media.movecartoons.ui.dialog.RobotDialog$contentView$2
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            public final View invoke() {
                return LayoutInflater.from(context).inflate(R.layout.dialog_robot_code, (ViewGroup) null);
            }
        });
        this.alertDialog = LazyKt__LazyJVMKt.lazy(new Function0<AlertDialog>() { // from class: com.jbzd.media.movecartoons.ui.dialog.RobotDialog$alertDialog$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final AlertDialog invoke() {
                AlertDialog createDialog;
                createDialog = RobotDialog.this.createDialog();
                return createDialog;
            }
        });
    }
}
