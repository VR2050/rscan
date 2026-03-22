package com.jbzd.media.movecartoons.p396ui.dialog;

import android.app.Dialog;
import android.content.Context;
import android.os.Bundle;
import android.util.Base64;
import android.view.LayoutInflater;
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
import com.jbzd.media.movecartoons.p396ui.dialog.ComicsChapterRobotDialog;
import com.jbzd.media.movecartoons.p396ui.search.model.ComicsViewModel;
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
import p005b.p143g.p144a.ComponentCallbacks2C1553c;
import p005b.p143g.p144a.p147m.p156v.p157c.C1721z;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p327w.p330b.p336c.C2851b;
import p005b.p327w.p330b.p336c.C2852c;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000D\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0002\b\n\n\u0002\u0018\u0002\n\u0002\b\u000b\n\u0002\u0018\u0002\n\u0002\b\u0007\u0018\u00002\u00020\u0001B-\u0012\u0006\u0010'\u001a\u00020&\u0012\u0006\u0010\u0010\u001a\u00020\u000f\u0012\u0014\b\u0002\u0010\u001b\u001a\u000e\u0012\u0004\u0012\u00020\u000f\u0012\u0004\u0012\u00020\f0\u001a¢\u0006\u0004\b+\u0010,J\u000f\u0010\u0003\u001a\u00020\u0002H\u0002¢\u0006\u0004\b\u0003\u0010\u0004J\u0019\u0010\b\u001a\u00020\u00072\b\u0010\u0006\u001a\u0004\u0018\u00010\u0005H\u0016¢\u0006\u0004\b\b\u0010\tJ!\u0010\r\u001a\u00020\f2\u0006\u0010\u000b\u001a\u00020\n2\b\u0010\u0006\u001a\u0004\u0018\u00010\u0005H\u0016¢\u0006\u0004\b\r\u0010\u000eR\u0019\u0010\u0010\u001a\u00020\u000f8\u0006@\u0006¢\u0006\f\n\u0004\b\u0010\u0010\u0011\u001a\u0004\b\u0012\u0010\u0013R%\u0010\u0019\u001a\n \u0014*\u0004\u0018\u00010\n0\n8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u0015\u0010\u0016\u001a\u0004\b\u0017\u0010\u0018R%\u0010\u001b\u001a\u000e\u0012\u0004\u0012\u00020\u000f\u0012\u0004\u0012\u00020\f0\u001a8\u0006@\u0006¢\u0006\f\n\u0004\b\u001b\u0010\u001c\u001a\u0004\b\u001d\u0010\u001eR\u001d\u0010!\u001a\u00020\u00028B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u001f\u0010\u0016\u001a\u0004\b \u0010\u0004R\"\u0010\"\u001a\u00020\u000f8\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\"\u0010\u0011\u001a\u0004\b#\u0010\u0013\"\u0004\b$\u0010%R\u0019\u0010'\u001a\u00020&8\u0006@\u0006¢\u0006\f\n\u0004\b'\u0010(\u001a\u0004\b)\u0010*¨\u0006-"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/dialog/ComicsChapterRobotDialog;", "Landroidx/fragment/app/DialogFragment;", "Landroidx/appcompat/app/AlertDialog;", "createDialog", "()Landroidx/appcompat/app/AlertDialog;", "Landroid/os/Bundle;", "savedInstanceState", "Landroid/app/Dialog;", "onCreateDialog", "(Landroid/os/Bundle;)Landroid/app/Dialog;", "Landroid/view/View;", "view", "", "onViewCreated", "(Landroid/view/View;Landroid/os/Bundle;)V", "", "content", "Ljava/lang/String;", "getContent", "()Ljava/lang/String;", "kotlin.jvm.PlatformType", "contentView$delegate", "Lkotlin/Lazy;", "getContentView", "()Landroid/view/View;", "contentView", "Lkotlin/Function1;", "submit", "Lkotlin/jvm/functions/Function1;", "getSubmit", "()Lkotlin/jvm/functions/Function1;", "alertDialog$delegate", "getAlertDialog", "alertDialog", "chapchaKey", "getChapchaKey", "setChapchaKey", "(Ljava/lang/String;)V", "Lcom/jbzd/media/movecartoons/ui/search/model/ComicsViewModel;", "viewModel", "Lcom/jbzd/media/movecartoons/ui/search/model/ComicsViewModel;", "getViewModel", "()Lcom/jbzd/media/movecartoons/ui/search/model/ComicsViewModel;", "<init>", "(Lcom/jbzd/media/movecartoons/ui/search/model/ComicsViewModel;Ljava/lang/String;Lkotlin/jvm/functions/Function1;)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class ComicsChapterRobotDialog extends DialogFragment {

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
    private final Function1<String, Unit> submit;

    @NotNull
    private final ComicsViewModel viewModel;

    public /* synthetic */ ComicsChapterRobotDialog(ComicsViewModel comicsViewModel, String str, Function1 function1, int i2, DefaultConstructorMarker defaultConstructorMarker) {
        this(comicsViewModel, str, (i2 & 4) != 0 ? new Function1<String, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.ComicsChapterRobotDialog.1
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
        AlertDialog create = new AlertDialog.Builder(requireContext(), R.style.TopScaleDialogStyle).setView(getContentView()).setCancelable(false).create();
        Intrinsics.checkNotNullExpressionValue(create, "Builder(requireContext(), R.style.TopScaleDialogStyle)\n            .setView(contentView)\n            .setCancelable(false)\n            .create()");
        ComicsViewModel comicsViewModel = this.viewModel;
        IntRange intRange = new IntRange(1, 32);
        ArrayList arrayList = new ArrayList(CollectionsKt__IterablesKt.collectionSizeOrDefault(intRange, 10));
        Iterator<Integer> it = intRange.iterator();
        while (it.hasNext()) {
            ((IntIterator) it).nextInt();
            arrayList.add(Character.valueOf("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ".charAt(Random.INSTANCE.nextInt(36))));
        }
        setChapchaKey(CollectionsKt___CollectionsKt.joinToString$default(arrayList, "", null, null, 0, null, null, 62, null));
        ComicsViewModel.systemCaptcha$default(getViewModel(), getChapchaKey(), false, 2, null);
        comicsViewModel.getPicVefBean().observe(this, new Observer() { // from class: b.a.a.a.t.e.g
            @Override // androidx.lifecycle.Observer
            public final void onChanged(Object obj) {
                ComicsChapterRobotDialog.m5771createDialog$lambda3$lambda0((PicVefBean) obj);
            }
        });
        comicsViewModel.getPicVefBean().observeForever(new Observer() { // from class: b.a.a.a.t.e.h
            @Override // androidx.lifecycle.Observer
            public final void onChanged(Object obj) {
                ComicsChapterRobotDialog.m5772createDialog$lambda3$lambda2(ComicsChapterRobotDialog.this, (PicVefBean) obj);
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
    /* renamed from: createDialog$lambda-3$lambda-0, reason: not valid java name */
    public static final void m5771createDialog$lambda3$lambda0(PicVefBean picVefBean) {
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: createDialog$lambda-3$lambda-2, reason: not valid java name */
    public static final void m5772createDialog$lambda3$lambda2(final ComicsChapterRobotDialog this$0, PicVefBean picVefBean) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        ImageView imageView = (ImageView) this$0.getContentView().findViewById(R.id.iv_close);
        ImageView imageView2 = (ImageView) this$0.getContentView().findViewById(R.id.iv_picVef);
        final AppCompatEditText appCompatEditText = (AppCompatEditText) this$0.getContentView().findViewById(R.id.edit_robot_code);
        TextView textView = (TextView) this$0.getContentView().findViewById(R.id.tv_robotcode_change);
        TextView textView2 = (TextView) this$0.getContentView().findViewById(R.id.tv_robotcode_sure);
        byte[] decode = Base64.decode(picVefBean == null ? null : picVefBean.getBase64WithoutHead(), 0);
        Intrinsics.checkNotNullExpressionValue(decode, "decode(it?.base64WithoutHead, Base64.DEFAULT)");
        Context context = this$0.getContext();
        if (context != null) {
            ((C2851b) ((C2851b) ((C2852c) ComponentCallbacks2C1553c.m738h(context)).mo770c().mo764Y(decode)).m1077G(new C1721z(10), true)).m3295i0().m757R(imageView2);
        }
        C2354n.m2374A(imageView, 0L, new Function1<ImageView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.ComicsChapterRobotDialog$createDialog$1$2$2
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(ImageView imageView3) {
                invoke2(imageView3);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(ImageView imageView3) {
                ComicsChapterRobotDialog.this.dismissAllowingStateLoss();
            }
        }, 1);
        C2354n.m2374A(textView, 0L, new Function1<TextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.ComicsChapterRobotDialog$createDialog$1$2$3
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
                ComicsViewModel.systemCaptcha$default(ComicsChapterRobotDialog.this.getViewModel(), ComicsChapterRobotDialog.this.getChapchaKey(), false, 2, null);
            }
        }, 1);
        C2354n.m2374A(textView2, 0L, new Function1<TextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.ComicsChapterRobotDialog$createDialog$1$2$4
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
                ComicsViewModel.systemUnlock$default(this$0.getViewModel(), this$0.getChapchaKey(), String.valueOf(AppCompatEditText.this.getText()), false, 4, null);
                this$0.dismiss();
            }
        }, 1);
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
    public final String getChapchaKey() {
        return this.chapchaKey;
    }

    @NotNull
    public final String getContent() {
        return this.content;
    }

    @NotNull
    public final Function1<String, Unit> getSubmit() {
        return this.submit;
    }

    @NotNull
    public final ComicsViewModel getViewModel() {
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

    /* JADX WARN: Multi-variable type inference failed */
    public ComicsChapterRobotDialog(@NotNull ComicsViewModel viewModel, @NotNull String content, @NotNull Function1<? super String, Unit> submit) {
        Intrinsics.checkNotNullParameter(viewModel, "viewModel");
        Intrinsics.checkNotNullParameter(content, "content");
        Intrinsics.checkNotNullParameter(submit, "submit");
        this.viewModel = viewModel;
        this.content = content;
        this.submit = submit;
        this.chapchaKey = "";
        this.contentView = LazyKt__LazyJVMKt.lazy(new Function0<View>() { // from class: com.jbzd.media.movecartoons.ui.dialog.ComicsChapterRobotDialog$contentView$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            public final View invoke() {
                return LayoutInflater.from(ComicsChapterRobotDialog.this.getContext()).inflate(R.layout.dialog_robot_code, (ViewGroup) null);
            }
        });
        this.alertDialog = LazyKt__LazyJVMKt.lazy(new Function0<AlertDialog>() { // from class: com.jbzd.media.movecartoons.ui.dialog.ComicsChapterRobotDialog$alertDialog$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final AlertDialog invoke() {
                AlertDialog createDialog;
                createDialog = ComicsChapterRobotDialog.this.createDialog();
                return createDialog;
            }
        });
    }
}
