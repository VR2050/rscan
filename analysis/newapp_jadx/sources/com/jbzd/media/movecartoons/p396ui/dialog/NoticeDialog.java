package com.jbzd.media.movecartoons.p396ui.dialog;

import android.app.Dialog;
import android.content.Context;
import android.content.DialogInterface;
import android.os.Bundle;
import android.view.KeyEvent;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.view.WindowManager;
import android.widget.TextView;
import androidx.appcompat.app.AlertDialog;
import androidx.fragment.app.DialogFragment;
import androidx.fragment.app.FragmentManager;
import com.jbzd.media.movecartoons.p396ui.appstore.AppStoreActivity;
import com.jbzd.media.movecartoons.p396ui.dialog.NoticeDialog;
import com.qnmd.adnnm.da0yzo.R;
import io.github.armcha.autolink.AutoLinkTextView;
import java.util.LinkedHashMap;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Result;
import kotlin.Unit;
import kotlin.coroutines.Continuation;
import kotlin.coroutines.intrinsics.IntrinsicsKt__IntrinsicsJvmKt;
import kotlin.coroutines.intrinsics.IntrinsicsKt__IntrinsicsKt;
import kotlin.coroutines.jvm.internal.DebugProbesKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p006a.p007a.p008a.p009a.C0840d;
import p005b.p006a.p007a.p008a.p009a.C0846g;
import p005b.p006a.p007a.p008a.p017r.C0917a;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p379c.p380a.C3069j;
import p379c.p380a.InterfaceC3066i;
import p429g.p430a.p431a.p432a.C4326a;
import p429g.p430a.p431a.p432a.C4330e;
import p429g.p433b.p434a.p438d.InterfaceC4341a;
import p429g.p433b.p434a.p444f.C4346a;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000N\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\u0010\u000b\n\u0002\b\u0012\u0018\u00002\u00020\u0001B\u000f\u0012\u0006\u0010\u001e\u001a\u00020\u0007¢\u0006\u0004\b*\u0010+J\u000f\u0010\u0003\u001a\u00020\u0002H\u0002¢\u0006\u0004\b\u0003\u0010\u0004J'\u0010\n\u001a\u00020\t2\u0006\u0010\u0006\u001a\u00020\u00052\n\b\u0002\u0010\b\u001a\u0004\u0018\u00010\u0007H\u0086@ø\u0001\u0000¢\u0006\u0004\b\n\u0010\u000bJ\u0017\u0010\u000e\u001a\u00020\t2\u0006\u0010\r\u001a\u00020\fH\u0016¢\u0006\u0004\b\u000e\u0010\u000fJ\u0019\u0010\u0013\u001a\u00020\u00122\b\u0010\u0011\u001a\u0004\u0018\u00010\u0010H\u0016¢\u0006\u0004\b\u0013\u0010\u0014J!\u0010\u0017\u001a\u00020\t2\u0006\u0010\u0016\u001a\u00020\u00152\b\u0010\u0011\u001a\u0004\u0018\u00010\u0010H\u0016¢\u0006\u0004\b\u0017\u0010\u0018R:\u0010\u001c\u001a&\u0012\f\u0012\n \u001b*\u0004\u0018\u00010\u001a0\u001a \u001b*\u0012\u0012\f\u0012\n \u001b*\u0004\u0018\u00010\u001a0\u001a\u0018\u00010\u00190\u00198\u0002@\u0002X\u0082\u0004¢\u0006\u0006\n\u0004\b\u001c\u0010\u001dR\u0019\u0010\u001e\u001a\u00020\u00078\u0006@\u0006¢\u0006\f\n\u0004\b\u001e\u0010\u001f\u001a\u0004\b \u0010!R%\u0010&\u001a\n \u001b*\u0004\u0018\u00010\u00150\u00158B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\"\u0010#\u001a\u0004\b$\u0010%R\u001d\u0010)\u001a\u00020\u00028B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b'\u0010#\u001a\u0004\b(\u0010\u0004\u0082\u0002\u0004\n\u0002\b\u0019¨\u0006,"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/dialog/NoticeDialog;", "Landroidx/fragment/app/DialogFragment;", "Landroidx/appcompat/app/AlertDialog;", "createDialog", "()Landroidx/appcompat/app/AlertDialog;", "Landroidx/fragment/app/FragmentManager;", "fm", "", "tag", "", "showAsSuspendable", "(Landroidx/fragment/app/FragmentManager;Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;", "Landroid/content/DialogInterface;", "dialog", "onDismiss", "(Landroid/content/DialogInterface;)V", "Landroid/os/Bundle;", "savedInstanceState", "Landroid/app/Dialog;", "onCreateDialog", "(Landroid/os/Bundle;)Landroid/app/Dialog;", "Landroid/view/View;", "view", "onViewCreated", "(Landroid/view/View;Landroid/os/Bundle;)V", "Lg/b/a/f/a;", "", "kotlin.jvm.PlatformType", "subject", "Lg/b/a/f/a;", "content", "Ljava/lang/String;", "getContent", "()Ljava/lang/String;", "contentView$delegate", "Lkotlin/Lazy;", "getContentView", "()Landroid/view/View;", "contentView", "alertDialog$delegate", "getAlertDialog", "alertDialog", "<init>", "(Ljava/lang/String;)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class NoticeDialog extends DialogFragment {

    /* renamed from: alertDialog$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy alertDialog;

    @NotNull
    private final String content;

    /* renamed from: contentView$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy contentView;
    private final C4346a<Boolean> subject;

    public NoticeDialog(@NotNull String content) {
        Intrinsics.checkNotNullParameter(content, "content");
        this.content = content;
        this.subject = new C4346a<>();
        this.contentView = LazyKt__LazyJVMKt.lazy(new Function0<View>() { // from class: com.jbzd.media.movecartoons.ui.dialog.NoticeDialog$contentView$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            public final View invoke() {
                return LayoutInflater.from(NoticeDialog.this.getContext()).inflate(R.layout.dialog_notice, (ViewGroup) null);
            }
        });
        this.alertDialog = LazyKt__LazyJVMKt.lazy(new Function0<AlertDialog>() { // from class: com.jbzd.media.movecartoons.ui.dialog.NoticeDialog$alertDialog$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final AlertDialog invoke() {
                AlertDialog createDialog;
                createDialog = NoticeDialog.this.createDialog();
                return createDialog;
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final AlertDialog createDialog() {
        AlertDialog m624j0 = C1499a.m624j0(new AlertDialog.Builder(requireContext(), R.style.TopScaleDialogStyle), getContentView(), "Builder(requireContext(), R.style.TopScaleDialogStyle)\n            .setView(contentView)\n            .create()");
        C2354n.m2374A((TextView) getContentView().findViewById(R.id.btnAppStore), 0L, new Function1<TextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.NoticeDialog$createDialog$1$1
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(TextView textView) {
                invoke2(textView);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(TextView textView) {
                NoticeDialog.this.dismissAllowingStateLoss();
                AppStoreActivity.Companion companion = AppStoreActivity.INSTANCE;
                Context requireContext = NoticeDialog.this.requireContext();
                Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
                companion.start(requireContext);
            }
        }, 1);
        C2354n.m2374A(getContentView().findViewById(R.id.btn), 0L, new Function1<TextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.NoticeDialog$createDialog$2
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(TextView textView) {
                invoke2(textView);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(TextView textView) {
                NoticeDialog.this.dismissAllowingStateLoss();
            }
        }, 1);
        AutoLinkTextView autoLinkTextView = (AutoLinkTextView) getContentView().findViewById(R.id.tvTips);
        autoLinkTextView.m4937a(new C4330e("(https?|ftp|file)://[-a-zA-Z0-9+&@#/%?=~_|!:,.;]*[-a-zA-Z0-9+&@#/%=~_|]"));
        autoLinkTextView.m4939c(new Function1<C4326a, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.NoticeDialog$createDialog$3
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
                Context requireContext = NoticeDialog.this.requireContext();
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
        m624j0.setOnKeyListener(new DialogInterface.OnKeyListener() { // from class: b.a.a.a.t.e.l
            @Override // android.content.DialogInterface.OnKeyListener
            public final boolean onKey(DialogInterface dialogInterface, int i2, KeyEvent keyEvent) {
                boolean m5776createDialog$lambda4$lambda3;
                m5776createDialog$lambda4$lambda3 = NoticeDialog.m5776createDialog$lambda4$lambda3(dialogInterface, i2, keyEvent);
                return m5776createDialog$lambda4$lambda3;
            }
        });
        return m624j0;
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: createDialog$lambda-4$lambda-3, reason: not valid java name */
    public static final boolean m5776createDialog$lambda4$lambda3(DialogInterface dialogInterface, int i2, KeyEvent keyEvent) {
        return i2 == 4 && keyEvent.getAction() == 1;
    }

    private final AlertDialog getAlertDialog() {
        return (AlertDialog) this.alertDialog.getValue();
    }

    private final View getContentView() {
        return (View) this.contentView.getValue();
    }

    public static /* synthetic */ Object showAsSuspendable$default(NoticeDialog noticeDialog, FragmentManager fragmentManager, String str, Continuation continuation, int i2, Object obj) {
        if ((i2 & 2) != 0) {
            str = null;
        }
        return noticeDialog.showAsSuspendable(fragmentManager, str, continuation);
    }

    public void _$_clearFindViewByIdCache() {
    }

    @NotNull
    public final String getContent() {
        return this.content;
    }

    @Override // androidx.fragment.app.DialogFragment
    @NotNull
    public Dialog onCreateDialog(@Nullable Bundle savedInstanceState) {
        return getAlertDialog();
    }

    @Override // androidx.fragment.app.DialogFragment, android.content.DialogInterface.OnDismissListener
    public void onDismiss(@NotNull DialogInterface dialog) {
        Intrinsics.checkNotNullParameter(dialog, "dialog");
        super.onDismiss(dialog);
        Intrinsics.checkNotNullParameter("close_notice", "act");
        LinkedHashMap linkedHashMap = new LinkedHashMap();
        linkedHashMap.put("act", "close_notice");
        C0917a.m221e(C0917a.f372a, "system/doLogs", Object.class, linkedHashMap, C0846g.f248c, null, false, false, null, false, 432);
    }

    @Override // androidx.fragment.app.Fragment
    public void onViewCreated(@NotNull View view, @Nullable Bundle savedInstanceState) {
        Intrinsics.checkNotNullParameter(view, "view");
        super.onViewCreated(view, savedInstanceState);
    }

    @Nullable
    public final Object showAsSuspendable(@NotNull FragmentManager fragmentManager, @Nullable String str, @NotNull Continuation<? super Unit> continuation) {
        final C3069j c3069j = new C3069j(IntrinsicsKt__IntrinsicsJvmKt.intercepted(continuation), 1);
        c3069j.m3602A();
        show(fragmentManager, str);
        this.subject.m4908b(new InterfaceC4341a<Boolean>() { // from class: com.jbzd.media.movecartoons.ui.dialog.NoticeDialog$showAsSuspendable$2$1
            @Override // p429g.p433b.p434a.p438d.InterfaceC4341a
            public final void accept(Boolean it) {
                Intrinsics.checkNotNullExpressionValue(it, "it");
                if (it.booleanValue()) {
                    InterfaceC3066i<Unit> interfaceC3066i = c3069j;
                    Unit unit = Unit.INSTANCE;
                    Result.Companion companion = Result.INSTANCE;
                    interfaceC3066i.resumeWith(Result.m6055constructorimpl(unit));
                }
            }
        });
        Object m3612u = c3069j.m3612u();
        if (m3612u == IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED()) {
            DebugProbesKt.probeCoroutineSuspended(continuation);
        }
        return m3612u == IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED() ? m3612u : Unit.INSTANCE;
    }
}
