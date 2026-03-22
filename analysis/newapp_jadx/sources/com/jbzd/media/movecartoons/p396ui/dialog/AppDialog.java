package com.jbzd.media.movecartoons.p396ui.dialog;

import android.app.Dialog;
import android.content.DialogInterface;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import androidx.appcompat.app.AlertDialog;
import androidx.fragment.app.DialogFragment;
import androidx.fragment.app.FragmentManager;
import androidx.recyclerview.widget.GridLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.jbzd.media.movecartoons.bean.response.AppItemNew;
import com.jbzd.media.movecartoons.p396ui.dialog.AppDialog$mAdapter$2;
import com.qnmd.adnnm.da0yzo.R;
import com.qunidayede.supportlibrary.utils.GridItemDecoration;
import java.util.LinkedHashMap;
import java.util.List;
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
import kotlin.jvm.internal.TypeIntrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p006a.p007a.p008a.p009a.C0846g;
import p005b.p006a.p007a.p008a.p017r.C0917a;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p379c.p380a.C3069j;
import p379c.p380a.InterfaceC3066i;
import p429g.p433b.p434a.p438d.InterfaceC4341a;
import p429g.p433b.p434a.p444f.C4346a;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000a\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\t\n\u0002\u0010 \n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\u0010\u000b\n\u0002\b\b*\u0001%\u0018\u00002\u00020\u0001B\u0015\u0012\f\u0010!\u001a\b\u0012\u0004\u0012\u00020 0\u001f¢\u0006\u0004\b1\u00102J\u000f\u0010\u0003\u001a\u00020\u0002H\u0002¢\u0006\u0004\b\u0003\u0010\u0004J'\u0010\n\u001a\u00020\t2\u0006\u0010\u0006\u001a\u00020\u00052\n\b\u0002\u0010\b\u001a\u0004\u0018\u00010\u0007H\u0086@ø\u0001\u0000¢\u0006\u0004\b\n\u0010\u000bJ\u0017\u0010\u000e\u001a\u00020\t2\u0006\u0010\r\u001a\u00020\fH\u0016¢\u0006\u0004\b\u000e\u0010\u000fJ\u0019\u0010\u0013\u001a\u00020\u00122\b\u0010\u0011\u001a\u0004\u0018\u00010\u0010H\u0016¢\u0006\u0004\b\u0013\u0010\u0014J!\u0010\u0017\u001a\u00020\t2\u0006\u0010\u0016\u001a\u00020\u00152\b\u0010\u0011\u001a\u0004\u0018\u00010\u0010H\u0016¢\u0006\u0004\b\u0017\u0010\u0018R%\u0010\u001e\u001a\n \u0019*\u0004\u0018\u00010\u00150\u00158B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u001a\u0010\u001b\u001a\u0004\b\u001c\u0010\u001dR\u001f\u0010!\u001a\b\u0012\u0004\u0012\u00020 0\u001f8\u0006@\u0006¢\u0006\f\n\u0004\b!\u0010\"\u001a\u0004\b#\u0010$R\u001d\u0010)\u001a\u00020%8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b&\u0010\u001b\u001a\u0004\b'\u0010(R:\u0010,\u001a&\u0012\f\u0012\n \u0019*\u0004\u0018\u00010+0+ \u0019*\u0012\u0012\f\u0012\n \u0019*\u0004\u0018\u00010+0+\u0018\u00010*0*8\u0002@\u0002X\u0082\u0004¢\u0006\u0006\n\u0004\b,\u0010-R\u001d\u00100\u001a\u00020\u00028B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b.\u0010\u001b\u001a\u0004\b/\u0010\u0004\u0082\u0002\u0004\n\u0002\b\u0019¨\u00063"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/dialog/AppDialog;", "Landroidx/fragment/app/DialogFragment;", "Landroidx/appcompat/app/AlertDialog;", "createDialog", "()Landroidx/appcompat/app/AlertDialog;", "Landroidx/fragment/app/FragmentManager;", "fm", "", "tag", "", "showAsSuspendable", "(Landroidx/fragment/app/FragmentManager;Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;", "Landroid/content/DialogInterface;", "dialog", "onDismiss", "(Landroid/content/DialogInterface;)V", "Landroid/os/Bundle;", "savedInstanceState", "Landroid/app/Dialog;", "onCreateDialog", "(Landroid/os/Bundle;)Landroid/app/Dialog;", "Landroid/view/View;", "view", "onViewCreated", "(Landroid/view/View;Landroid/os/Bundle;)V", "kotlin.jvm.PlatformType", "contentView$delegate", "Lkotlin/Lazy;", "getContentView", "()Landroid/view/View;", "contentView", "", "Lcom/jbzd/media/movecartoons/bean/response/AppItemNew;", "data", "Ljava/util/List;", "getData", "()Ljava/util/List;", "com/jbzd/media/movecartoons/ui/dialog/AppDialog$mAdapter$2$1", "mAdapter$delegate", "getMAdapter", "()Lcom/jbzd/media/movecartoons/ui/dialog/AppDialog$mAdapter$2$1;", "mAdapter", "Lg/b/a/f/a;", "", "subject", "Lg/b/a/f/a;", "alertDialog$delegate", "getAlertDialog", "alertDialog", "<init>", "(Ljava/util/List;)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class AppDialog extends DialogFragment {

    /* renamed from: alertDialog$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy alertDialog;

    /* renamed from: contentView$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy contentView;

    @NotNull
    private final List<AppItemNew> data;

    /* renamed from: mAdapter$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mAdapter;
    private final C4346a<Boolean> subject;

    /* JADX WARN: Multi-variable type inference failed */
    public AppDialog(@NotNull List<? extends AppItemNew> data) {
        Intrinsics.checkNotNullParameter(data, "data");
        this.data = data;
        this.subject = new C4346a<>();
        this.contentView = LazyKt__LazyJVMKt.lazy(new Function0<View>() { // from class: com.jbzd.media.movecartoons.ui.dialog.AppDialog$contentView$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            public final View invoke() {
                return LayoutInflater.from(AppDialog.this.getContext()).inflate(R.layout.dialog_app, (ViewGroup) null);
            }
        });
        this.alertDialog = LazyKt__LazyJVMKt.lazy(new Function0<AlertDialog>() { // from class: com.jbzd.media.movecartoons.ui.dialog.AppDialog$alertDialog$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final AlertDialog invoke() {
                AlertDialog createDialog;
                createDialog = AppDialog.this.createDialog();
                return createDialog;
            }
        });
        this.mAdapter = LazyKt__LazyJVMKt.lazy(new AppDialog$mAdapter$2(this));
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final AlertDialog createDialog() {
        AlertDialog m624j0 = C1499a.m624j0(new AlertDialog.Builder(requireContext(), R.style.AppDialogStyle), getContentView(), "Builder(requireContext(), R.style.AppDialogStyle)\n            .setView(contentView)\n            .create()");
        C2354n.m2374A(getContentView().findViewById(R.id.iv_cancel), 0L, new Function1<ImageView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.AppDialog$createDialog$1
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(ImageView imageView) {
                invoke2(imageView);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(ImageView imageView) {
                AppDialog.this.dismissAllowingStateLoss();
            }
        }, 1);
        RecyclerView recyclerView = (RecyclerView) getContentView().findViewById(R.id.f13003rv);
        recyclerView.setAdapter(getMAdapter());
        recyclerView.setLayoutManager(new GridLayoutManager(requireContext(), 5));
        if (recyclerView.getItemDecorationCount() == 0) {
            GridItemDecoration.C4053a c4053a = new GridItemDecoration.C4053a(recyclerView.getContext());
            c4053a.f10336d = C1499a.m638x(c4053a, R.color.transparent, recyclerView, 6.0d);
            c4053a.f10337e = C2354n.m2437V(recyclerView.getContext(), 6.0d);
            c4053a.f10339g = false;
            c4053a.f10340h = false;
            c4053a.f10338f = false;
            C1499a.m604Z(c4053a, recyclerView);
        }
        getMAdapter().setData$com_github_CymChad_brvah(TypeIntrinsics.asMutableList(this.data));
        return m624j0;
    }

    private final AlertDialog getAlertDialog() {
        return (AlertDialog) this.alertDialog.getValue();
    }

    private final View getContentView() {
        return (View) this.contentView.getValue();
    }

    private final AppDialog$mAdapter$2.C36831 getMAdapter() {
        return (AppDialog$mAdapter$2.C36831) this.mAdapter.getValue();
    }

    public static /* synthetic */ Object showAsSuspendable$default(AppDialog appDialog, FragmentManager fragmentManager, String str, Continuation continuation, int i2, Object obj) {
        if ((i2 & 2) != 0) {
            str = null;
        }
        return appDialog.showAsSuspendable(fragmentManager, str, continuation);
    }

    public void _$_clearFindViewByIdCache() {
    }

    @NotNull
    public final List<AppItemNew> getData() {
        return this.data;
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
        this.subject.onSuccess(Boolean.TRUE);
        Intrinsics.checkNotNullParameter("close_appstore", "act");
        LinkedHashMap linkedHashMap = new LinkedHashMap();
        linkedHashMap.put("act", "close_appstore");
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
        this.subject.m4908b(new InterfaceC4341a<Boolean>() { // from class: com.jbzd.media.movecartoons.ui.dialog.AppDialog$showAsSuspendable$2$1
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
