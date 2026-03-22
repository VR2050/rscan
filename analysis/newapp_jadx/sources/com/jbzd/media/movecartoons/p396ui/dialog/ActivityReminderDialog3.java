package com.jbzd.media.movecartoons.p396ui.dialog;

import android.app.Dialog;
import android.content.DialogInterface;
import android.os.Bundle;
import android.view.View;
import android.view.Window;
import android.widget.ImageView;
import androidx.fragment.app.DialogFragment;
import androidx.fragment.app.FragmentManager;
import androidx.recyclerview.widget.RecyclerView;
import com.jbzd.media.movecartoons.bean.response.home.AdBean;
import com.jbzd.media.movecartoons.p396ui.dialog.ActivityReminderDialog3$imageAdAdapter$2;
import com.qnmd.adnnm.da0yzo.R;
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
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p006a.p007a.p008a.p009a.C0846g;
import p005b.p006a.p007a.p008a.p017r.C0917a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p379c.p380a.C3069j;
import p379c.p380a.InterfaceC3066i;
import p429g.p433b.p434a.p438d.InterfaceC4341a;
import p429g.p433b.p434a.p444f.C4346a;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000[\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010 \n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\u0010\u000b\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0002*\u0001\u001d\u0018\u00002\u00020\u0001B\u0015\u0012\f\u0010\u0019\u001a\b\u0012\u0004\u0012\u00020\u00180\u0017¢\u0006\u0004\b(\u0010)J'\u0010\u0007\u001a\u00020\u00062\u0006\u0010\u0003\u001a\u00020\u00022\n\b\u0002\u0010\u0005\u001a\u0004\u0018\u00010\u0004H\u0086@ø\u0001\u0000¢\u0006\u0004\b\u0007\u0010\bJ\u0017\u0010\u000b\u001a\u00020\u00062\u0006\u0010\n\u001a\u00020\tH\u0016¢\u0006\u0004\b\u000b\u0010\fJ\u0019\u0010\u000f\u001a\u00020\u00062\b\u0010\u000e\u001a\u0004\u0018\u00010\rH\u0016¢\u0006\u0004\b\u000f\u0010\u0010J\u000f\u0010\u0011\u001a\u00020\u0006H\u0016¢\u0006\u0004\b\u0011\u0010\u0012J!\u0010\u0015\u001a\u00020\u00062\u0006\u0010\u0014\u001a\u00020\u00132\b\u0010\u000e\u001a\u0004\u0018\u00010\rH\u0016¢\u0006\u0004\b\u0015\u0010\u0016R\u001f\u0010\u0019\u001a\b\u0012\u0004\u0012\u00020\u00180\u00178\u0006@\u0006¢\u0006\f\n\u0004\b\u0019\u0010\u001a\u001a\u0004\b\u001b\u0010\u001cR\u001d\u0010\"\u001a\u00020\u001d8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u001e\u0010\u001f\u001a\u0004\b \u0010!R:\u0010&\u001a&\u0012\f\u0012\n %*\u0004\u0018\u00010$0$ %*\u0012\u0012\f\u0012\n %*\u0004\u0018\u00010$0$\u0018\u00010#0#8\u0002@\u0002X\u0082\u0004¢\u0006\u0006\n\u0004\b&\u0010'\u0082\u0002\u0004\n\u0002\b\u0019¨\u0006,²\u0006\u000e\u0010+\u001a\u00020*8\n@\nX\u008a\u0084\u0002"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/dialog/ActivityReminderDialog3;", "Landroidx/fragment/app/DialogFragment;", "Landroidx/fragment/app/FragmentManager;", "fm", "", "tag", "", "showAsSuspendable", "(Landroidx/fragment/app/FragmentManager;Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;", "Landroid/content/DialogInterface;", "dialog", "onDismiss", "(Landroid/content/DialogInterface;)V", "Landroid/os/Bundle;", "savedInstanceState", "onCreate", "(Landroid/os/Bundle;)V", "onStart", "()V", "Landroid/view/View;", "contentView", "onViewCreated", "(Landroid/view/View;Landroid/os/Bundle;)V", "", "Lcom/jbzd/media/movecartoons/bean/response/home/AdBean;", "bean", "Ljava/util/List;", "getBean", "()Ljava/util/List;", "com/jbzd/media/movecartoons/ui/dialog/ActivityReminderDialog3$imageAdAdapter$2$1", "imageAdAdapter$delegate", "Lkotlin/Lazy;", "getImageAdAdapter", "()Lcom/jbzd/media/movecartoons/ui/dialog/ActivityReminderDialog3$imageAdAdapter$2$1;", "imageAdAdapter", "Lg/b/a/f/a;", "", "kotlin.jvm.PlatformType", "subject", "Lg/b/a/f/a;", "<init>", "(Ljava/util/List;)V", "Landroidx/recyclerview/widget/RecyclerView;", "rv_list_adImg", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class ActivityReminderDialog3 extends DialogFragment {

    @NotNull
    private final List<AdBean> bean;

    /* renamed from: imageAdAdapter$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy imageAdAdapter;
    private final C4346a<Boolean> subject;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    /* JADX WARN: Multi-variable type inference failed */
    public ActivityReminderDialog3(@NotNull List<? extends AdBean> bean) {
        super(R.layout.dialog_activity_reminder);
        Intrinsics.checkNotNullParameter(bean, "bean");
        this.bean = bean;
        this.subject = new C4346a<>();
        this.imageAdAdapter = LazyKt__LazyJVMKt.lazy(new ActivityReminderDialog3$imageAdAdapter$2(this));
    }

    private final ActivityReminderDialog3$imageAdAdapter$2.C36821 getImageAdAdapter() {
        return (ActivityReminderDialog3$imageAdAdapter$2.C36821) this.imageAdAdapter.getValue();
    }

    /* renamed from: onViewCreated$lambda-2, reason: not valid java name */
    private static final RecyclerView m5766onViewCreated$lambda2(Lazy<? extends RecyclerView> lazy) {
        return lazy.getValue();
    }

    public static /* synthetic */ Object showAsSuspendable$default(ActivityReminderDialog3 activityReminderDialog3, FragmentManager fragmentManager, String str, Continuation continuation, int i2, Object obj) {
        if ((i2 & 2) != 0) {
            str = null;
        }
        return activityReminderDialog3.showAsSuspendable(fragmentManager, str, continuation);
    }

    public void _$_clearFindViewByIdCache() {
    }

    @NotNull
    public final List<AdBean> getBean() {
        return this.bean;
    }

    @Override // androidx.fragment.app.DialogFragment, androidx.fragment.app.Fragment
    public void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setStyle(0, R.style.TopScaleDialogStyle);
    }

    @Override // androidx.fragment.app.DialogFragment, android.content.DialogInterface.OnDismissListener
    public void onDismiss(@NotNull DialogInterface dialog) {
        Intrinsics.checkNotNullParameter(dialog, "dialog");
        super.onDismiss(dialog);
        this.subject.onSuccess(Boolean.TRUE);
        Intrinsics.checkNotNullParameter("close_ad", "act");
        LinkedHashMap linkedHashMap = new LinkedHashMap();
        linkedHashMap.put("act", "close_ad");
        C0917a.m221e(C0917a.f372a, "system/doLogs", Object.class, linkedHashMap, C0846g.f248c, null, false, false, null, false, 432);
    }

    @Override // androidx.fragment.app.DialogFragment, androidx.fragment.app.Fragment
    public void onStart() {
        Window window;
        super.onStart();
        Dialog dialog = getDialog();
        if (dialog == null || (window = dialog.getWindow()) == null) {
            return;
        }
        window.setLayout(-1, -1);
    }

    @Override // androidx.fragment.app.Fragment
    public void onViewCreated(@NotNull final View contentView, @Nullable Bundle savedInstanceState) {
        Intrinsics.checkNotNullParameter(contentView, "contentView");
        super.onViewCreated(contentView, savedInstanceState);
        RecyclerView m5766onViewCreated$lambda2 = m5766onViewCreated$lambda2(LazyKt__LazyJVMKt.lazy(new Function0<RecyclerView>() { // from class: com.jbzd.media.movecartoons.ui.dialog.ActivityReminderDialog3$onViewCreated$rv_list_adImg$2
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final RecyclerView invoke() {
                RecyclerView recyclerView = (RecyclerView) contentView.findViewById(R.id.rv_list_adImg);
                Intrinsics.checkNotNull(recyclerView);
                return recyclerView;
            }
        }));
        m5766onViewCreated$lambda2.setAdapter(getImageAdAdapter());
        if (getBean() != null) {
            getImageAdAdapter().setNewData2(getBean());
        }
        m5766onViewCreated$lambda2.setVisibility(0);
        C2354n.m2374A(contentView.findViewById(R.id.iv_cancel), 0L, new Function1<ImageView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.ActivityReminderDialog3$onViewCreated$2
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
                ActivityReminderDialog3.this.dismiss();
            }
        }, 1);
    }

    @Nullable
    public final Object showAsSuspendable(@NotNull FragmentManager fragmentManager, @Nullable String str, @NotNull Continuation<? super Unit> continuation) {
        final C3069j c3069j = new C3069j(IntrinsicsKt__IntrinsicsJvmKt.intercepted(continuation), 1);
        c3069j.m3602A();
        show(fragmentManager, str);
        this.subject.m4908b(new InterfaceC4341a<Boolean>() { // from class: com.jbzd.media.movecartoons.ui.dialog.ActivityReminderDialog3$showAsSuspendable$2$1
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
