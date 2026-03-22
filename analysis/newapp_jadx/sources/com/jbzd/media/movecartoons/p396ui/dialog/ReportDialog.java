package com.jbzd.media.movecartoons.p396ui.dialog;

import android.app.Dialog;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.view.WindowManager;
import androidx.appcompat.app.AlertDialog;
import androidx.fragment.app.DialogFragment;
import androidx.recyclerview.widget.RecyclerView;
import com.google.android.flexbox.FlexboxLayoutManager;
import com.jbzd.media.movecartoons.p396ui.dialog.ReportDialog$adapter$2;
import com.jbzd.media.movecartoons.view.GradientRoundCornerButton;
import com.qnmd.adnnm.da0yzo.R;
import java.util.List;
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
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000_\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\u0010\b\n\u0002\u0018\u0002\n\u0002\b\u0012\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0007\n\u0002\u0010!\n\u0002\u0010\u000e\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\n*\u0001$\u0018\u00002\u00020\u0001B:\u0012\f\u00103\u001a\b\u0012\u0004\u0012\u00020201\u0012#\b\u0002\u0010\u0014\u001a\u001d\u0012\u0013\u0012\u00110\u0010¢\u0006\f\b\u0011\u0012\b\b\u0012\u0012\u0004\b\b(\u0013\u0012\u0004\u0012\u00020\f0\u000f¢\u0006\u0004\b?\u0010@J\u000f\u0010\u0003\u001a\u00020\u0002H\u0002¢\u0006\u0004\b\u0003\u0010\u0004J\u0019\u0010\b\u001a\u00020\u00072\b\u0010\u0006\u001a\u0004\u0018\u00010\u0005H\u0016¢\u0006\u0004\b\b\u0010\tJ!\u0010\r\u001a\u00020\f2\u0006\u0010\u000b\u001a\u00020\n2\b\u0010\u0006\u001a\u0004\u0018\u00010\u0005H\u0016¢\u0006\u0004\b\r\u0010\u000eR4\u0010\u0014\u001a\u001d\u0012\u0013\u0012\u00110\u0010¢\u0006\f\b\u0011\u0012\b\b\u0012\u0012\u0004\b\b(\u0013\u0012\u0004\u0012\u00020\f0\u000f8\u0006@\u0006¢\u0006\f\n\u0004\b\u0014\u0010\u0015\u001a\u0004\b\u0016\u0010\u0017R%\u0010\u001d\u001a\n \u0018*\u0004\u0018\u00010\n0\n8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u0019\u0010\u001a\u001a\u0004\b\u001b\u0010\u001cR\"\u0010\u001e\u001a\u00020\u00108\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\u001e\u0010\u001f\u001a\u0004\b \u0010!\"\u0004\b\"\u0010#R\u001d\u0010(\u001a\u00020$8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b%\u0010\u001a\u001a\u0004\b&\u0010'R\u001d\u0010-\u001a\u00020)8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b*\u0010\u001a\u001a\u0004\b+\u0010,R\u001d\u00100\u001a\u00020)8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b.\u0010\u001a\u001a\u0004\b/\u0010,R\u001f\u00103\u001a\b\u0012\u0004\u0012\u000202018\u0006@\u0006¢\u0006\f\n\u0004\b3\u00104\u001a\u0004\b5\u00106R\u001d\u0010;\u001a\u0002078B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b8\u0010\u001a\u001a\u0004\b9\u0010:R\u001d\u0010>\u001a\u00020\u00028B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b<\u0010\u001a\u001a\u0004\b=\u0010\u0004¨\u0006A"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/dialog/ReportDialog;", "Landroidx/fragment/app/DialogFragment;", "Landroidx/appcompat/app/AlertDialog;", "createDialog", "()Landroidx/appcompat/app/AlertDialog;", "Landroid/os/Bundle;", "savedInstanceState", "Landroid/app/Dialog;", "onCreateDialog", "(Landroid/os/Bundle;)Landroid/app/Dialog;", "Landroid/view/View;", "view", "", "onViewCreated", "(Landroid/view/View;Landroid/os/Bundle;)V", "Lkotlin/Function1;", "", "Lkotlin/ParameterName;", "name", "position", "submit", "Lkotlin/jvm/functions/Function1;", "getSubmit", "()Lkotlin/jvm/functions/Function1;", "kotlin.jvm.PlatformType", "contentView$delegate", "Lkotlin/Lazy;", "getContentView", "()Landroid/view/View;", "contentView", "selectIndex", "I", "getSelectIndex", "()I", "setSelectIndex", "(I)V", "com/jbzd/media/movecartoons/ui/dialog/ReportDialog$adapter$2$1", "adapter$delegate", "getAdapter", "()Lcom/jbzd/media/movecartoons/ui/dialog/ReportDialog$adapter$2$1;", "adapter", "Lcom/jbzd/media/movecartoons/view/GradientRoundCornerButton;", "btnClose$delegate", "getBtnClose", "()Lcom/jbzd/media/movecartoons/view/GradientRoundCornerButton;", "btnClose", "btnBuy$delegate", "getBtnBuy", "btnBuy", "", "", "list", "Ljava/util/List;", "getList", "()Ljava/util/List;", "Landroidx/recyclerview/widget/RecyclerView;", "rvContent$delegate", "getRvContent", "()Landroidx/recyclerview/widget/RecyclerView;", "rvContent", "alertDialog$delegate", "getAlertDialog", "alertDialog", "<init>", "(Ljava/util/List;Lkotlin/jvm/functions/Function1;)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class ReportDialog extends DialogFragment {

    /* renamed from: adapter$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy adapter;

    /* renamed from: alertDialog$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy alertDialog;

    /* renamed from: btnBuy$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy btnBuy;

    /* renamed from: btnClose$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy btnClose;

    /* renamed from: contentView$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy contentView;

    @NotNull
    private final List<String> list;

    /* renamed from: rvContent$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy rvContent;
    private int selectIndex;

    @NotNull
    private final Function1<Integer, Unit> submit;

    public /* synthetic */ ReportDialog(List list, Function1 function1, int i2, DefaultConstructorMarker defaultConstructorMarker) {
        this(list, (i2 & 2) != 0 ? new Function1<Integer, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.ReportDialog.1
            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(Integer num) {
                invoke(num.intValue());
                return Unit.INSTANCE;
            }

            public final void invoke(int i3) {
            }
        } : function1);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final AlertDialog createDialog() {
        AlertDialog m624j0 = C1499a.m624j0(new AlertDialog.Builder(requireContext(), R.style.dialog_center), getContentView(), "Builder(requireContext(), R.style.dialog_center)\n            .setView(contentView)\n            .create()");
        C2354n.m2374A(getBtnBuy(), 0L, new Function1<GradientRoundCornerButton, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.ReportDialog$createDialog$1
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(GradientRoundCornerButton gradientRoundCornerButton) {
                invoke2(gradientRoundCornerButton);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull GradientRoundCornerButton it) {
                Intrinsics.checkNotNullParameter(it, "it");
                if (ReportDialog.this.getSelectIndex() == -1) {
                    C2354n.m2379B1("请选择举报类型");
                } else {
                    ReportDialog.this.getSubmit().invoke(Integer.valueOf(ReportDialog.this.getSelectIndex()));
                    ReportDialog.this.dismissAllowingStateLoss();
                }
            }
        }, 1);
        RecyclerView rvContent = getRvContent();
        FlexboxLayoutManager flexboxLayoutManager = new FlexboxLayoutManager(rvContent.getContext());
        flexboxLayoutManager.m4176y(1);
        flexboxLayoutManager.m4175x(0);
        Unit unit = Unit.INSTANCE;
        rvContent.setLayoutManager(flexboxLayoutManager);
        rvContent.setAdapter(getAdapter());
        getAdapter().setNewData(this.list);
        C2354n.m2374A(getBtnClose(), 0L, new Function1<GradientRoundCornerButton, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.ReportDialog$createDialog$3
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(GradientRoundCornerButton gradientRoundCornerButton) {
                invoke2(gradientRoundCornerButton);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull GradientRoundCornerButton it) {
                Intrinsics.checkNotNullParameter(it, "it");
                ReportDialog.this.dismissAllowingStateLoss();
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

    private final ReportDialog$adapter$2.C37261 getAdapter() {
        return (ReportDialog$adapter$2.C37261) this.adapter.getValue();
    }

    private final AlertDialog getAlertDialog() {
        return (AlertDialog) this.alertDialog.getValue();
    }

    private final GradientRoundCornerButton getBtnBuy() {
        return (GradientRoundCornerButton) this.btnBuy.getValue();
    }

    private final GradientRoundCornerButton getBtnClose() {
        return (GradientRoundCornerButton) this.btnClose.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final View getContentView() {
        return (View) this.contentView.getValue();
    }

    private final RecyclerView getRvContent() {
        return (RecyclerView) this.rvContent.getValue();
    }

    public void _$_clearFindViewByIdCache() {
    }

    @NotNull
    public final List<String> getList() {
        return this.list;
    }

    public final int getSelectIndex() {
        return this.selectIndex;
    }

    @NotNull
    public final Function1<Integer, Unit> getSubmit() {
        return this.submit;
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

    public final void setSelectIndex(int i2) {
        this.selectIndex = i2;
    }

    /* JADX WARN: Multi-variable type inference failed */
    public ReportDialog(@NotNull List<String> list, @NotNull Function1<? super Integer, Unit> submit) {
        Intrinsics.checkNotNullParameter(list, "list");
        Intrinsics.checkNotNullParameter(submit, "submit");
        this.list = list;
        this.submit = submit;
        this.contentView = LazyKt__LazyJVMKt.lazy(new Function0<View>() { // from class: com.jbzd.media.movecartoons.ui.dialog.ReportDialog$contentView$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            public final View invoke() {
                return LayoutInflater.from(ReportDialog.this.getContext()).inflate(R.layout.dialog_post_report, (ViewGroup) null);
            }
        });
        this.rvContent = LazyKt__LazyJVMKt.lazy(new Function0<RecyclerView>() { // from class: com.jbzd.media.movecartoons.ui.dialog.ReportDialog$rvContent$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final RecyclerView invoke() {
                View contentView;
                contentView = ReportDialog.this.getContentView();
                View findViewById = contentView.findViewById(R.id.rv_content);
                Objects.requireNonNull(findViewById, "null cannot be cast to non-null type androidx.recyclerview.widget.RecyclerView");
                return (RecyclerView) findViewById;
            }
        });
        this.btnBuy = LazyKt__LazyJVMKt.lazy(new Function0<GradientRoundCornerButton>() { // from class: com.jbzd.media.movecartoons.ui.dialog.ReportDialog$btnBuy$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final GradientRoundCornerButton invoke() {
                View contentView;
                contentView = ReportDialog.this.getContentView();
                View findViewById = contentView.findViewById(R.id.vip);
                Objects.requireNonNull(findViewById, "null cannot be cast to non-null type com.jbzd.media.movecartoons.view.GradientRoundCornerButton");
                return (GradientRoundCornerButton) findViewById;
            }
        });
        this.btnClose = LazyKt__LazyJVMKt.lazy(new Function0<GradientRoundCornerButton>() { // from class: com.jbzd.media.movecartoons.ui.dialog.ReportDialog$btnClose$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final GradientRoundCornerButton invoke() {
                View contentView;
                contentView = ReportDialog.this.getContentView();
                View findViewById = contentView.findViewById(R.id.close);
                Objects.requireNonNull(findViewById, "null cannot be cast to non-null type com.jbzd.media.movecartoons.view.GradientRoundCornerButton");
                return (GradientRoundCornerButton) findViewById;
            }
        });
        this.alertDialog = LazyKt__LazyJVMKt.lazy(new Function0<AlertDialog>() { // from class: com.jbzd.media.movecartoons.ui.dialog.ReportDialog$alertDialog$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final AlertDialog invoke() {
                AlertDialog createDialog;
                createDialog = ReportDialog.this.createDialog();
                return createDialog;
            }
        });
        this.selectIndex = -1;
        this.adapter = LazyKt__LazyJVMKt.lazy(new ReportDialog$adapter$2(this));
    }
}
