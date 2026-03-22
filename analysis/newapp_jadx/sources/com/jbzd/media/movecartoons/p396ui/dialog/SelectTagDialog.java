package com.jbzd.media.movecartoons.p396ui.dialog;

import android.annotation.SuppressLint;
import android.app.Dialog;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.view.WindowManager;
import android.widget.TextView;
import androidx.appcompat.app.AlertDialog;
import androidx.fragment.app.DialogFragment;
import androidx.recyclerview.widget.GridLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.jbzd.media.movecartoons.bean.response.tag.TagBean;
import com.jbzd.media.movecartoons.p396ui.dialog.SelectTagDialog$adapter$2;
import com.jbzd.media.movecartoons.view.GradientRoundCornerButton;
import com.luck.picture.lib.config.PictureConfig;
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

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000_\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\u0010!\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0010\n\u0002\u0018\u0002\n\u0002\b\t\n\u0002\u0018\u0002\n\u0002\b\u0007\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\b\b*\u0001:\b\u0007\u0018\u00002\u00020\u0001BN\u0012\f\u0010\u0019\u001a\b\u0012\u0004\u0012\u00020\u00110\u0010\u0012\f\u0010+\u001a\b\u0012\u0004\u0012\u00020\u00110\u0010\u0012)\b\u0002\u0010\u0015\u001a#\u0012\u0019\u0012\u0017\u0012\u0004\u0012\u00020\u00110\u0010¢\u0006\f\b\u0012\u0012\b\b\u0013\u0012\u0004\b\b(\u0014\u0012\u0004\u0012\u00020\f0\u000f¢\u0006\u0004\b?\u0010@J\u000f\u0010\u0003\u001a\u00020\u0002H\u0002¢\u0006\u0004\b\u0003\u0010\u0004J\u0019\u0010\b\u001a\u00020\u00072\b\u0010\u0006\u001a\u0004\u0018\u00010\u0005H\u0016¢\u0006\u0004\b\b\u0010\tJ!\u0010\r\u001a\u00020\f2\u0006\u0010\u000b\u001a\u00020\n2\b\u0010\u0006\u001a\u0004\u0018\u00010\u0005H\u0016¢\u0006\u0004\b\r\u0010\u000eR:\u0010\u0015\u001a#\u0012\u0019\u0012\u0017\u0012\u0004\u0012\u00020\u00110\u0010¢\u0006\f\b\u0012\u0012\b\b\u0013\u0012\u0004\b\b(\u0014\u0012\u0004\u0012\u00020\f0\u000f8\u0006@\u0006¢\u0006\f\n\u0004\b\u0015\u0010\u0016\u001a\u0004\b\u0017\u0010\u0018R\u001f\u0010\u0019\u001a\b\u0012\u0004\u0012\u00020\u00110\u00108\u0006@\u0006¢\u0006\f\n\u0004\b\u0019\u0010\u001a\u001a\u0004\b\u001b\u0010\u001cR%\u0010\"\u001a\n \u001d*\u0004\u0018\u00010\n0\n8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u001e\u0010\u001f\u001a\u0004\b \u0010!R\u001d\u0010'\u001a\u00020#8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b$\u0010\u001f\u001a\u0004\b%\u0010&R\u001d\u0010*\u001a\u00020\n8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b(\u0010\u001f\u001a\u0004\b)\u0010!R\u001f\u0010+\u001a\b\u0012\u0004\u0012\u00020\u00110\u00108\u0006@\u0006¢\u0006\f\n\u0004\b+\u0010\u001a\u001a\u0004\b,\u0010\u001cR\u001d\u00101\u001a\u00020-8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b.\u0010\u001f\u001a\u0004\b/\u00100R\u001d\u00104\u001a\u00020\u00028B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b2\u0010\u001f\u001a\u0004\b3\u0010\u0004R\u001d\u00109\u001a\u0002058B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b6\u0010\u001f\u001a\u0004\b7\u00108R\u001d\u0010>\u001a\u00020:8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b;\u0010\u001f\u001a\u0004\b<\u0010=¨\u0006A"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/dialog/SelectTagDialog;", "Landroidx/fragment/app/DialogFragment;", "Landroidx/appcompat/app/AlertDialog;", "createDialog", "()Landroidx/appcompat/app/AlertDialog;", "Landroid/os/Bundle;", "savedInstanceState", "Landroid/app/Dialog;", "onCreateDialog", "(Landroid/os/Bundle;)Landroid/app/Dialog;", "Landroid/view/View;", "view", "", "onViewCreated", "(Landroid/view/View;Landroid/os/Bundle;)V", "Lkotlin/Function1;", "", "Lcom/jbzd/media/movecartoons/bean/response/tag/TagBean;", "Lkotlin/ParameterName;", "name", "result", "enterBlock", "Lkotlin/jvm/functions/Function1;", "getEnterBlock", "()Lkotlin/jvm/functions/Function1;", PictureConfig.EXTRA_SELECT_LIST, "Ljava/util/List;", "getSelectList", "()Ljava/util/List;", "kotlin.jvm.PlatformType", "contentView$delegate", "Lkotlin/Lazy;", "getContentView", "()Landroid/view/View;", "contentView", "Landroidx/recyclerview/widget/RecyclerView;", "rvContent$delegate", "getRvContent", "()Landroidx/recyclerview/widget/RecyclerView;", "rvContent", "outsideView$delegate", "getOutsideView", "outsideView", "allList", "getAllList", "Landroid/widget/TextView;", "tvTitle$delegate", "getTvTitle", "()Landroid/widget/TextView;", "tvTitle", "alertDialog$delegate", "getAlertDialog", "alertDialog", "Lcom/jbzd/media/movecartoons/view/GradientRoundCornerButton;", "btnSave$delegate", "getBtnSave", "()Lcom/jbzd/media/movecartoons/view/GradientRoundCornerButton;", "btnSave", "com/jbzd/media/movecartoons/ui/dialog/SelectTagDialog$adapter$2$1", "adapter$delegate", "getAdapter", "()Lcom/jbzd/media/movecartoons/ui/dialog/SelectTagDialog$adapter$2$1;", "adapter", "<init>", "(Ljava/util/List;Ljava/util/List;Lkotlin/jvm/functions/Function1;)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
@SuppressLint({"SetTextI18n"})
/* loaded from: classes2.dex */
public final class SelectTagDialog extends DialogFragment {

    /* renamed from: adapter$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy adapter;

    /* renamed from: alertDialog$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy alertDialog;

    @NotNull
    private final List<TagBean> allList;

    /* renamed from: btnSave$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy btnSave;

    /* renamed from: contentView$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy contentView;

    @NotNull
    private final Function1<List<TagBean>, Unit> enterBlock;

    /* renamed from: outsideView$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy outsideView;

    /* renamed from: rvContent$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy rvContent;

    @NotNull
    private final List<TagBean> selectList;

    /* renamed from: tvTitle$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tvTitle;

    public /* synthetic */ SelectTagDialog(List list, List list2, Function1 function1, int i2, DefaultConstructorMarker defaultConstructorMarker) {
        this(list, list2, (i2 & 4) != 0 ? new Function1<List<TagBean>, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.SelectTagDialog.1
            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(List<TagBean> list3) {
                invoke2(list3);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull List<TagBean> it) {
                Intrinsics.checkNotNullParameter(it, "it");
            }
        } : function1);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final AlertDialog createDialog() {
        C2354n.m2374A(getOutsideView(), 0L, new Function1<View, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.SelectTagDialog$createDialog$1
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
                Intrinsics.checkNotNullParameter(it, "it");
                SelectTagDialog.this.dismissAllowingStateLoss();
            }
        }, 1);
        C2354n.m2374A(getBtnSave(), 0L, new Function1<GradientRoundCornerButton, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.SelectTagDialog$createDialog$2
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
                SelectTagDialog.this.getEnterBlock().invoke(SelectTagDialog.this.getSelectList());
                SelectTagDialog.this.dismissAllowingStateLoss();
            }
        }, 1);
        RecyclerView rvContent = getRvContent();
        rvContent.setAdapter(getAdapter());
        rvContent.setLayoutManager(new GridLayoutManager(requireContext(), 3));
        AlertDialog m624j0 = C1499a.m624j0(new AlertDialog.Builder(requireContext(), 2131951873), getContentView(), "Builder(requireContext(), R.style.Dialog_FullScreen_BottomIn)\n            .setView(contentView)\n            .create()");
        TextView tvTitle = getTvTitle();
        StringBuilder m586H = C1499a.m586H("选择喜欢的标签(");
        m586H.append(this.selectList.size());
        m586H.append("/3)");
        tvTitle.setText(m586H.toString());
        getAdapter().setNewData(this.allList);
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

    private final SelectTagDialog$adapter$2.C37321 getAdapter() {
        return (SelectTagDialog$adapter$2.C37321) this.adapter.getValue();
    }

    private final AlertDialog getAlertDialog() {
        return (AlertDialog) this.alertDialog.getValue();
    }

    private final GradientRoundCornerButton getBtnSave() {
        return (GradientRoundCornerButton) this.btnSave.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final View getContentView() {
        return (View) this.contentView.getValue();
    }

    private final View getOutsideView() {
        return (View) this.outsideView.getValue();
    }

    private final RecyclerView getRvContent() {
        return (RecyclerView) this.rvContent.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final TextView getTvTitle() {
        return (TextView) this.tvTitle.getValue();
    }

    public void _$_clearFindViewByIdCache() {
    }

    @NotNull
    public final List<TagBean> getAllList() {
        return this.allList;
    }

    @NotNull
    public final Function1<List<TagBean>, Unit> getEnterBlock() {
        return this.enterBlock;
    }

    @NotNull
    public final List<TagBean> getSelectList() {
        return this.selectList;
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

    /* JADX WARN: Multi-variable type inference failed */
    public SelectTagDialog(@NotNull List<TagBean> selectList, @NotNull List<TagBean> allList, @NotNull Function1<? super List<TagBean>, Unit> enterBlock) {
        Intrinsics.checkNotNullParameter(selectList, "selectList");
        Intrinsics.checkNotNullParameter(allList, "allList");
        Intrinsics.checkNotNullParameter(enterBlock, "enterBlock");
        this.selectList = selectList;
        this.allList = allList;
        this.enterBlock = enterBlock;
        this.contentView = LazyKt__LazyJVMKt.lazy(new Function0<View>() { // from class: com.jbzd.media.movecartoons.ui.dialog.SelectTagDialog$contentView$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            public final View invoke() {
                return LayoutInflater.from(SelectTagDialog.this.getContext()).inflate(R.layout.dialog_select_tag, (ViewGroup) null);
            }
        });
        this.outsideView = LazyKt__LazyJVMKt.lazy(new Function0<View>() { // from class: com.jbzd.media.movecartoons.ui.dialog.SelectTagDialog$outsideView$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final View invoke() {
                View contentView;
                contentView = SelectTagDialog.this.getContentView();
                View findViewById = contentView.findViewById(R.id.outside_view);
                Objects.requireNonNull(findViewById, "null cannot be cast to non-null type android.view.View");
                return findViewById;
            }
        });
        this.btnSave = LazyKt__LazyJVMKt.lazy(new Function0<GradientRoundCornerButton>() { // from class: com.jbzd.media.movecartoons.ui.dialog.SelectTagDialog$btnSave$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final GradientRoundCornerButton invoke() {
                View contentView;
                contentView = SelectTagDialog.this.getContentView();
                View findViewById = contentView.findViewById(R.id.btnSave);
                Objects.requireNonNull(findViewById, "null cannot be cast to non-null type com.jbzd.media.movecartoons.view.GradientRoundCornerButton");
                return (GradientRoundCornerButton) findViewById;
            }
        });
        this.tvTitle = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.dialog.SelectTagDialog$tvTitle$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final TextView invoke() {
                View contentView;
                contentView = SelectTagDialog.this.getContentView();
                View findViewById = contentView.findViewById(R.id.tvTitle);
                Objects.requireNonNull(findViewById, "null cannot be cast to non-null type android.widget.TextView");
                return (TextView) findViewById;
            }
        });
        this.rvContent = LazyKt__LazyJVMKt.lazy(new Function0<RecyclerView>() { // from class: com.jbzd.media.movecartoons.ui.dialog.SelectTagDialog$rvContent$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final RecyclerView invoke() {
                View contentView;
                contentView = SelectTagDialog.this.getContentView();
                View findViewById = contentView.findViewById(R.id.rv_content);
                Objects.requireNonNull(findViewById, "null cannot be cast to non-null type androidx.recyclerview.widget.RecyclerView");
                return (RecyclerView) findViewById;
            }
        });
        this.alertDialog = LazyKt__LazyJVMKt.lazy(new Function0<AlertDialog>() { // from class: com.jbzd.media.movecartoons.ui.dialog.SelectTagDialog$alertDialog$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final AlertDialog invoke() {
                AlertDialog createDialog;
                createDialog = SelectTagDialog.this.createDialog();
                return createDialog;
            }
        });
        this.adapter = LazyKt__LazyJVMKt.lazy(new SelectTagDialog$adapter$2(this));
    }
}
