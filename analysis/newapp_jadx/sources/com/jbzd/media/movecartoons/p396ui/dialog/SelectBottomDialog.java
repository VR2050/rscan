package com.jbzd.media.movecartoons.p396ui.dialog;

import android.app.Dialog;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.view.WindowManager;
import android.widget.FrameLayout;
import android.widget.TextView;
import androidx.annotation.LayoutRes;
import androidx.appcompat.app.AlertDialog;
import androidx.exifinterface.media.ExifInterface;
import androidx.fragment.app.DialogFragment;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.chad.library.adapter.base.BaseQuickAdapter;
import com.chad.library.adapter.base.viewholder.BaseViewHolder;
import com.jbzd.media.movecartoons.view.XDividerItemDecoration;
import com.qnmd.adnnm.da0yzo.R;
import java.util.ArrayList;
import java.util.Objects;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000r\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u000b\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0010\n\u0002\u0018\u0002\n\u0002\b\t\b&\u0018\u0000*\u0004\b\u0000\u0010\u00012\u00020\u0002B\u0007¢\u0006\u0004\bA\u0010'J\u000f\u0010\u0004\u001a\u00020\u0003H\u0002¢\u0006\u0004\b\u0004\u0010\u0005J\u000f\u0010\u0007\u001a\u00020\u0006H'¢\u0006\u0004\b\u0007\u0010\bJ\u001f\u0010\r\u001a\u00020\f2\u0006\u0010\n\u001a\u00020\t2\u0006\u0010\u000b\u001a\u00028\u0000H&¢\u0006\u0004\b\r\u0010\u000eJ\u001f\u0010\u0011\u001a\u0012\u0012\u0004\u0012\u00028\u00000\u000fj\b\u0012\u0004\u0012\u00028\u0000`\u0010H&¢\u0006\u0004\b\u0011\u0010\u0012J\u000f\u0010\u0014\u001a\u00020\u0013H\u0016¢\u0006\u0004\b\u0014\u0010\u0015J\u000f\u0010\u0016\u001a\u00020\u0006H\u0016¢\u0006\u0004\b\u0016\u0010\bJ3\u0010\u001c\u001a\u00020\f2\u0012\u0010\u0018\u001a\u000e\u0012\u0004\u0012\u00028\u0000\u0012\u0004\u0012\u00020\t0\u00172\u0006\u0010\u001a\u001a\u00020\u00192\u0006\u0010\u001b\u001a\u00020\u0006H\u0016¢\u0006\u0004\b\u001c\u0010\u001dJ\r\u0010\u001f\u001a\u00020\u001e¢\u0006\u0004\b\u001f\u0010 J\u0019\u0010$\u001a\u00020#2\b\u0010\"\u001a\u0004\u0018\u00010!H\u0016¢\u0006\u0004\b$\u0010%J\u000f\u0010&\u001a\u00020\fH\u0016¢\u0006\u0004\b&\u0010'R\u001d\u0010-\u001a\u00020(8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b)\u0010*\u001a\u0004\b+\u0010,R%\u00102\u001a\n .*\u0004\u0018\u00010\u00190\u00198B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b/\u0010*\u001a\u0004\b0\u00101R\u001d\u00105\u001a\u00020\u00038B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b3\u0010*\u001a\u0004\b4\u0010\u0005R)\u0010\u0018\u001a\u000e\u0012\u0004\u0012\u00028\u0000\u0012\u0004\u0012\u00020\t0\u00178B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b6\u0010*\u001a\u0004\b7\u00108R\u001d\u0010=\u001a\u0002098B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b:\u0010*\u001a\u0004\b;\u0010<R\u001d\u0010@\u001a\u00020\u00198B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b>\u0010*\u001a\u0004\b?\u00101¨\u0006B"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/dialog/SelectBottomDialog;", ExifInterface.GPS_DIRECTION_TRUE, "Landroidx/fragment/app/DialogFragment;", "Landroidx/appcompat/app/AlertDialog;", "createDialog", "()Landroidx/appcompat/app/AlertDialog;", "", "getItemLayoutId", "()I", "Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;", "helper", "item", "", "bindItem", "(Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;Ljava/lang/Object;)V", "Ljava/util/ArrayList;", "Lkotlin/collections/ArrayList;", "getData", "()Ljava/util/ArrayList;", "", "getShowCancel", "()Z", "getBg", "Lcom/chad/library/adapter/base/BaseQuickAdapter;", "adapter", "Landroid/view/View;", "view", "position", "onItemClick", "(Lcom/chad/library/adapter/base/BaseQuickAdapter;Landroid/view/View;I)V", "Landroidx/recyclerview/widget/RecyclerView$ItemDecoration;", "getItemDecoration", "()Landroidx/recyclerview/widget/RecyclerView$ItemDecoration;", "Landroid/os/Bundle;", "savedInstanceState", "Landroid/app/Dialog;", "onCreateDialog", "(Landroid/os/Bundle;)Landroid/app/Dialog;", "onStart", "()V", "Landroidx/recyclerview/widget/RecyclerView;", "rvContent$delegate", "Lkotlin/Lazy;", "getRvContent", "()Landroidx/recyclerview/widget/RecyclerView;", "rvContent", "kotlin.jvm.PlatformType", "contentView$delegate", "getContentView", "()Landroid/view/View;", "contentView", "alertDialog$delegate", "getAlertDialog", "alertDialog", "adapter$delegate", "getAdapter", "()Lcom/chad/library/adapter/base/BaseQuickAdapter;", "Landroid/widget/TextView;", "btnCancel$delegate", "getBtnCancel", "()Landroid/widget/TextView;", "btnCancel", "outside_view$delegate", "getOutside_view", "outside_view", "<init>", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public abstract class SelectBottomDialog<T> extends DialogFragment {

    /* renamed from: contentView$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy contentView = LazyKt__LazyJVMKt.lazy(new Function0<View>(this) { // from class: com.jbzd.media.movecartoons.ui.dialog.SelectBottomDialog$contentView$2
        public final /* synthetic */ SelectBottomDialog<T> this$0;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        {
            super(0);
            this.this$0 = this;
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        public final View invoke() {
            return LayoutInflater.from(this.this$0.getContext()).inflate(R.layout.dialog_select_bottom, (ViewGroup) null);
        }
    });

    /* renamed from: adapter$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy adapter = LazyKt__LazyJVMKt.lazy(new SelectBottomDialog$adapter$2(this));

    /* renamed from: outside_view$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy outside_view = LazyKt__LazyJVMKt.lazy(new Function0<View>(this) { // from class: com.jbzd.media.movecartoons.ui.dialog.SelectBottomDialog$outside_view$2
        public final /* synthetic */ SelectBottomDialog<T> this$0;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        {
            super(0);
            this.this$0 = this;
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final View invoke() {
            View contentView;
            contentView = this.this$0.getContentView();
            View findViewById = contentView.findViewById(R.id.outside_view);
            Objects.requireNonNull(findViewById, "null cannot be cast to non-null type android.view.View");
            return findViewById;
        }
    });

    /* renamed from: rvContent$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy rvContent = LazyKt__LazyJVMKt.lazy(new Function0<RecyclerView>(this) { // from class: com.jbzd.media.movecartoons.ui.dialog.SelectBottomDialog$rvContent$2
        public final /* synthetic */ SelectBottomDialog<T> this$0;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        {
            super(0);
            this.this$0 = this;
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final RecyclerView invoke() {
            View contentView;
            contentView = this.this$0.getContentView();
            View findViewById = contentView.findViewById(R.id.rv_content);
            Objects.requireNonNull(findViewById, "null cannot be cast to non-null type androidx.recyclerview.widget.RecyclerView");
            return (RecyclerView) findViewById;
        }
    });

    /* renamed from: btnCancel$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy btnCancel = LazyKt__LazyJVMKt.lazy(new Function0<TextView>(this) { // from class: com.jbzd.media.movecartoons.ui.dialog.SelectBottomDialog$btnCancel$2
        public final /* synthetic */ SelectBottomDialog<T> this$0;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        {
            super(0);
            this.this$0 = this;
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final TextView invoke() {
            View contentView;
            contentView = this.this$0.getContentView();
            View findViewById = contentView.findViewById(R.id.btnCancel);
            Objects.requireNonNull(findViewById, "null cannot be cast to non-null type android.widget.TextView");
            return (TextView) findViewById;
        }
    });

    /* renamed from: alertDialog$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy alertDialog = LazyKt__LazyJVMKt.lazy(new Function0<AlertDialog>(this) { // from class: com.jbzd.media.movecartoons.ui.dialog.SelectBottomDialog$alertDialog$2
        public final /* synthetic */ SelectBottomDialog<T> this$0;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        {
            super(0);
            this.this$0 = this;
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final AlertDialog invoke() {
            AlertDialog createDialog;
            createDialog = this.this$0.createDialog();
            return createDialog;
        }
    });

    /* JADX INFO: Access modifiers changed from: private */
    public final AlertDialog createDialog() {
        C2354n.m2374A(getOutside_view(), 0L, new Function1<View, Unit>(this) { // from class: com.jbzd.media.movecartoons.ui.dialog.SelectBottomDialog$createDialog$1
            public final /* synthetic */ SelectBottomDialog<T> this$0;

            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
                this.this$0 = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(View view) {
                invoke2(view);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull View it) {
                Intrinsics.checkNotNullParameter(it, "it");
                this.this$0.dismiss();
            }
        }, 1);
        RecyclerView rvContent = getRvContent();
        rvContent.setLayoutManager(new LinearLayoutManager(requireContext()));
        rvContent.setAdapter(getAdapter());
        rvContent.addItemDecoration(getItemDecoration());
        AlertDialog m624j0 = C1499a.m624j0(new AlertDialog.Builder(requireContext(), 2131951873), getContentView(), "Builder(requireContext(), R.style.Dialog_FullScreen_BottomIn)\n            .setView(contentView)\n            .create()");
        ((FrameLayout) getContentView().findViewById(R.id.flBg)).setBackgroundResource(getBg());
        C2354n.m2374A(getContentView().findViewById(R.id.flRoot), 0L, new Function1<FrameLayout, Unit>(this) { // from class: com.jbzd.media.movecartoons.ui.dialog.SelectBottomDialog$createDialog$3
            public final /* synthetic */ SelectBottomDialog<T> this$0;

            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
                this.this$0 = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(FrameLayout frameLayout) {
                invoke2(frameLayout);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(FrameLayout frameLayout) {
                this.this$0.dismissAllowingStateLoss();
            }
        }, 1);
        C2354n.m2374A(getBtnCancel(), 0L, new Function1<TextView, Unit>(this) { // from class: com.jbzd.media.movecartoons.ui.dialog.SelectBottomDialog$createDialog$4
            public final /* synthetic */ SelectBottomDialog<T> this$0;

            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
                this.this$0 = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(TextView textView) {
                invoke2(textView);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull TextView it) {
                Intrinsics.checkNotNullParameter(it, "it");
                this.this$0.dismissAllowingStateLoss();
            }
        }, 1);
        getBtnCancel().setVisibility(getShowCancel() ? 0 : 8);
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

    private final BaseQuickAdapter<T, BaseViewHolder> getAdapter() {
        return (BaseQuickAdapter) this.adapter.getValue();
    }

    private final AlertDialog getAlertDialog() {
        return (AlertDialog) this.alertDialog.getValue();
    }

    private final TextView getBtnCancel() {
        return (TextView) this.btnCancel.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final View getContentView() {
        return (View) this.contentView.getValue();
    }

    private final View getOutside_view() {
        return (View) this.outside_view.getValue();
    }

    private final RecyclerView getRvContent() {
        return (RecyclerView) this.rvContent.getValue();
    }

    public void _$_clearFindViewByIdCache() {
    }

    public abstract void bindItem(@NotNull BaseViewHolder helper, T item);

    public int getBg() {
        return R.drawable.shape_audience;
    }

    @NotNull
    public abstract ArrayList<T> getData();

    @NotNull
    public final RecyclerView.ItemDecoration getItemDecoration() {
        XDividerItemDecoration xDividerItemDecoration = new XDividerItemDecoration(getContext(), 1);
        xDividerItemDecoration.setDrawable(getResources().getDrawable(R.drawable.divider_line));
        return xDividerItemDecoration;
    }

    @LayoutRes
    public abstract int getItemLayoutId();

    public boolean getShowCancel() {
        return true;
    }

    @Override // androidx.fragment.app.DialogFragment
    @NotNull
    public Dialog onCreateDialog(@Nullable Bundle savedInstanceState) {
        return getAlertDialog();
    }

    public void onItemClick(@NotNull BaseQuickAdapter<T, BaseViewHolder> adapter, @NotNull View view, int position) {
        Intrinsics.checkNotNullParameter(adapter, "adapter");
        Intrinsics.checkNotNullParameter(view, "view");
    }

    @Override // androidx.fragment.app.DialogFragment, androidx.fragment.app.Fragment
    public void onStart() {
        super.onStart();
        getAdapter().setNewData(getData());
    }
}
