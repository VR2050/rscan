package com.jbzd.media.movecartoons.p396ui.download;

import android.content.Context;
import android.widget.RelativeLayout;
import android.widget.TextView;
import com.gyf.immersionbar.ImmersionBar;
import com.jbzd.media.movecartoons.p396ui.dialog.XAlertDialog;
import com.qnmd.adnnm.da0yzo.R;
import com.qunidayede.supportlibrary.core.view.BaseActivity;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000H\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0002\b\u0006\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0010\u000b\n\u0002\b\b\n\u0002\u0018\u0002\n\u0002\b\n\u0018\u0000 22\u00020\u0001:\u00012B\u0007¢\u0006\u0004\b1\u0010\u0004J\u000f\u0010\u0003\u001a\u00020\u0002H\u0002¢\u0006\u0004\b\u0003\u0010\u0004J\u000f\u0010\u0006\u001a\u00020\u0005H\u0016¢\u0006\u0004\b\u0006\u0010\u0007J\u000f\u0010\b\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\b\u0010\u0004J\u000f\u0010\t\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\t\u0010\u0004J\u000f\u0010\n\u001a\u00020\u0005H\u0016¢\u0006\u0004\b\n\u0010\u0007J\u000f\u0010\u000b\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\u000b\u0010\u0004J\u000f\u0010\r\u001a\u00020\fH\u0016¢\u0006\u0004\b\r\u0010\u000eR\u001d\u0010\u0014\u001a\u00020\u000f8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u0010\u0010\u0011\u001a\u0004\b\u0012\u0010\u0013R\u001d\u0010\u0019\u001a\u00020\u00158B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u0016\u0010\u0011\u001a\u0004\b\u0017\u0010\u0018R%\u0010\u001f\u001a\n \u001b*\u0004\u0018\u00010\u001a0\u001a8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u001c\u0010\u0011\u001a\u0004\b\u001d\u0010\u001eR\"\u0010\u0003\u001a\u00020 8\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\u0003\u0010!\u001a\u0004\b\"\u0010#\"\u0004\b$\u0010%R\u001d\u0010(\u001a\u00020\u000f8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b&\u0010\u0011\u001a\u0004\b'\u0010\u0013R\u001d\u0010-\u001a\u00020)8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b*\u0010\u0011\u001a\u0004\b+\u0010,R\u001d\u00100\u001a\u00020)8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b.\u0010\u0011\u001a\u0004\b/\u0010,¨\u00063"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/download/DownloadActivity;", "Lcom/qunidayede/supportlibrary/core/view/BaseActivity;", "", "showEdit", "()V", "", "getTopBarTitle", "()Ljava/lang/String;", "initStatusBar", "bindEvent", "getRightTitle", "clickRight", "", "getLayoutId", "()I", "Landroid/widget/TextView;", "tvAll$delegate", "Lkotlin/Lazy;", "getTvAll", "()Landroid/widget/TextView;", "tvAll", "Lcom/jbzd/media/movecartoons/ui/download/ListFragment;", "listFragment$delegate", "getListFragment", "()Lcom/jbzd/media/movecartoons/ui/download/ListFragment;", "listFragment", "Lcom/jbzd/media/movecartoons/ui/dialog/XAlertDialog;", "kotlin.jvm.PlatformType", "dialog$delegate", "getDialog", "()Lcom/jbzd/media/movecartoons/ui/dialog/XAlertDialog;", "dialog", "", "Z", "getShowEdit", "()Z", "setShowEdit", "(Z)V", "btnDel$delegate", "getBtnDel", "btnDel", "Landroid/widget/RelativeLayout;", "btnCancel$delegate", "getBtnCancel", "()Landroid/widget/RelativeLayout;", "btnCancel", "btnAll$delegate", "getBtnAll", "btnAll", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class DownloadActivity extends BaseActivity {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);
    private boolean showEdit;

    /* renamed from: listFragment$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy listFragment = LazyKt__LazyJVMKt.lazy(new Function0<ListFragment>() { // from class: com.jbzd.media.movecartoons.ui.download.DownloadActivity$listFragment$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ListFragment invoke() {
            return new ListFragment();
        }
    });

    /* renamed from: dialog$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy dialog = LazyKt__LazyJVMKt.lazy(new Function0<XAlertDialog>() { // from class: com.jbzd.media.movecartoons.ui.download.DownloadActivity$dialog$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        public final XAlertDialog invoke() {
            return new XAlertDialog(DownloadActivity.this).builder();
        }
    });

    /* renamed from: btnCancel$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy btnCancel = LazyKt__LazyJVMKt.lazy(new Function0<RelativeLayout>() { // from class: com.jbzd.media.movecartoons.ui.download.DownloadActivity$btnCancel$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final RelativeLayout invoke() {
            RelativeLayout relativeLayout = (RelativeLayout) DownloadActivity.this.findViewById(R.id.btnCancel);
            Intrinsics.checkNotNull(relativeLayout);
            return relativeLayout;
        }
    });

    /* renamed from: btnAll$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy btnAll = LazyKt__LazyJVMKt.lazy(new Function0<RelativeLayout>() { // from class: com.jbzd.media.movecartoons.ui.download.DownloadActivity$btnAll$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final RelativeLayout invoke() {
            RelativeLayout relativeLayout = (RelativeLayout) DownloadActivity.this.findViewById(R.id.btnAll);
            Intrinsics.checkNotNull(relativeLayout);
            return relativeLayout;
        }
    });

    /* renamed from: tvAll$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tvAll = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.download.DownloadActivity$tvAll$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final TextView invoke() {
            TextView textView = (TextView) DownloadActivity.this.findViewById(R.id.tvAll);
            Intrinsics.checkNotNull(textView);
            return textView;
        }
    });

    /* renamed from: btnDel$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy btnDel = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.download.DownloadActivity$btnDel$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final TextView invoke() {
            TextView textView = (TextView) DownloadActivity.this.findViewById(R.id.btnDel);
            Intrinsics.checkNotNull(textView);
            return textView;
        }
    });

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0016\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0005\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0007\u0010\bJ\u0015\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u0003\u001a\u00020\u0002¢\u0006\u0004\b\u0005\u0010\u0006¨\u0006\t"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/download/DownloadActivity$Companion;", "", "Landroid/content/Context;", "context", "", "start", "(Landroid/content/Context;)V", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public final void start(@NotNull Context context) {
            C1499a.m602X(context, "context", context, DownloadActivity.class);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final XAlertDialog getDialog() {
        return (XAlertDialog) this.dialog.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final ListFragment getListFragment() {
        return (ListFragment) this.listFragment.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void showEdit() {
        getBtnDel().setVisibility(this.showEdit ? 0 : 8);
        ImmersionBar.with(this).fitsSystemWindows(false).statusBarColor(this.showEdit ? "#111111" : "#000000").statusBarDarkFont(true).init();
        getListFragment().openEdit(this.showEdit);
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseActivity
    public void _$_clearFindViewByIdCache() {
    }

    @Override // p005b.p327w.p330b.p331b.p334e.InterfaceC2847j
    public void bindEvent() {
        getSupportFragmentManager().beginTransaction().replace(R.id.fr_container, getListFragment()).commit();
        C2354n.m2374A(getBtnCancel(), 0L, new Function1<RelativeLayout, Unit>() { // from class: com.jbzd.media.movecartoons.ui.download.DownloadActivity$bindEvent$1
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(RelativeLayout relativeLayout) {
                invoke2(relativeLayout);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull RelativeLayout it) {
                Intrinsics.checkNotNullParameter(it, "it");
                DownloadActivity.this.setShowEdit(false);
                DownloadActivity.this.showEdit();
            }
        }, 1);
        C2354n.m2374A(getBtnAll(), 0L, new Function1<RelativeLayout, Unit>() { // from class: com.jbzd.media.movecartoons.ui.download.DownloadActivity$bindEvent$2
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(RelativeLayout relativeLayout) {
                invoke2(relativeLayout);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull RelativeLayout it) {
                ListFragment listFragment;
                ListFragment listFragment2;
                Intrinsics.checkNotNullParameter(it, "it");
                if (Intrinsics.areEqual(DownloadActivity.this.getTvAll().getText(), "全选")) {
                    DownloadActivity.this.getTvAll().setText("取消全选");
                    listFragment2 = DownloadActivity.this.getListFragment();
                    listFragment2.select(true);
                } else {
                    DownloadActivity.this.getTvAll().setText("全选");
                    listFragment = DownloadActivity.this.getListFragment();
                    listFragment.select(false);
                }
            }
        }, 1);
        C2354n.m2374A(getBtnDel(), 0L, new DownloadActivity$bindEvent$3(this), 1);
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseActivity
    public void clickRight() {
        super.clickRight();
        this.showEdit = true;
        showEdit();
    }

    @NotNull
    public final RelativeLayout getBtnAll() {
        return (RelativeLayout) this.btnAll.getValue();
    }

    @NotNull
    public final RelativeLayout getBtnCancel() {
        return (RelativeLayout) this.btnCancel.getValue();
    }

    @NotNull
    public final TextView getBtnDel() {
        return (TextView) this.btnDel.getValue();
    }

    @Override // p005b.p327w.p330b.p331b.p334e.InterfaceC2847j
    public int getLayoutId() {
        return R.layout.act_download;
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseActivity
    @NotNull
    public String getRightTitle() {
        return "编辑";
    }

    public final boolean getShowEdit() {
        return this.showEdit;
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseActivity
    @NotNull
    public String getTopBarTitle() {
        String string = getString(R.string.mine_download);
        Intrinsics.checkNotNullExpressionValue(string, "getString(R.string.mine_download)");
        return string;
    }

    @NotNull
    public final TextView getTvAll() {
        return (TextView) this.tvAll.getValue();
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseActivity
    public void initStatusBar() {
        ImmersionBar.with(this).fitsSystemWindows(false).navigationBarColor("#000000").statusBarDarkFont(true).init();
    }

    public final void setShowEdit(boolean z) {
        this.showEdit = z;
    }
}
