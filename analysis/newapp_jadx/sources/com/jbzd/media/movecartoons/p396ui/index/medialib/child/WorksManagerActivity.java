package com.jbzd.media.movecartoons.p396ui.index.medialib.child;

import android.content.Context;
import com.jbzd.media.movecartoons.bean.response.VideoStatusBean;
import com.jbzd.media.movecartoons.p396ui.dialog.StatusPopup;
import com.jbzd.media.movecartoons.view.text.ImageTextView;
import com.qnmd.adnnm.da0yzo.R;
import com.qunidayede.supportlibrary.core.view.BaseActivity;
import kotlin.Deprecated;
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

@Deprecated(message = "has no this page!!")
@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u00008\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u000e\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\u0005\n\u0002\u0010\b\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\b\n\u0002\u0018\u0002\n\u0002\b\r\b\u0007\u0018\u0000 )2\u00020\u0001:\u0001)B\u0007¢\u0006\u0004\b(\u0010\u0007J\u000f\u0010\u0003\u001a\u00020\u0002H\u0002¢\u0006\u0004\b\u0003\u0010\u0004J\u000f\u0010\u0006\u001a\u00020\u0005H\u0002¢\u0006\u0004\b\u0006\u0010\u0007J\u000f\u0010\b\u001a\u00020\u0005H\u0002¢\u0006\u0004\b\b\u0010\u0007J\u000f\u0010\t\u001a\u00020\u0005H\u0002¢\u0006\u0004\b\t\u0010\u0007J\u000f\u0010\n\u001a\u00020\u0005H\u0016¢\u0006\u0004\b\n\u0010\u0007J\u000f\u0010\f\u001a\u00020\u000bH\u0016¢\u0006\u0004\b\f\u0010\rJ\u000f\u0010\u000e\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\u000e\u0010\u0004J\u000f\u0010\u000f\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\u000f\u0010\u0004J\u000f\u0010\u0010\u001a\u00020\u0005H\u0016¢\u0006\u0004\b\u0010\u0010\u0007R\u0018\u0010\u0012\u001a\u0004\u0018\u00010\u00118\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\u0012\u0010\u0013R\u001d\u0010\u0019\u001a\u00020\u00148F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u0015\u0010\u0016\u001a\u0004\b\u0017\u0010\u0018R\u001d\u0010\u001c\u001a\u00020\u00148F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u001a\u0010\u0016\u001a\u0004\b\u001b\u0010\u0018R\u001d\u0010!\u001a\u00020\u001d8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u001e\u0010\u0016\u001a\u0004\b\u001f\u0010 R\u001d\u0010$\u001a\u00020\u00148F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\"\u0010\u0016\u001a\u0004\b#\u0010\u0018R\u001d\u0010'\u001a\u00020\u00148F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b%\u0010\u0016\u001a\u0004\b&\u0010\u0018¨\u0006*"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/index/medialib/child/WorksManagerActivity;", "Lcom/qunidayede/supportlibrary/core/view/BaseActivity;", "", "getCanvas", "()Ljava/lang/String;", "", "showLong", "()V", "showShort", "showAll", "bindEvent", "", "getLayoutId", "()I", "getTopBarTitle", "getRightTitle", "clickRight", "Lcom/jbzd/media/movecartoons/ui/dialog/StatusPopup;", "statusPopup", "Lcom/jbzd/media/movecartoons/ui/dialog/StatusPopup;", "Lcom/jbzd/media/movecartoons/view/text/ImageTextView;", "itv_long$delegate", "Lkotlin/Lazy;", "getItv_long", "()Lcom/jbzd/media/movecartoons/view/text/ImageTextView;", "itv_long", "itv_short$delegate", "getItv_short", "itv_short", "Lcom/jbzd/media/movecartoons/ui/index/medialib/child/WorksListFragment;", "fragment$delegate", "getFragment", "()Lcom/jbzd/media/movecartoons/ui/index/medialib/child/WorksListFragment;", "fragment", "itv_all$delegate", "getItv_all", "itv_all", "itv_status$delegate", "getItv_status", "itv_status", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class WorksManagerActivity extends BaseActivity {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    @Nullable
    private StatusPopup statusPopup;

    /* renamed from: fragment$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy fragment = LazyKt__LazyJVMKt.lazy(new Function0<WorksListFragment>() { // from class: com.jbzd.media.movecartoons.ui.index.medialib.child.WorksManagerActivity$fragment$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final WorksListFragment invoke() {
            return WorksListFragment.INSTANCE.newInstance();
        }
    });

    /* renamed from: itv_long$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy itv_long = LazyKt__LazyJVMKt.lazy(new Function0<ImageTextView>() { // from class: com.jbzd.media.movecartoons.ui.index.medialib.child.WorksManagerActivity$itv_long$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ImageTextView invoke() {
            ImageTextView imageTextView = (ImageTextView) WorksManagerActivity.this.findViewById(R.id.itv_long);
            Intrinsics.checkNotNull(imageTextView);
            return imageTextView;
        }
    });

    /* renamed from: itv_short$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy itv_short = LazyKt__LazyJVMKt.lazy(new Function0<ImageTextView>() { // from class: com.jbzd.media.movecartoons.ui.index.medialib.child.WorksManagerActivity$itv_short$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ImageTextView invoke() {
            ImageTextView imageTextView = (ImageTextView) WorksManagerActivity.this.findViewById(R.id.itv_short);
            Intrinsics.checkNotNull(imageTextView);
            return imageTextView;
        }
    });

    /* renamed from: itv_all$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy itv_all = LazyKt__LazyJVMKt.lazy(new Function0<ImageTextView>() { // from class: com.jbzd.media.movecartoons.ui.index.medialib.child.WorksManagerActivity$itv_all$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ImageTextView invoke() {
            ImageTextView imageTextView = (ImageTextView) WorksManagerActivity.this.findViewById(R.id.itv_all);
            Intrinsics.checkNotNull(imageTextView);
            return imageTextView;
        }
    });

    /* renamed from: itv_status$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy itv_status = LazyKt__LazyJVMKt.lazy(new Function0<ImageTextView>() { // from class: com.jbzd.media.movecartoons.ui.index.medialib.child.WorksManagerActivity$itv_status$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ImageTextView invoke() {
            ImageTextView imageTextView = (ImageTextView) WorksManagerActivity.this.findViewById(R.id.itv_status);
            Intrinsics.checkNotNull(imageTextView);
            return imageTextView;
        }
    });

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0016\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0005\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0007\u0010\bJ\u0015\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u0003\u001a\u00020\u0002¢\u0006\u0004\b\u0005\u0010\u0006¨\u0006\t"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/index/medialib/child/WorksManagerActivity$Companion;", "", "Landroid/content/Context;", "context", "", "start", "(Landroid/content/Context;)V", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public final void start(@NotNull Context context) {
            C1499a.m602X(context, "context", context, WorksManagerActivity.class);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final String getCanvas() {
        return getItv_long().isSelected() ? "long" : getItv_short().isSelected() ? "short" : "";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final WorksListFragment getFragment() {
        return (WorksListFragment) this.fragment.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void showAll() {
        getItv_all().setSelected(true);
        getItv_long().setSelected(false);
        getItv_short().setSelected(false);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void showLong() {
        getItv_all().setSelected(false);
        getItv_long().setSelected(true);
        getItv_short().setSelected(false);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void showShort() {
        getItv_all().setSelected(false);
        getItv_long().setSelected(false);
        getItv_short().setSelected(true);
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseActivity
    public void _$_clearFindViewByIdCache() {
    }

    @Override // p005b.p327w.p330b.p331b.p334e.InterfaceC2847j
    public void bindEvent() {
        getSupportFragmentManager().beginTransaction().replace(R.id.frag_content, getFragment()).commit();
        showAll();
        C2354n.m2374A(getItv_long(), 0L, new Function1<ImageTextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.medialib.child.WorksManagerActivity$bindEvent$1
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(ImageTextView imageTextView) {
                invoke2(imageTextView);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull ImageTextView it) {
                WorksListFragment fragment;
                String canvas;
                Intrinsics.checkNotNullParameter(it, "it");
                if (WorksManagerActivity.this.getItv_long().isSelected()) {
                    return;
                }
                WorksManagerActivity.this.showLong();
                fragment = WorksManagerActivity.this.getFragment();
                canvas = WorksManagerActivity.this.getCanvas();
                fragment.updateCanvas(canvas);
            }
        }, 1);
        C2354n.m2374A(getItv_short(), 0L, new Function1<ImageTextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.medialib.child.WorksManagerActivity$bindEvent$2
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(ImageTextView imageTextView) {
                invoke2(imageTextView);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull ImageTextView it) {
                WorksListFragment fragment;
                String canvas;
                Intrinsics.checkNotNullParameter(it, "it");
                if (WorksManagerActivity.this.getItv_short().isSelected()) {
                    return;
                }
                WorksManagerActivity.this.showShort();
                fragment = WorksManagerActivity.this.getFragment();
                canvas = WorksManagerActivity.this.getCanvas();
                fragment.updateCanvas(canvas);
            }
        }, 1);
        C2354n.m2374A(getItv_all(), 0L, new Function1<ImageTextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.medialib.child.WorksManagerActivity$bindEvent$3
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(ImageTextView imageTextView) {
                invoke2(imageTextView);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull ImageTextView it) {
                WorksListFragment fragment;
                String canvas;
                Intrinsics.checkNotNullParameter(it, "it");
                if (WorksManagerActivity.this.getItv_all().isSelected()) {
                    return;
                }
                WorksManagerActivity.this.showAll();
                fragment = WorksManagerActivity.this.getFragment();
                canvas = WorksManagerActivity.this.getCanvas();
                fragment.updateCanvas(canvas);
            }
        }, 1);
        this.statusPopup = new StatusPopup(this, new Function1<VideoStatusBean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.medialib.child.WorksManagerActivity$bindEvent$4
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(VideoStatusBean videoStatusBean) {
                invoke2(videoStatusBean);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull VideoStatusBean it) {
                WorksListFragment fragment;
                Intrinsics.checkNotNullParameter(it, "it");
                WorksManagerActivity.this.getItv_status().setText(it.statusTxt);
                fragment = WorksManagerActivity.this.getFragment();
                fragment.updateStatus(it.status);
            }
        });
        C2354n.m2374A(getItv_status(), 0L, new Function1<ImageTextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.medialib.child.WorksManagerActivity$bindEvent$5
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(ImageTextView imageTextView) {
                invoke2(imageTextView);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull ImageTextView it) {
                StatusPopup statusPopup;
                StatusPopup statusPopup2;
                StatusPopup statusPopup3;
                Intrinsics.checkNotNullParameter(it, "it");
                statusPopup = WorksManagerActivity.this.statusPopup;
                if (Intrinsics.areEqual(statusPopup == null ? null : Boolean.valueOf(statusPopup.isShowing()), Boolean.TRUE)) {
                    statusPopup3 = WorksManagerActivity.this.statusPopup;
                    if (statusPopup3 == null) {
                        return;
                    }
                    statusPopup3.dismiss();
                    return;
                }
                statusPopup2 = WorksManagerActivity.this.statusPopup;
                if (statusPopup2 == null) {
                    return;
                }
                statusPopup2.showAsDropDown(WorksManagerActivity.this.getItv_status());
            }
        }, 1);
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseActivity
    public void clickRight() {
        super.clickRight();
        UploadListActivity.INSTANCE.start(this);
    }

    @NotNull
    public final ImageTextView getItv_all() {
        return (ImageTextView) this.itv_all.getValue();
    }

    @NotNull
    public final ImageTextView getItv_long() {
        return (ImageTextView) this.itv_long.getValue();
    }

    @NotNull
    public final ImageTextView getItv_short() {
        return (ImageTextView) this.itv_short.getValue();
    }

    @NotNull
    public final ImageTextView getItv_status() {
        return (ImageTextView) this.itv_status.getValue();
    }

    @Override // p005b.p327w.p330b.p331b.p334e.InterfaceC2847j
    public int getLayoutId() {
        return R.layout.act_works_manager;
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseActivity
    @NotNull
    public String getRightTitle() {
        return "上传列表";
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseActivity
    @NotNull
    public String getTopBarTitle() {
        return "作品管理";
    }
}
