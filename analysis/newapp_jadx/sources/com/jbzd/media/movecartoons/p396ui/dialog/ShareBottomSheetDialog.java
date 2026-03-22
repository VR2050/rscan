package com.jbzd.media.movecartoons.p396ui.dialog;

import android.app.Activity;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.appcompat.widget.ActivityChooserModel;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.jbzd.media.movecartoons.bean.response.VideoDetailBean;
import com.jbzd.media.movecartoons.p396ui.dialog.ShareBottomSheetDialog$linkAdapter$2;
import com.jbzd.media.movecartoons.view.decoration.ItemDecorationH;
import com.qnmd.adnnm.da0yzo.R;
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
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p327w.p330b.p337d.C2861e;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000O\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0010\b\n\u0002\b\u0006*\u0001\u001b\u0018\u0000 12\u00020\u0001:\u00011B\u001f\u0012\u0006\u0010!\u001a\u00020 \u0012\u0006\u0010-\u001a\u00020,\u0012\u0006\u0010.\u001a\u00020,¢\u0006\u0004\b/\u00100J\u000f\u0010\u0003\u001a\u00020\u0002H\u0002¢\u0006\u0004\b\u0003\u0010\u0004J\u0017\u0010\u0007\u001a\u00020\u00022\b\u0010\u0006\u001a\u0004\u0018\u00010\u0005¢\u0006\u0004\b\u0007\u0010\bJ\r\u0010\t\u001a\u00020\u0002¢\u0006\u0004\b\t\u0010\u0004J\u000f\u0010\n\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\n\u0010\u0004R\u001d\u0010\u0010\u001a\u00020\u000b8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\f\u0010\r\u001a\u0004\b\u000e\u0010\u000fR\u001d\u0010\u0015\u001a\u00020\u00118B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u0012\u0010\r\u001a\u0004\b\u0013\u0010\u0014R\u001d\u0010\u001a\u001a\u00020\u00168B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u0017\u0010\r\u001a\u0004\b\u0018\u0010\u0019R\u001d\u0010\u001f\u001a\u00020\u001b8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u001c\u0010\r\u001a\u0004\b\u001d\u0010\u001eR\u0016\u0010!\u001a\u00020 8\u0002@\u0002X\u0082\u0004¢\u0006\u0006\n\u0004\b!\u0010\"R%\u0010&\u001a\n #*\u0004\u0018\u00010\u000b0\u000b8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b$\u0010\r\u001a\u0004\b%\u0010\u000fR\u001d\u0010+\u001a\u00020'8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b(\u0010\r\u001a\u0004\b)\u0010*¨\u00062"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/dialog/ShareBottomSheetDialog;", "Lcom/jbzd/media/movecartoons/ui/dialog/StrongBottomSheetDialog;", "", "initDefaultShow", "()V", "Lcom/jbzd/media/movecartoons/bean/response/VideoDetailBean;", "video", "setShowData", "(Lcom/jbzd/media/movecartoons/bean/response/VideoDetailBean;)V", "init", "dismiss", "Landroid/view/View;", "outside_view$delegate", "Lkotlin/Lazy;", "getOutside_view", "()Landroid/view/View;", "outside_view", "Landroidx/recyclerview/widget/RecyclerView;", "rv_links$delegate", "getRv_links", "()Landroidx/recyclerview/widget/RecyclerView;", "rv_links", "Landroid/widget/TextView;", "tv_shareRule$delegate", "getTv_shareRule", "()Landroid/widget/TextView;", "tv_shareRule", "com/jbzd/media/movecartoons/ui/dialog/ShareBottomSheetDialog$linkAdapter$2$1", "linkAdapter$delegate", "getLinkAdapter", "()Lcom/jbzd/media/movecartoons/ui/dialog/ShareBottomSheetDialog$linkAdapter$2$1;", "linkAdapter", "Landroid/app/Activity;", "context", "Landroid/app/Activity;", "kotlin.jvm.PlatformType", "contentView$delegate", "getContentView", "contentView", "Landroid/widget/ImageView;", "iv_dismiss$delegate", "getIv_dismiss", "()Landroid/widget/ImageView;", "iv_dismiss", "", "peekHeight", "maxHeight", "<init>", "(Landroid/app/Activity;II)V", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class ShareBottomSheetDialog extends StrongBottomSheetDialog {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    /* renamed from: contentView$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy contentView;

    @NotNull
    private final Activity context;

    /* renamed from: iv_dismiss$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy iv_dismiss;

    /* renamed from: linkAdapter$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy linkAdapter;

    /* renamed from: outside_view$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy outside_view;

    /* renamed from: rv_links$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy rv_links;

    /* renamed from: tv_shareRule$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_shareRule;

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0016\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0005\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0007\u0010\bJ\u0015\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u0003\u001a\u00020\u0002¢\u0006\u0004\b\u0005\u0010\u0006¨\u0006\t"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/dialog/ShareBottomSheetDialog$Companion;", "", "Landroid/app/Activity;", ActivityChooserModel.ATTRIBUTE_ACTIVITY, "Lcom/jbzd/media/movecartoons/ui/dialog/ShareBottomSheetDialog;", "getShareBottomSheetDialog", "(Landroid/app/Activity;)Lcom/jbzd/media/movecartoons/ui/dialog/ShareBottomSheetDialog;", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        @NotNull
        public final ShareBottomSheetDialog getShareBottomSheetDialog(@NotNull Activity activity) {
            View findViewById;
            Intrinsics.checkNotNullParameter(activity, "activity");
            int m2513s0 = (C2354n.m2513s0(activity) * 2) / 5;
            ShareBottomSheetDialog shareBottomSheetDialog = new ShareBottomSheetDialog(activity, m2513s0, m2513s0);
            shareBottomSheetDialog.init();
            Window window = shareBottomSheetDialog.getWindow();
            if (window != null && (findViewById = window.findViewById(R.id.design_bottom_sheet)) != null) {
                findViewById.setBackgroundResource(android.R.color.transparent);
            }
            return shareBottomSheetDialog;
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public ShareBottomSheetDialog(@NotNull Activity context, int i2, int i3) {
        super(context, i2, i3, R.style.TransBottomSheetDialogStyle);
        Intrinsics.checkNotNullParameter(context, "context");
        this.context = context;
        this.contentView = LazyKt__LazyJVMKt.lazy(new Function0<View>() { // from class: com.jbzd.media.movecartoons.ui.dialog.ShareBottomSheetDialog$contentView$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            public final View invoke() {
                Activity activity;
                activity = ShareBottomSheetDialog.this.context;
                return LayoutInflater.from(activity).inflate(R.layout.dialog_share_bottom, (ViewGroup) null);
            }
        });
        this.tv_shareRule = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.dialog.ShareBottomSheetDialog$tv_shareRule$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final TextView invoke() {
                View contentView;
                contentView = ShareBottomSheetDialog.this.getContentView();
                View findViewById = contentView.findViewById(R.id.tv_shareRule);
                Objects.requireNonNull(findViewById, "null cannot be cast to non-null type android.widget.TextView");
                return (TextView) findViewById;
            }
        });
        this.outside_view = LazyKt__LazyJVMKt.lazy(new Function0<View>() { // from class: com.jbzd.media.movecartoons.ui.dialog.ShareBottomSheetDialog$outside_view$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final View invoke() {
                View contentView;
                contentView = ShareBottomSheetDialog.this.getContentView();
                View findViewById = contentView.findViewById(R.id.outside_view);
                Objects.requireNonNull(findViewById, "null cannot be cast to non-null type android.view.View");
                return findViewById;
            }
        });
        this.rv_links = LazyKt__LazyJVMKt.lazy(new Function0<RecyclerView>() { // from class: com.jbzd.media.movecartoons.ui.dialog.ShareBottomSheetDialog$rv_links$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final RecyclerView invoke() {
                View contentView;
                contentView = ShareBottomSheetDialog.this.getContentView();
                View findViewById = contentView.findViewById(R.id.rv_links);
                Objects.requireNonNull(findViewById, "null cannot be cast to non-null type androidx.recyclerview.widget.RecyclerView");
                return (RecyclerView) findViewById;
            }
        });
        this.iv_dismiss = LazyKt__LazyJVMKt.lazy(new Function0<ImageView>() { // from class: com.jbzd.media.movecartoons.ui.dialog.ShareBottomSheetDialog$iv_dismiss$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final ImageView invoke() {
                View contentView;
                contentView = ShareBottomSheetDialog.this.getContentView();
                View findViewById = contentView.findViewById(R.id.iv_dismiss);
                Objects.requireNonNull(findViewById, "null cannot be cast to non-null type android.widget.ImageView");
                return (ImageView) findViewById;
            }
        });
        this.linkAdapter = LazyKt__LazyJVMKt.lazy(new ShareBottomSheetDialog$linkAdapter$2(this));
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final View getContentView() {
        return (View) this.contentView.getValue();
    }

    private final ImageView getIv_dismiss() {
        return (ImageView) this.iv_dismiss.getValue();
    }

    private final ShareBottomSheetDialog$linkAdapter$2.C37341 getLinkAdapter() {
        return (ShareBottomSheetDialog$linkAdapter$2.C37341) this.linkAdapter.getValue();
    }

    private final View getOutside_view() {
        return (View) this.outside_view.getValue();
    }

    private final RecyclerView getRv_links() {
        return (RecyclerView) this.rv_links.getValue();
    }

    private final TextView getTv_shareRule() {
        return (TextView) this.tv_shareRule.getValue();
    }

    private final void initDefaultShow() {
        C2354n.m2374A(getIv_dismiss(), 0L, new Function1<ImageView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.ShareBottomSheetDialog$initDefaultShow$1
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(ImageView imageView) {
                invoke2(imageView);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull ImageView it) {
                Intrinsics.checkNotNullParameter(it, "it");
                ShareBottomSheetDialog.this.dismiss();
            }
        }, 1);
        C2354n.m2374A(getOutside_view(), 0L, new Function1<View, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.ShareBottomSheetDialog$initDefaultShow$2
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
                ShareBottomSheetDialog.this.dismiss();
            }
        }, 1);
        RecyclerView rv_links = getRv_links();
        rv_links.setAdapter(getLinkAdapter());
        rv_links.setLayoutManager(new LinearLayoutManager(rv_links.getContext(), 0, false));
        if (rv_links.getItemDecorationCount() == 0) {
            rv_links.addItemDecoration(new ItemDecorationH(C2354n.m2425R(rv_links.getContext(), 45.0f), C2354n.m2425R(rv_links.getContext(), 0.0f)));
        }
    }

    @Override // androidx.appcompat.app.AppCompatDialog, android.app.Dialog, android.content.DialogInterface
    public void dismiss() {
        View currentFocus = getCurrentFocus();
        if (currentFocus instanceof EditText) {
            C2861e.m3306d(currentFocus);
        }
        super.dismiss();
    }

    public final void init() {
        setContentView(getContentView());
        initDefaultShow();
    }

    public final void setShowData(@Nullable VideoDetailBean video) {
    }
}
