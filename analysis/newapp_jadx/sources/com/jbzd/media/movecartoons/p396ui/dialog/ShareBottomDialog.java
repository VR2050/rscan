package com.jbzd.media.movecartoons.p396ui.dialog;

import android.app.Dialog;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.view.WindowManager;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.appcompat.app.AlertDialog;
import androidx.fragment.app.DialogFragment;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.jbzd.media.movecartoons.bean.response.VideoDetailBean;
import com.jbzd.media.movecartoons.p396ui.dialog.ShareBottomDialog$linkAdapter$2;
import com.jbzd.media.movecartoons.view.decoration.ItemDecorationH;
import com.qnmd.adnnm.da0yzo.R;
import java.util.Objects;
import kotlin.Deprecated;
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

@Deprecated(message = "已废弃不用")
@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000M\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\b\b\n\u0002\u0018\u0002\n\u0002\b\b\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0007*\u0001\u0010\b\u0007\u0018\u00002\u00020\u0001B\u000f\u0012\u0006\u0010\"\u001a\u00020!¢\u0006\u0004\b0\u00101J\u000f\u0010\u0003\u001a\u00020\u0002H\u0002¢\u0006\u0004\b\u0003\u0010\u0004J\u0019\u0010\b\u001a\u00020\u00072\b\u0010\u0006\u001a\u0004\u0018\u00010\u0005H\u0016¢\u0006\u0004\b\b\u0010\tR\u001d\u0010\u000f\u001a\u00020\n8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u000b\u0010\f\u001a\u0004\b\r\u0010\u000eR\u001d\u0010\u0014\u001a\u00020\u00108B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u0011\u0010\f\u001a\u0004\b\u0012\u0010\u0013R\u001d\u0010\u0017\u001a\u00020\u00028B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u0015\u0010\f\u001a\u0004\b\u0016\u0010\u0004R\u001d\u0010\u001c\u001a\u00020\u00188B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u0019\u0010\f\u001a\u0004\b\u001a\u0010\u001bR%\u0010 \u001a\n \u001d*\u0004\u0018\u00010\u00180\u00188B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u001e\u0010\f\u001a\u0004\b\u001f\u0010\u001bR\u0019\u0010\"\u001a\u00020!8\u0006@\u0006¢\u0006\f\n\u0004\b\"\u0010#\u001a\u0004\b$\u0010%R\u001d\u0010*\u001a\u00020&8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b'\u0010\f\u001a\u0004\b(\u0010)R\u001d\u0010/\u001a\u00020+8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b,\u0010\f\u001a\u0004\b-\u0010.¨\u00062"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/dialog/ShareBottomDialog;", "Landroidx/fragment/app/DialogFragment;", "Landroidx/appcompat/app/AlertDialog;", "createDialog", "()Landroidx/appcompat/app/AlertDialog;", "Landroid/os/Bundle;", "savedInstanceState", "Landroid/app/Dialog;", "onCreateDialog", "(Landroid/os/Bundle;)Landroid/app/Dialog;", "Landroidx/recyclerview/widget/RecyclerView;", "rv_links$delegate", "Lkotlin/Lazy;", "getRv_links", "()Landroidx/recyclerview/widget/RecyclerView;", "rv_links", "com/jbzd/media/movecartoons/ui/dialog/ShareBottomDialog$linkAdapter$2$1", "linkAdapter$delegate", "getLinkAdapter", "()Lcom/jbzd/media/movecartoons/ui/dialog/ShareBottomDialog$linkAdapter$2$1;", "linkAdapter", "alertDialog$delegate", "getAlertDialog", "alertDialog", "Landroid/view/View;", "outside_view$delegate", "getOutside_view", "()Landroid/view/View;", "outside_view", "kotlin.jvm.PlatformType", "contentView$delegate", "getContentView", "contentView", "Lcom/jbzd/media/movecartoons/bean/response/VideoDetailBean;", "video", "Lcom/jbzd/media/movecartoons/bean/response/VideoDetailBean;", "getVideo", "()Lcom/jbzd/media/movecartoons/bean/response/VideoDetailBean;", "Landroid/widget/TextView;", "tv_shareRule$delegate", "getTv_shareRule", "()Landroid/widget/TextView;", "tv_shareRule", "Landroid/widget/ImageView;", "iv_dismiss$delegate", "getIv_dismiss", "()Landroid/widget/ImageView;", "iv_dismiss", "<init>", "(Lcom/jbzd/media/movecartoons/bean/response/VideoDetailBean;)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class ShareBottomDialog extends DialogFragment {

    /* renamed from: alertDialog$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy alertDialog;

    /* renamed from: contentView$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy contentView;

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

    @NotNull
    private final VideoDetailBean video;

    public ShareBottomDialog(@NotNull VideoDetailBean video) {
        Intrinsics.checkNotNullParameter(video, "video");
        this.video = video;
        this.contentView = LazyKt__LazyJVMKt.lazy(new Function0<View>() { // from class: com.jbzd.media.movecartoons.ui.dialog.ShareBottomDialog$contentView$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            public final View invoke() {
                return LayoutInflater.from(ShareBottomDialog.this.getContext()).inflate(R.layout.dialog_share_bottom, (ViewGroup) null);
            }
        });
        this.outside_view = LazyKt__LazyJVMKt.lazy(new Function0<View>() { // from class: com.jbzd.media.movecartoons.ui.dialog.ShareBottomDialog$outside_view$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final View invoke() {
                View contentView;
                contentView = ShareBottomDialog.this.getContentView();
                View findViewById = contentView.findViewById(R.id.outside_view);
                Objects.requireNonNull(findViewById, "null cannot be cast to non-null type android.view.View");
                return findViewById;
            }
        });
        this.tv_shareRule = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.dialog.ShareBottomDialog$tv_shareRule$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final TextView invoke() {
                View contentView;
                contentView = ShareBottomDialog.this.getContentView();
                View findViewById = contentView.findViewById(R.id.tv_shareRule);
                Objects.requireNonNull(findViewById, "null cannot be cast to non-null type android.widget.TextView");
                return (TextView) findViewById;
            }
        });
        this.rv_links = LazyKt__LazyJVMKt.lazy(new Function0<RecyclerView>() { // from class: com.jbzd.media.movecartoons.ui.dialog.ShareBottomDialog$rv_links$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final RecyclerView invoke() {
                View contentView;
                contentView = ShareBottomDialog.this.getContentView();
                View findViewById = contentView.findViewById(R.id.rv_links);
                Objects.requireNonNull(findViewById, "null cannot be cast to non-null type androidx.recyclerview.widget.RecyclerView");
                return (RecyclerView) findViewById;
            }
        });
        this.iv_dismiss = LazyKt__LazyJVMKt.lazy(new Function0<ImageView>() { // from class: com.jbzd.media.movecartoons.ui.dialog.ShareBottomDialog$iv_dismiss$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final ImageView invoke() {
                View contentView;
                contentView = ShareBottomDialog.this.getContentView();
                View findViewById = contentView.findViewById(R.id.iv_dismiss);
                Objects.requireNonNull(findViewById, "null cannot be cast to non-null type android.widget.ImageView");
                return (ImageView) findViewById;
            }
        });
        this.alertDialog = LazyKt__LazyJVMKt.lazy(new Function0<AlertDialog>() { // from class: com.jbzd.media.movecartoons.ui.dialog.ShareBottomDialog$alertDialog$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final AlertDialog invoke() {
                AlertDialog createDialog;
                createDialog = ShareBottomDialog.this.createDialog();
                return createDialog;
            }
        });
        this.linkAdapter = LazyKt__LazyJVMKt.lazy(new ShareBottomDialog$linkAdapter$2(this));
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final AlertDialog createDialog() {
        C2354n.m2374A(getOutside_view(), 0L, new Function1<View, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.ShareBottomDialog$createDialog$1
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
                ShareBottomDialog.this.dismissAllowingStateLoss();
            }
        }, 1);
        AlertDialog m624j0 = C1499a.m624j0(new AlertDialog.Builder(requireContext(), 2131951873), getContentView(), "Builder(requireContext(), R.style.Dialog_FullScreen_BottomIn)\n            .setView(contentView)\n            .create()");
        C2354n.m2374A(getIv_dismiss(), 0L, new Function1<ImageView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.ShareBottomDialog$createDialog$2
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
                ShareBottomDialog.this.dismissAllowingStateLoss();
            }
        }, 1);
        RecyclerView rv_links = getRv_links();
        rv_links.setAdapter(getLinkAdapter());
        rv_links.setLayoutManager(new LinearLayoutManager(requireContext(), 0, false));
        if (rv_links.getItemDecorationCount() == 0) {
            rv_links.addItemDecoration(new ItemDecorationH(C2354n.m2425R(requireContext(), 45.0f), C2354n.m2425R(requireContext(), 0.0f)));
        }
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

    private final AlertDialog getAlertDialog() {
        return (AlertDialog) this.alertDialog.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final View getContentView() {
        return (View) this.contentView.getValue();
    }

    private final ImageView getIv_dismiss() {
        return (ImageView) this.iv_dismiss.getValue();
    }

    private final ShareBottomDialog$linkAdapter$2.C37331 getLinkAdapter() {
        return (ShareBottomDialog$linkAdapter$2.C37331) this.linkAdapter.getValue();
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

    public void _$_clearFindViewByIdCache() {
    }

    @NotNull
    public final VideoDetailBean getVideo() {
        return this.video;
    }

    @Override // androidx.fragment.app.DialogFragment
    @NotNull
    public Dialog onCreateDialog(@Nullable Bundle savedInstanceState) {
        return getAlertDialog();
    }
}
