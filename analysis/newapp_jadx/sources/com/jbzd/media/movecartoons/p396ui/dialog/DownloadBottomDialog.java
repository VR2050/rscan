package com.jbzd.media.movecartoons.p396ui.dialog;

import android.app.Dialog;
import android.content.Intent;
import android.os.Bundle;
import android.provider.MediaStore;
import android.text.TextUtils;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.view.WindowManager;
import android.widget.ProgressBar;
import android.widget.RelativeLayout;
import android.widget.TextView;
import androidx.appcompat.app.AlertDialog;
import androidx.fragment.app.DialogFragment;
import androidx.fragment.app.FragmentActivity;
import com.jbzd.media.movecartoons.bean.event.EventDownload;
import com.jbzd.media.movecartoons.bean.response.DownloadVideoInfo;
import com.jbzd.media.movecartoons.p396ui.dialog.DownloadBottomDialog;
import com.jbzd.media.movecartoons.p396ui.download.MergeTsToMp4Helper;
import com.jbzd.media.movecartoons.view.text.ImageTextView;
import com.qnmd.adnnm.da0yzo.R;
import java.text.NumberFormat;
import java.util.Objects;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import org.greenrobot.eventbus.ThreadMode;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p006a.p007a.p008a.p009a.C0855k0;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p476m.p496b.p497a.C4909c;
import p476m.p496b.p497a.InterfaceC4919m;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000t\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0010\u0006\n\u0000\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\n\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u000b\u0018\u00002\u00020\u0001B\u000f\u0012\u0006\u0010D\u001a\u00020\u0013¢\u0006\u0004\bH\u0010IJ\u000f\u0010\u0003\u001a\u00020\u0002H\u0002¢\u0006\u0004\b\u0003\u0010\u0004J\u000f\u0010\u0006\u001a\u00020\u0005H\u0002¢\u0006\u0004\b\u0006\u0010\u0007J\u0017\u0010\n\u001a\u00020\u00052\u0006\u0010\t\u001a\u00020\bH\u0007¢\u0006\u0004\b\n\u0010\u000bJ\u000f\u0010\f\u001a\u00020\u0005H\u0016¢\u0006\u0004\b\f\u0010\u0007J\u000f\u0010\r\u001a\u00020\u0005H\u0016¢\u0006\u0004\b\r\u0010\u0007J'\u0010\u0014\u001a\u0004\u0018\u00010\u00132\u0006\u0010\u000f\u001a\u00020\u000e2\u0006\u0010\u0011\u001a\u00020\u00102\u0006\u0010\u0012\u001a\u00020\u0010¢\u0006\u0004\b\u0014\u0010\u0015J\u000f\u0010\u0016\u001a\u00020\u0005H\u0016¢\u0006\u0004\b\u0016\u0010\u0007J\u000f\u0010\u0017\u001a\u00020\u0005H\u0016¢\u0006\u0004\b\u0017\u0010\u0007J\u0019\u0010\u001b\u001a\u00020\u001a2\b\u0010\u0019\u001a\u0004\u0018\u00010\u0018H\u0016¢\u0006\u0004\b\u001b\u0010\u001cR\u001d\u0010 \u001a\u00020\u00028B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u001d\u0010\u001e\u001a\u0004\b\u001f\u0010\u0004R\u0018\u0010\"\u001a\u0004\u0018\u00010!8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\"\u0010#R\u001d\u0010(\u001a\u00020$8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b%\u0010\u001e\u001a\u0004\b&\u0010'R%\u0010.\u001a\n **\u0004\u0018\u00010)0)8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b+\u0010\u001e\u001a\u0004\b,\u0010-R\u001d\u00103\u001a\u00020/8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b0\u0010\u001e\u001a\u0004\b1\u00102R\u001d\u00106\u001a\u00020)8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b4\u0010\u001e\u001a\u0004\b5\u0010-R\u001d\u00109\u001a\u00020$8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b7\u0010\u001e\u001a\u0004\b8\u0010'R\u001d\u0010>\u001a\u00020:8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b;\u0010\u001e\u001a\u0004\b<\u0010=R\u001d\u0010C\u001a\u00020?8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b@\u0010\u001e\u001a\u0004\bA\u0010BR\u0019\u0010D\u001a\u00020\u00138\u0006@\u0006¢\u0006\f\n\u0004\bD\u0010E\u001a\u0004\bF\u0010G¨\u0006J"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/dialog/DownloadBottomDialog;", "Landroidx/fragment/app/DialogFragment;", "Landroidx/appcompat/app/AlertDialog;", "createDialog", "()Landroidx/appcompat/app/AlertDialog;", "", "cancelDownload", "()V", "Lcom/jbzd/media/movecartoons/bean/event/EventDownload;", "eventDownload", "onEventDownload", "(Lcom/jbzd/media/movecartoons/bean/event/EventDownload;)V", "onStart", "onDestroyView", "", "d", "", "IntegerDigits", "FractionDigits", "", "getPercentFormat", "(DII)Ljava/lang/String;", "dismissAllowingStateLoss", "dismiss", "Landroid/os/Bundle;", "savedInstanceState", "Landroid/app/Dialog;", "onCreateDialog", "(Landroid/os/Bundle;)Landroid/app/Dialog;", "alertDialog$delegate", "Lkotlin/Lazy;", "getAlertDialog", "alertDialog", "Lcom/jbzd/media/movecartoons/bean/response/DownloadVideoInfo;", "mDownloadVideoInfo", "Lcom/jbzd/media/movecartoons/bean/response/DownloadVideoInfo;", "Landroid/widget/TextView;", "tv_goPhotos$delegate", "getTv_goPhotos", "()Landroid/widget/TextView;", "tv_goPhotos", "Landroid/view/View;", "kotlin.jvm.PlatformType", "contentView$delegate", "getContentView", "()Landroid/view/View;", "contentView", "Lcom/jbzd/media/movecartoons/view/text/ImageTextView;", "itv_progressTxt$delegate", "getItv_progressTxt", "()Lcom/jbzd/media/movecartoons/view/text/ImageTextView;", "itv_progressTxt", "outside_view$delegate", "getOutside_view", "outside_view", "tv_cancel$delegate", "getTv_cancel", "tv_cancel", "Landroid/widget/ProgressBar;", "pb_progress$delegate", "getPb_progress", "()Landroid/widget/ProgressBar;", "pb_progress", "Landroid/widget/RelativeLayout;", "rl_downlod$delegate", "getRl_downlod", "()Landroid/widget/RelativeLayout;", "rl_downlod", "taskId", "Ljava/lang/String;", "getTaskId", "()Ljava/lang/String;", "<init>", "(Ljava/lang/String;)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class DownloadBottomDialog extends DialogFragment {

    /* renamed from: alertDialog$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy alertDialog;

    /* renamed from: contentView$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy contentView;

    /* renamed from: itv_progressTxt$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy itv_progressTxt;

    @Nullable
    private DownloadVideoInfo mDownloadVideoInfo;

    /* renamed from: outside_view$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy outside_view;

    /* renamed from: pb_progress$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy pb_progress;

    /* renamed from: rl_downlod$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy rl_downlod;

    @NotNull
    private final String taskId;

    /* renamed from: tv_cancel$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_cancel;

    /* renamed from: tv_goPhotos$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_goPhotos;

    public DownloadBottomDialog(@NotNull String taskId) {
        Intrinsics.checkNotNullParameter(taskId, "taskId");
        this.taskId = taskId;
        this.contentView = LazyKt__LazyJVMKt.lazy(new Function0<View>() { // from class: com.jbzd.media.movecartoons.ui.dialog.DownloadBottomDialog$contentView$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            public final View invoke() {
                return LayoutInflater.from(DownloadBottomDialog.this.getContext()).inflate(R.layout.dialog_download_bottom, (ViewGroup) null);
            }
        });
        this.outside_view = LazyKt__LazyJVMKt.lazy(new Function0<View>() { // from class: com.jbzd.media.movecartoons.ui.dialog.DownloadBottomDialog$outside_view$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final View invoke() {
                View contentView;
                contentView = DownloadBottomDialog.this.getContentView();
                View findViewById = contentView.findViewById(R.id.outside_view);
                Objects.requireNonNull(findViewById, "null cannot be cast to non-null type android.view.View");
                return findViewById;
            }
        });
        this.rl_downlod = LazyKt__LazyJVMKt.lazy(new Function0<RelativeLayout>() { // from class: com.jbzd.media.movecartoons.ui.dialog.DownloadBottomDialog$rl_downlod$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final RelativeLayout invoke() {
                View contentView;
                contentView = DownloadBottomDialog.this.getContentView();
                View findViewById = contentView.findViewById(R.id.rl_downlod);
                Objects.requireNonNull(findViewById, "null cannot be cast to non-null type android.widget.RelativeLayout");
                return (RelativeLayout) findViewById;
            }
        });
        this.pb_progress = LazyKt__LazyJVMKt.lazy(new Function0<ProgressBar>() { // from class: com.jbzd.media.movecartoons.ui.dialog.DownloadBottomDialog$pb_progress$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final ProgressBar invoke() {
                View contentView;
                contentView = DownloadBottomDialog.this.getContentView();
                View findViewById = contentView.findViewById(R.id.pb_progress);
                Objects.requireNonNull(findViewById, "null cannot be cast to non-null type android.widget.ProgressBar");
                return (ProgressBar) findViewById;
            }
        });
        this.itv_progressTxt = LazyKt__LazyJVMKt.lazy(new Function0<ImageTextView>() { // from class: com.jbzd.media.movecartoons.ui.dialog.DownloadBottomDialog$itv_progressTxt$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final ImageTextView invoke() {
                View contentView;
                contentView = DownloadBottomDialog.this.getContentView();
                View findViewById = contentView.findViewById(R.id.itv_progressTxt);
                Objects.requireNonNull(findViewById, "null cannot be cast to non-null type com.jbzd.media.movecartoons.view.text.ImageTextView");
                return (ImageTextView) findViewById;
            }
        });
        this.tv_goPhotos = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.dialog.DownloadBottomDialog$tv_goPhotos$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final TextView invoke() {
                View contentView;
                contentView = DownloadBottomDialog.this.getContentView();
                View findViewById = contentView.findViewById(R.id.tv_goPhotos);
                Objects.requireNonNull(findViewById, "null cannot be cast to non-null type android.widget.TextView");
                return (TextView) findViewById;
            }
        });
        this.tv_cancel = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.dialog.DownloadBottomDialog$tv_cancel$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final TextView invoke() {
                View contentView;
                contentView = DownloadBottomDialog.this.getContentView();
                View findViewById = contentView.findViewById(R.id.tv_cancel);
                Objects.requireNonNull(findViewById, "null cannot be cast to non-null type android.widget.TextView");
                return (TextView) findViewById;
            }
        });
        this.alertDialog = LazyKt__LazyJVMKt.lazy(new Function0<AlertDialog>() { // from class: com.jbzd.media.movecartoons.ui.dialog.DownloadBottomDialog$alertDialog$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final AlertDialog invoke() {
                AlertDialog createDialog;
                createDialog = DownloadBottomDialog.this.createDialog();
                return createDialog;
            }
        });
    }

    private final void cancelDownload() {
        DownloadVideoInfo downloadVideoInfo = this.mDownloadVideoInfo;
        if (downloadVideoInfo == null || TextUtils.equals(downloadVideoInfo.status, "completed")) {
            return;
        }
        Objects.requireNonNull(C0855k0.f257a);
        C0855k0 c0855k0 = C0855k0.f258b;
        String id = downloadVideoInfo.f9947id;
        Intrinsics.checkNotNullExpressionValue(id, "id");
        c0855k0.m187c(id);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final AlertDialog createDialog() {
        getOutside_view().setOnClickListener(new View.OnClickListener() { // from class: b.a.a.a.t.e.i
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                DownloadBottomDialog.m5773createDialog$lambda0(DownloadBottomDialog.this, view);
            }
        });
        AlertDialog m624j0 = C1499a.m624j0(new AlertDialog.Builder(requireContext(), 2131951873), getContentView(), "Builder(requireContext(), R.style.Dialog_FullScreen_BottomIn)\n            .setView(contentView)\n            .create()");
        C2354n.m2374A(getTv_cancel(), 0L, new Function1<TextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.DownloadBottomDialog$createDialog$2
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(TextView textView) {
                invoke2(textView);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull TextView it) {
                Intrinsics.checkNotNullParameter(it, "it");
                DownloadBottomDialog.this.dismissAllowingStateLoss();
            }
        }, 1);
        if (MergeTsToMp4Helper.INSTANCE.isMp4Exist(this.taskId)) {
            getPb_progress().setProgress(100);
            getItv_progressTxt().setVisibility(8);
            getTv_goPhotos().setVisibility(0);
            getItv_progressTxt().setText("");
            C2354n.m2374A(getRl_downlod(), 0L, new Function1<RelativeLayout, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.DownloadBottomDialog$createDialog$3
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
                    DownloadBottomDialog.this.dismissAllowingStateLoss();
                    FragmentActivity context = DownloadBottomDialog.this.requireActivity();
                    Intrinsics.checkNotNullExpressionValue(context, "requireActivity()");
                    Intrinsics.checkNotNullParameter(context, "context");
                    context.startActivity(new Intent("android.intent.action.VIEW", MediaStore.Video.Media.EXTERNAL_CONTENT_URI));
                }
            }, 1);
            getTv_cancel().setText("取消");
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

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: createDialog$lambda-0, reason: not valid java name */
    public static final void m5773createDialog$lambda0(DownloadBottomDialog this$0, View view) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        this$0.dismissAllowingStateLoss();
    }

    private final AlertDialog getAlertDialog() {
        return (AlertDialog) this.alertDialog.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final View getContentView() {
        return (View) this.contentView.getValue();
    }

    private final ImageTextView getItv_progressTxt() {
        return (ImageTextView) this.itv_progressTxt.getValue();
    }

    private final View getOutside_view() {
        return (View) this.outside_view.getValue();
    }

    private final ProgressBar getPb_progress() {
        return (ProgressBar) this.pb_progress.getValue();
    }

    private final RelativeLayout getRl_downlod() {
        return (RelativeLayout) this.rl_downlod.getValue();
    }

    private final TextView getTv_cancel() {
        return (TextView) this.tv_cancel.getValue();
    }

    private final TextView getTv_goPhotos() {
        return (TextView) this.tv_goPhotos.getValue();
    }

    public void _$_clearFindViewByIdCache() {
    }

    @Override // androidx.fragment.app.DialogFragment
    public void dismiss() {
        super.dismiss();
        cancelDownload();
    }

    @Override // androidx.fragment.app.DialogFragment
    public void dismissAllowingStateLoss() {
        super.dismissAllowingStateLoss();
        cancelDownload();
    }

    @Nullable
    public final String getPercentFormat(double d2, int IntegerDigits, int FractionDigits) {
        NumberFormat percentInstance = NumberFormat.getPercentInstance();
        Intrinsics.checkNotNullExpressionValue(percentInstance, "getPercentInstance()");
        percentInstance.setMaximumIntegerDigits(IntegerDigits);
        percentInstance.setMinimumFractionDigits(FractionDigits);
        return percentInstance.format(d2);
    }

    @NotNull
    public final String getTaskId() {
        return this.taskId;
    }

    @Override // androidx.fragment.app.DialogFragment
    @NotNull
    public Dialog onCreateDialog(@Nullable Bundle savedInstanceState) {
        return getAlertDialog();
    }

    @Override // androidx.fragment.app.DialogFragment, androidx.fragment.app.Fragment
    public void onDestroyView() {
        super.onDestroyView();
        C4909c.m5569b().m5580m(this);
    }

    /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue
    java.lang.NullPointerException: Cannot invoke "java.util.List.iterator()" because the return value of "jadx.core.dex.visitors.regions.SwitchOverStringVisitor$SwitchData.getNewCases()" is null
    	at jadx.core.dex.visitors.regions.SwitchOverStringVisitor.restoreSwitchOverString(SwitchOverStringVisitor.java:109)
    	at jadx.core.dex.visitors.regions.SwitchOverStringVisitor.visitRegion(SwitchOverStringVisitor.java:66)
    	at jadx.core.dex.visitors.regions.DepthRegionTraversal.traverseIterativeStepInternal(DepthRegionTraversal.java:77)
    	at jadx.core.dex.visitors.regions.DepthRegionTraversal.traverseIterativeStepInternal(DepthRegionTraversal.java:82)
     */
    @InterfaceC4919m(threadMode = ThreadMode.MAIN)
    public final void onEventDownload(@NotNull EventDownload eventDownload) {
        Intrinsics.checkNotNullParameter(eventDownload, "eventDownload");
        DownloadVideoInfo downloadVideoInfo = eventDownload.getDownloadVideoInfo();
        this.mDownloadVideoInfo = downloadVideoInfo;
        String str = downloadVideoInfo.status;
        if (str != null) {
            switch (str.hashCode()) {
                case -1402931637:
                    if (str.equals("completed")) {
                        getPb_progress().setProgress(100);
                        getItv_progressTxt().setVisibility(8);
                        getTv_goPhotos().setVisibility(0);
                        getItv_progressTxt().setText("");
                        C2354n.m2374A(getRl_downlod(), 0L, new Function1<RelativeLayout, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.DownloadBottomDialog$onEventDownload$3
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
                                DownloadBottomDialog.this.dismissAllowingStateLoss();
                                FragmentActivity context = DownloadBottomDialog.this.requireActivity();
                                Intrinsics.checkNotNullExpressionValue(context, "requireActivity()");
                                Intrinsics.checkNotNullParameter(context, "context");
                                context.startActivity(new Intent("android.intent.action.VIEW", MediaStore.Video.Media.EXTERNAL_CONTENT_URI));
                            }
                        }, 1);
                        getTv_cancel().setText("取消");
                        return;
                    }
                    break;
                case 3641717:
                    if (str.equals("wait")) {
                        getPb_progress().setProgress(100);
                        getItv_progressTxt().setVisibility(0);
                        getTv_goPhotos().setVisibility(8);
                        getItv_progressTxt().setText("等待中");
                        getTv_cancel().setText("取消保存");
                        C2354n.m2374A(getRl_downlod(), 0L, new Function1<RelativeLayout, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.DownloadBottomDialog$onEventDownload$2
                            @Override // kotlin.jvm.functions.Function1
                            public /* bridge */ /* synthetic */ Unit invoke(RelativeLayout relativeLayout) {
                                invoke2(relativeLayout);
                                return Unit.INSTANCE;
                            }

                            /* renamed from: invoke, reason: avoid collision after fix types in other method */
                            public final void invoke2(@NotNull RelativeLayout it) {
                                Intrinsics.checkNotNullParameter(it, "it");
                                C2354n.m2451Z1("请等待下载...");
                            }
                        }, 1);
                        return;
                    }
                    break;
                case 95763319:
                    if (str.equals("doing")) {
                        double size = downloadVideoInfo.successCount / downloadVideoInfo.files.size();
                        getPb_progress().setProgress((int) (100 * size));
                        getItv_progressTxt().setVisibility(0);
                        getTv_goPhotos().setVisibility(8);
                        getItv_progressTxt().setText(Intrinsics.stringPlus("下载中 ", getPercentFormat(size, 2, 1)));
                        getTv_cancel().setText("取消保存");
                        getRl_downlod().setOnClickListener(null);
                        return;
                    }
                    break;
                case 96784904:
                    if (str.equals("error")) {
                        getPb_progress().setProgress(100);
                        getItv_progressTxt().setVisibility(0);
                        getTv_goPhotos().setVisibility(8);
                        getItv_progressTxt().setText("下载失败");
                        getTv_cancel().setText("取消保存");
                        C2354n.m2374A(getRl_downlod(), 0L, new Function1<RelativeLayout, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.DownloadBottomDialog$onEventDownload$1
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
                                DownloadBottomDialog.this.dismissAllowingStateLoss();
                                C2354n.m2449Z("下载失败，请尝试重新下载！");
                            }
                        }, 1);
                        return;
                    }
                    break;
            }
        }
        getPb_progress().setProgress(100);
        getItv_progressTxt().setVisibility(0);
        getTv_goPhotos().setVisibility(8);
        getItv_progressTxt().setText("下载失败");
        getTv_cancel().setText("取消保存");
        C2354n.m2374A(getRl_downlod(), 0L, new Function1<RelativeLayout, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.DownloadBottomDialog$onEventDownload$4
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
                DownloadBottomDialog.this.dismissAllowingStateLoss();
                C2354n.m2449Z("下载失败，请尝试重新下载！");
            }
        }, 1);
    }

    @Override // androidx.fragment.app.DialogFragment, androidx.fragment.app.Fragment
    public void onStart() {
        super.onStart();
        if (C4909c.m5569b().m5573f(this)) {
            return;
        }
        C4909c.m5569b().m5578k(this);
    }
}
