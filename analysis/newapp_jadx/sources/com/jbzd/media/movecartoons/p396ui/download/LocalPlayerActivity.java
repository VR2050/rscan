package com.jbzd.media.movecartoons.p396ui.download;

import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.view.View;
import android.widget.FrameLayout;
import android.widget.TextView;
import com.gyf.immersionbar.ImmersionBar;
import com.jbzd.media.movecartoons.R$id;
import com.jbzd.media.movecartoons.bean.response.DownloadListBean;
import com.jbzd.media.movecartoons.p396ui.download.LocalPlayerActivity;
import com.jbzd.media.movecartoons.view.video.FullPlayerView;
import com.qnmd.adnnm.da0yzo.R;
import com.qunidayede.supportlibrary.core.view.BaseActivity;
import java.io.File;
import java.io.Serializable;
import java.util.Objects;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.collections.CollectionsKt__CollectionsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p362y.p363a.C2920c;
import p005b.p362y.p363a.p367g.C2934c;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000 \n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0004\n\u0002\u0010\b\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\b\u0018\u0000 \u00142\u00020\u0001:\u0001\u0014B\u0007¢\u0006\u0004\b\u0013\u0010\u0004J\u000f\u0010\u0003\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\u0003\u0010\u0004J\u000f\u0010\u0005\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\u0005\u0010\u0004J\u000f\u0010\u0006\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\u0006\u0010\u0004J\u000f\u0010\b\u001a\u00020\u0007H\u0016¢\u0006\u0004\b\b\u0010\tJ\u000f\u0010\n\u001a\u00020\u0002H\u0014¢\u0006\u0004\b\n\u0010\u0004J\u000f\u0010\u000b\u001a\u00020\u0002H\u0014¢\u0006\u0004\b\u000b\u0010\u0004J\u000f\u0010\f\u001a\u00020\u0002H\u0014¢\u0006\u0004\b\f\u0010\u0004R\u001d\u0010\u0012\u001a\u00020\r8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u000e\u0010\u000f\u001a\u0004\b\u0010\u0010\u0011¨\u0006\u0015"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/download/LocalPlayerActivity;", "Lcom/qunidayede/supportlibrary/core/view/BaseActivity;", "", "bindEvent", "()V", "initStatusBar", "onBackPressed", "", "getLayoutId", "()I", "onPause", "onResume", "onDestroy", "Lcom/jbzd/media/movecartoons/bean/response/DownloadListBean;", "bean$delegate", "Lkotlin/Lazy;", "getBean", "()Lcom/jbzd/media/movecartoons/bean/response/DownloadListBean;", "bean", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class LocalPlayerActivity extends BaseActivity {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    /* renamed from: bean$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy bean = LazyKt__LazyJVMKt.lazy(new Function0<DownloadListBean>() { // from class: com.jbzd.media.movecartoons.ui.download.LocalPlayerActivity$bean$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final DownloadListBean invoke() {
            Serializable serializableExtra = LocalPlayerActivity.this.getIntent().getSerializableExtra("bean");
            Objects.requireNonNull(serializableExtra, "null cannot be cast to non-null type com.jbzd.media.movecartoons.bean.response.DownloadListBean");
            return (DownloadListBean) serializableExtra;
        }
    });

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u001c\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0005\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\t\u0010\nJ\u001d\u0010\u0007\u001a\u00020\u00062\u0006\u0010\u0003\u001a\u00020\u00022\u0006\u0010\u0005\u001a\u00020\u0004¢\u0006\u0004\b\u0007\u0010\b¨\u0006\u000b"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/download/LocalPlayerActivity$Companion;", "", "Landroid/content/Context;", "context", "Lcom/jbzd/media/movecartoons/bean/response/DownloadListBean;", "item", "", "start", "(Landroid/content/Context;Lcom/jbzd/media/movecartoons/bean/response/DownloadListBean;)V", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public final void start(@NotNull Context context, @NotNull DownloadListBean item) {
            Intrinsics.checkNotNullParameter(context, "context");
            Intrinsics.checkNotNullParameter(item, "item");
            Intent intent = new Intent(context, (Class<?>) LocalPlayerActivity.class);
            intent.putExtra("bean", item);
            Unit unit = Unit.INSTANCE;
            context.startActivity(intent);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: bindEvent$lambda-4$lambda-0, reason: not valid java name */
    public static final void m5800bindEvent$lambda4$lambda0(LocalPlayerActivity this$0, View view) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        this$0.finish();
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: bindEvent$lambda-4$lambda-1, reason: not valid java name */
    public static final void m5801bindEvent$lambda4$lambda1(LocalPlayerActivity this$0, FullPlayerView fullPlayerView, View view) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        ((FullPlayerView) this$0.findViewById(R$id.full_player)).startWindowFullscreen(fullPlayerView.getContext(), false, true);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: bindEvent$lambda-4$lambda-3, reason: not valid java name */
    public static final void m5803bindEvent$lambda4$lambda3(LocalPlayerActivity this$0) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        ((TextView) this$0.findViewById(R$id.btn_replay)).setVisibility(0);
        ((FrameLayout) this$0.findViewById(R$id.fl_replay)).setVisibility(0);
    }

    private final DownloadListBean getBean() {
        return (DownloadListBean) this.bean.getValue();
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseActivity
    public void _$_clearFindViewByIdCache() {
    }

    @Override // p005b.p327w.p330b.p331b.p334e.InterfaceC2847j
    public void bindEvent() {
        if (getBean() == null) {
            C2354n.m2379B1("资源出错");
            finish();
        }
        C2920c.m3394c().f7996f = CollectionsKt__CollectionsKt.arrayListOf(new C2934c(1, "protocol_whitelist", "crypto,file,http,https,tcp,tls,udp"));
        Uri fromFile = Uri.fromFile(new File(getBean().localUrl));
        C2354n.m2374A((TextView) findViewById(R$id.btn_replay), 0L, new Function1<TextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.download.LocalPlayerActivity$bindEvent$1
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(TextView textView) {
                invoke2(textView);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(TextView textView) {
                textView.setVisibility(8);
                ((FrameLayout) LocalPlayerActivity.this.findViewById(R$id.fl_replay)).setVisibility(8);
                ((FullPlayerView) LocalPlayerActivity.this.findViewById(R$id.full_player)).startPlayLogic();
            }
        }, 1);
        final FullPlayerView fullPlayerView = (FullPlayerView) findViewById(R$id.full_player);
        fullPlayerView.getBackButton().setOnClickListener(new View.OnClickListener() { // from class: b.a.a.a.t.f.d
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                LocalPlayerActivity.m5800bindEvent$lambda4$lambda0(LocalPlayerActivity.this, view);
            }
        });
        fullPlayerView.setShowFullAnimation(false);
        fullPlayerView.setNeedLockFull(true);
        fullPlayerView.setAutoFullWithSize(true);
        fullPlayerView.loadCoverImage(getBean().img_x);
        fullPlayerView.getFullscreenButton().setOnClickListener(new View.OnClickListener() { // from class: b.a.a.a.t.f.c
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                LocalPlayerActivity.m5801bindEvent$lambda4$lambda1(LocalPlayerActivity.this, fullPlayerView, view);
            }
        });
        fullPlayerView.setUp(fromFile.getPath(), true, getBean().name);
        fullPlayerView.postDelayed(new Runnable() { // from class: b.a.a.a.t.f.b
            @Override // java.lang.Runnable
            public final void run() {
                FullPlayerView.this.startPlayLogic();
            }
        }, 400L);
        fullPlayerView.setCallBack(new FullPlayerView.VideoCallBack() { // from class: b.a.a.a.t.f.e
            @Override // com.jbzd.media.movecartoons.view.video.FullPlayerView.VideoCallBack
            public final void onAutoComplete() {
                LocalPlayerActivity.m5803bindEvent$lambda4$lambda3(LocalPlayerActivity.this);
            }
        });
    }

    @Override // p005b.p327w.p330b.p331b.p334e.InterfaceC2847j
    public int getLayoutId() {
        return R.layout.activity_local_player;
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseActivity
    public void initStatusBar() {
        super.initStatusBar();
        ImmersionBar.with(this).fitsSystemWindows(true).statusBarColorInt(getResources().getColor(R.color.black)).statusBarDarkFont(true).init();
    }

    @Override // androidx.activity.ComponentActivity, android.app.Activity
    public void onBackPressed() {
        if (C2920c.m3393b(this)) {
            return;
        }
        super.onBackPressed();
    }

    @Override // androidx.appcompat.app.AppCompatActivity, androidx.fragment.app.FragmentActivity, android.app.Activity
    public void onDestroy() {
        super.onDestroy();
        C2920c.m3397f();
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseActivity, androidx.fragment.app.FragmentActivity, android.app.Activity
    public void onPause() {
        super.onPause();
        C2920c.m3395d();
    }

    @Override // androidx.fragment.app.FragmentActivity, android.app.Activity
    public void onResume() {
        super.onResume();
        C2920c.m3396e();
    }
}
