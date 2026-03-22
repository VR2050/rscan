package com.jbzd.media.movecartoons.p396ui.preview;

import android.app.Application;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.text.TextUtils;
import android.util.ArrayMap;
import android.widget.ImageView;
import com.alibaba.fastjson.asm.Label;
import com.gyf.immersionbar.ImmersionBar;
import com.jbzd.media.movecartoons.MyApp;
import com.jbzd.media.movecartoons.p396ui.preview.PreviewVideoActivity;
import com.jbzd.media.movecartoons.view.video.FullPlayerView;
import com.qnmd.adnnm.da0yzo.R;
import com.qunidayede.supportlibrary.core.view.BaseActivity;
import java.io.File;
import java.util.Map;
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
import p005b.p325v.p326a.C2818e;
import p005b.p362y.p363a.C2920c;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u00002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\b\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\u0010\u000e\n\u0002\b\u0007\u0018\u0000 \u001d2\u00020\u0001:\u0001\u001dB\u0007¢\u0006\u0004\b\u001c\u0010\bJ\u0019\u0010\u0005\u001a\u00020\u00042\b\u0010\u0003\u001a\u0004\u0018\u00010\u0002H\u0014¢\u0006\u0004\b\u0005\u0010\u0006J\u000f\u0010\u0007\u001a\u00020\u0004H\u0016¢\u0006\u0004\b\u0007\u0010\bJ\u000f\u0010\t\u001a\u00020\u0004H\u0014¢\u0006\u0004\b\t\u0010\bJ\u000f\u0010\n\u001a\u00020\u0004H\u0014¢\u0006\u0004\b\n\u0010\bJ\u000f\u0010\u000b\u001a\u00020\u0004H\u0014¢\u0006\u0004\b\u000b\u0010\bJ\u000f\u0010\f\u001a\u00020\u0004H\u0016¢\u0006\u0004\b\f\u0010\bJ\u000f\u0010\u000e\u001a\u00020\rH\u0016¢\u0006\u0004\b\u000e\u0010\u000fR\u001d\u0010\u0015\u001a\u00020\u00108F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u0011\u0010\u0012\u001a\u0004\b\u0013\u0010\u0014R)\u0010\u001b\u001a\u000e\u0012\u0004\u0012\u00020\u0017\u0012\u0004\u0012\u00020\u00170\u00168B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u0018\u0010\u0012\u001a\u0004\b\u0019\u0010\u001a¨\u0006\u001e"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/preview/PreviewVideoActivity;", "Lcom/qunidayede/supportlibrary/core/view/BaseActivity;", "Landroid/os/Bundle;", "savedInstanceState", "", "onCreate", "(Landroid/os/Bundle;)V", "bindEvent", "()V", "onPause", "onResume", "onDestroy", "onBackPressed", "", "getLayoutId", "()I", "Lcom/jbzd/media/movecartoons/view/video/FullPlayerView;", "full_player$delegate", "Lkotlin/Lazy;", "getFull_player", "()Lcom/jbzd/media/movecartoons/view/video/FullPlayerView;", "full_player", "Landroid/util/ArrayMap;", "", "videoPlayHeader$delegate", "getVideoPlayHeader", "()Landroid/util/ArrayMap;", "videoPlayHeader", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class PreviewVideoActivity extends BaseActivity {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);
    public static String videoUrl;

    /* renamed from: full_player$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy full_player = LazyKt__LazyJVMKt.lazy(new Function0<FullPlayerView>() { // from class: com.jbzd.media.movecartoons.ui.preview.PreviewVideoActivity$full_player$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final FullPlayerView invoke() {
            FullPlayerView fullPlayerView = (FullPlayerView) PreviewVideoActivity.this.findViewById(R.id.full_player);
            Intrinsics.checkNotNull(fullPlayerView);
            return fullPlayerView;
        }
    });

    /* renamed from: videoPlayHeader$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy videoPlayHeader = LazyKt__LazyJVMKt.lazy(new Function0<ArrayMap<String, String>>() { // from class: com.jbzd.media.movecartoons.ui.preview.PreviewVideoActivity$videoPlayHeader$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ArrayMap<String, String> invoke() {
            ArrayMap<String, String> arrayMap = new ArrayMap<>();
            MyApp myApp = MyApp.f9891f;
            arrayMap.put("referer", MyApp.m4185f().cdn_header);
            return arrayMap;
        }
    });

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u001c\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u000b\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u000f\u0010\u0010J\u001d\u0010\u0007\u001a\u00020\u00062\u0006\u0010\u0003\u001a\u00020\u00022\u0006\u0010\u0005\u001a\u00020\u0004¢\u0006\u0004\b\u0007\u0010\bR\"\u0010\t\u001a\u00020\u00048\u0006@\u0006X\u0086.¢\u0006\u0012\n\u0004\b\t\u0010\n\u001a\u0004\b\u000b\u0010\f\"\u0004\b\r\u0010\u000e¨\u0006\u0011"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/preview/PreviewVideoActivity$Companion;", "", "Landroid/content/Context;", "context", "", "url", "", "start", "(Landroid/content/Context;Ljava/lang/String;)V", "videoUrl", "Ljava/lang/String;", "getVideoUrl", "()Ljava/lang/String;", "setVideoUrl", "(Ljava/lang/String;)V", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        @NotNull
        public final String getVideoUrl() {
            String str = PreviewVideoActivity.videoUrl;
            if (str != null) {
                return str;
            }
            Intrinsics.throwUninitializedPropertyAccessException("videoUrl");
            throw null;
        }

        public final void setVideoUrl(@NotNull String str) {
            Intrinsics.checkNotNullParameter(str, "<set-?>");
            PreviewVideoActivity.videoUrl = str;
        }

        public final void start(@NotNull Context context, @NotNull String url) {
            Intrinsics.checkNotNullParameter(context, "context");
            Intrinsics.checkNotNullParameter(url, "url");
            setVideoUrl(url);
            Intent intent = new Intent(context, (Class<?>) PreviewVideoActivity.class);
            if (context instanceof Application) {
                intent.addFlags(Label.FORWARD_REFERENCE_TYPE_SHORT);
            }
            intent.putExtra("videoUrl", url);
            context.startActivity(intent);
        }
    }

    private final ArrayMap<String, String> getVideoPlayHeader() {
        return (ArrayMap) this.videoPlayHeader.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: onCreate$lambda-1$lambda-0, reason: not valid java name */
    public static final void m5974onCreate$lambda1$lambda0(FullPlayerView this_run) {
        Intrinsics.checkNotNullParameter(this_run, "$this_run");
        this_run.startPlayLogic();
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseActivity
    public void _$_clearFindViewByIdCache() {
    }

    @Override // p005b.p327w.p330b.p331b.p334e.InterfaceC2847j
    public void bindEvent() {
    }

    @NotNull
    public final FullPlayerView getFull_player() {
        return (FullPlayerView) this.full_player.getValue();
    }

    @Override // p005b.p327w.p330b.p331b.p334e.InterfaceC2847j
    public int getLayoutId() {
        ImmersionBar.with(this).statusBarColor(R.color.bgBlack).init();
        return R.layout.preview_video_act;
    }

    @Override // androidx.activity.ComponentActivity, android.app.Activity
    public void onBackPressed() {
        if (C2920c.m3393b(this)) {
            return;
        }
        super.onBackPressed();
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseActivity, androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    public void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Companion companion = INSTANCE;
        String stringExtra = getIntent().getStringExtra("videoUrl");
        if (stringExtra == null) {
            stringExtra = "";
        }
        companion.setVideoUrl(stringExtra);
        if (TextUtils.isEmpty(companion.getVideoUrl())) {
            C2354n.m2449Z("资源错误");
            finish();
        }
        final FullPlayerView full_player = getFull_player();
        C2354n.m2374A(full_player.getBackButton(), 0L, new Function1<ImageView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.preview.PreviewVideoActivity$onCreate$1$1
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
                PreviewVideoActivity.this.finish();
            }
        }, 1);
        full_player.setShowFullAnimation(false);
        full_player.setNeedLockFull(true);
        full_player.setAutoFullWithSize(true);
        C2354n.m2374A(full_player.getFullscreenButton(), 0L, new Function1<ImageView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.preview.PreviewVideoActivity$onCreate$1$2
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
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
                PreviewVideoActivity.this.getFull_player().startWindowFullscreen(full_player.getContext(), false, true);
            }
        }, 1);
        C2818e.m3272a(companion.getVideoUrl(), new Object[0]);
        full_player.setUp(companion.getVideoUrl(), false, (File) null, (Map<String, String>) getVideoPlayHeader(), "");
        full_player.postDelayed(new Runnable() { // from class: b.a.a.a.t.l.a
            @Override // java.lang.Runnable
            public final void run() {
                PreviewVideoActivity.m5974onCreate$lambda1$lambda0(FullPlayerView.this);
            }
        }, 200L);
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
