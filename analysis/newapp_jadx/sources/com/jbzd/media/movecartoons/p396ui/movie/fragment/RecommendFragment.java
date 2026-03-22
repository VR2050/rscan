package com.jbzd.media.movecartoons.p396ui.movie.fragment;

import android.os.Bundle;
import androidx.core.app.NotificationCompat;
import com.jbzd.media.movecartoons.bean.event.EventMoviBottom;
import com.jbzd.media.movecartoons.p396ui.search.child.CommonLongListFragment;
import java.util.HashMap;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.greenrobot.eventbus.ThreadMode;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p476m.p496b.p497a.C4909c;
import p476m.p496b.p497a.InterfaceC4919m;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u00004\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u000e\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0010\u000b\n\u0002\b\r\u0018\u0000  2\u00020\u0001:\u0001 B\u0007¢\u0006\u0004\b\u001f\u0010\u000bJ\u000f\u0010\u0003\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\u0003\u0010\u0004J+\u0010\u0007\u001a\u001e\u0012\u0004\u0012\u00020\u0002\u0012\u0004\u0012\u00020\u00020\u0005j\u000e\u0012\u0004\u0012\u00020\u0002\u0012\u0004\u0012\u00020\u0002`\u0006H\u0016¢\u0006\u0004\b\u0007\u0010\bJ\u000f\u0010\n\u001a\u00020\tH\u0016¢\u0006\u0004\b\n\u0010\u000bJ\u000f\u0010\f\u001a\u00020\tH\u0016¢\u0006\u0004\b\f\u0010\u000bJ\u0017\u0010\u000f\u001a\u00020\t2\u0006\u0010\u000e\u001a\u00020\rH\u0007¢\u0006\u0004\b\u000f\u0010\u0010J\u0015\u0010\u0012\u001a\u00020\t2\u0006\u0010\u0011\u001a\u00020\u0002¢\u0006\u0004\b\u0012\u0010\u0013J\u000f\u0010\u0015\u001a\u00020\u0014H\u0016¢\u0006\u0004\b\u0015\u0010\u0016J\u000f\u0010\u0017\u001a\u00020\u0014H\u0016¢\u0006\u0004\b\u0017\u0010\u0016R\u001d\u0010\u001b\u001a\u00020\u00028B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u0018\u0010\u0019\u001a\u0004\b\u001a\u0010\u0004R\u001d\u0010\u001e\u001a\u00020\u00028B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u001c\u0010\u0019\u001a\u0004\b\u001d\u0010\u0004¨\u0006!"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/movie/fragment/RecommendFragment;", "Lcom/jbzd/media/movecartoons/ui/search/child/CommonLongListFragment;", "", "getRequestUrl", "()Ljava/lang/String;", "Ljava/util/HashMap;", "Lkotlin/collections/HashMap;", "getRequestBody", "()Ljava/util/HashMap;", "", "onStart", "()V", "onDestroyView", "Lcom/jbzd/media/movecartoons/bean/event/EventMoviBottom;", NotificationCompat.CATEGORY_EVENT, "updateVideo", "(Lcom/jbzd/media/movecartoons/bean/event/EventMoviBottom;)V", "videoId", "updateVideoId", "(Ljava/lang/String;)V", "", "getRefreshEnable", "()Z", "getLoadMoreEnable", "mType$delegate", "Lkotlin/Lazy;", "getMType", "mType", "mVideoId$delegate", "getMVideoId", "mVideoId", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class RecommendFragment extends CommonLongListFragment {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    @NotNull
    public static final String key_type = "type";

    @NotNull
    public static final String key_video_id = "video_id";

    /* renamed from: mVideoId$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mVideoId = LazyKt__LazyJVMKt.lazy(new Function0<String>() { // from class: com.jbzd.media.movecartoons.ui.movie.fragment.RecommendFragment$mVideoId$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final String invoke() {
            String string;
            Bundle arguments = RecommendFragment.this.getArguments();
            return (arguments == null || (string = arguments.getString(RecommendFragment.key_video_id)) == null) ? "" : string;
        }
    });

    /* renamed from: mType$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mType = LazyKt__LazyJVMKt.lazy(new Function0<String>() { // from class: com.jbzd.media.movecartoons.ui.movie.fragment.RecommendFragment$mType$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final String invoke() {
            String string;
            Bundle arguments = RecommendFragment.this.getArguments();
            return (arguments == null || (string = arguments.getString("type")) == null) ? "" : string;
        }
    });

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0018\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\u000e\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\b\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u000b\u0010\fJ\u001f\u0010\u0006\u001a\u00020\u00052\b\u0010\u0003\u001a\u0004\u0018\u00010\u00022\u0006\u0010\u0004\u001a\u00020\u0002¢\u0006\u0004\b\u0006\u0010\u0007R\u0016\u0010\b\u001a\u00020\u00028\u0006@\u0006X\u0086T¢\u0006\u0006\n\u0004\b\b\u0010\tR\u0016\u0010\n\u001a\u00020\u00028\u0006@\u0006X\u0086T¢\u0006\u0006\n\u0004\b\n\u0010\t¨\u0006\r"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/movie/fragment/RecommendFragment$Companion;", "", "", "videoId", "type", "Lcom/jbzd/media/movecartoons/ui/movie/fragment/RecommendFragment;", "newInstance", "(Ljava/lang/String;Ljava/lang/String;)Lcom/jbzd/media/movecartoons/ui/movie/fragment/RecommendFragment;", "key_type", "Ljava/lang/String;", com.jbzd.media.movecartoons.p396ui.movie.RecommendFragment.key_video_id, "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        @NotNull
        public final RecommendFragment newInstance(@Nullable String videoId, @NotNull String type) {
            Intrinsics.checkNotNullParameter(type, "type");
            RecommendFragment recommendFragment = new RecommendFragment();
            Bundle bundle = new Bundle();
            bundle.putString(RecommendFragment.key_video_id, videoId);
            bundle.putString("type", type);
            Unit unit = Unit.INSTANCE;
            recommendFragment.setArguments(bundle);
            return recommendFragment;
        }
    }

    private final String getMType() {
        return (String) this.mType.getValue();
    }

    private final String getMVideoId() {
        return (String) this.mVideoId.getValue();
    }

    @Override // com.jbzd.media.movecartoons.p396ui.search.child.CommonLongListFragment, com.jbzd.media.movecartoons.p396ui.search.child.BaseCommonVideoListFragment, com.jbzd.media.movecartoons.core.BaseListFragment, com.jbzd.media.movecartoons.core.MyThemeFragment, com.qunidayede.supportlibrary.core.view.BaseThemeFragment, com.qunidayede.supportlibrary.core.view.BaseFragment
    public void _$_clearFindViewByIdCache() {
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    public boolean getLoadMoreEnable() {
        return false;
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    public boolean getRefreshEnable() {
        return false;
    }

    @Override // com.jbzd.media.movecartoons.p396ui.search.child.CommonLongListFragment, com.jbzd.media.movecartoons.p396ui.search.child.BaseCommonVideoListFragment
    @NotNull
    public HashMap<String, String> getRequestBody() {
        HashMap<String, String> hashMap = new HashMap<>();
        hashMap.put("id", getMVideoId());
        hashMap.put("type", getMType());
        return hashMap;
    }

    @Override // com.jbzd.media.movecartoons.p396ui.search.child.BaseCommonVideoListFragment
    @NotNull
    public String getRequestUrl() {
        return "video/detailList";
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment, androidx.fragment.app.Fragment
    public void onDestroyView() {
        super.onDestroyView();
        C4909c.m5569b().m5580m(this);
    }

    @Override // androidx.fragment.app.Fragment
    public void onStart() {
        super.onStart();
        if (C4909c.m5569b().m5573f(this)) {
            return;
        }
        C4909c.m5569b().m5578k(this);
    }

    @InterfaceC4919m(threadMode = ThreadMode.MAIN)
    public final void updateVideo(@NotNull EventMoviBottom event) {
        Intrinsics.checkNotNullParameter(event, "event");
        String str = event.videoId;
        Intrinsics.checkNotNullExpressionValue(str, "event.videoId");
        updateVideoId(str);
    }

    public final void updateVideoId(@NotNull String videoId) {
        Intrinsics.checkNotNullParameter(videoId, "videoId");
        getRequestRoomParameter().put("id", videoId);
        reset();
    }
}
