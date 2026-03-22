package com.jbzd.media.movecartoons.utils.banner;

import android.view.View;
import androidx.recyclerview.widget.RecyclerView;
import com.jbzd.media.movecartoons.MyApp;
import com.jbzd.media.movecartoons.view.video.BannerPlayerView;
import com.qnmd.adnnm.da0yzo.R;
import java.util.Map;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0018\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0004\u0018\u00002\u00020\u0001B\u000f\u0012\u0006\u0010\t\u001a\u00020\b¢\u0006\u0004\b\n\u0010\u000bR\u0019\u0010\u0007\u001a\u00020\u00028\u0006@\u0006¢\u0006\f\n\u0004\b\u0003\u0010\u0004\u001a\u0004\b\u0005\u0010\u0006¨\u0006\f"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/utils/banner/VideoHolder;", "Landroidx/recyclerview/widget/RecyclerView$ViewHolder;", "Lcom/jbzd/media/movecartoons/view/video/BannerPlayerView;", "a", "Lcom/jbzd/media/movecartoons/view/video/BannerPlayerView;", "getPlayer", "()Lcom/jbzd/media/movecartoons/view/video/BannerPlayerView;", "player", "Landroid/view/View;", "view", "<init>", "(Landroid/view/View;)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class VideoHolder extends RecyclerView.ViewHolder {

    /* renamed from: a, reason: from kotlin metadata */
    @NotNull
    public final BannerPlayerView player;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public VideoHolder(@NotNull View view) {
        super(view);
        Intrinsics.checkNotNullParameter(view, "view");
        View findViewById = view.findViewById(R.id.banner_player);
        BannerPlayerView bannerPlayerView = (BannerPlayerView) findViewById;
        Map<String, String> mapHeadData = bannerPlayerView.getMapHeadData();
        Intrinsics.checkNotNullExpressionValue(mapHeadData, "mapHeadData");
        MyApp myApp = MyApp.f9891f;
        mapHeadData.put("referer", MyApp.m4185f().cdn_header);
        Map<String, String> mapHeadData2 = bannerPlayerView.getMapHeadData();
        Intrinsics.checkNotNullExpressionValue(mapHeadData2, "mapHeadData");
        mapHeadData2.put("allowCrossProtocolRedirects", "true");
        Unit unit = Unit.INSTANCE;
        Intrinsics.checkNotNullExpressionValue(findViewById, "view.findViewById<BannerPlayerView?>(R.id.banner_player).apply {\n        mapHeadData[\"referer\"] = MyApp.systemBean.cdn_header\n        mapHeadData[\"allowCrossProtocolRedirects\"] = \"true\"\n    }");
        this.player = bannerPlayerView;
    }
}
