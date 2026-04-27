package im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.config;

import android.content.Context;
import com.bjz.comm.net.utils.HttpUtils;
import com.danikula.videocache.HttpProxyCacheServer;
import com.danikula.videocache.ProxyCacheUtils;
import com.danikula.videocache.file.Md5FileNameGenerator;
import com.danikula.videocache.headers.HeaderInjector;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.factory.IVideoPlayerFactory;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.factory.MediaPlayerFactory;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.utils.Utils;
import java.io.File;
import java.util.HashMap;
import java.util.Map;

/* JADX INFO: loaded from: classes5.dex */
public final class VideoPlayerConfig {
    private static final int DEFAULT_VIDEO_CACHE_COUNT = 10;
    private boolean mCacheEnable;
    private HttpProxyCacheServer mCacheProxy;
    private boolean mLogEnable;
    private IVideoPlayerFactory mPlayerFactory;
    private boolean mSmallWindowPlayEnable;

    private VideoPlayerConfig(Builder builder) {
        this.mPlayerFactory = builder.playerFactory;
        this.mSmallWindowPlayEnable = builder.smallWindowPlayEnable;
        this.mCacheEnable = builder.cacheEnable;
        this.mCacheProxy = builder.proxy;
        this.mLogEnable = builder.logEnable;
    }

    public IVideoPlayerFactory getPlayerFactory() {
        return this.mPlayerFactory;
    }

    public boolean isSmallWindowPlayEnable() {
        return this.mSmallWindowPlayEnable;
    }

    public boolean isCacheEnable() {
        return this.mCacheEnable;
    }

    public HttpProxyCacheServer getCacheProxy() {
        return this.mCacheProxy;
    }

    public static final class Builder {
        private Context context;
        private boolean logEnable;
        private IVideoPlayerFactory playerFactory;
        private HttpProxyCacheServer proxy;
        private boolean smallWindowPlayEnable = false;
        private boolean cacheEnable = false;

        public Builder(Context ctx) {
            this.context = ctx;
        }

        public Builder() {
        }

        public Builder buildPlayerFactory(IVideoPlayerFactory factory) {
            this.playerFactory = factory;
            return this;
        }

        public Builder enableSmallWindowPlay() {
            this.smallWindowPlayEnable = true;
            return this;
        }

        public Builder enableCache(boolean cacheEnable) {
            this.cacheEnable = cacheEnable;
            return this;
        }

        public Builder enableLog(boolean logEnable) {
            this.logEnable = logEnable;
            return this;
        }

        public Builder cacheProxy(HttpProxyCacheServer cacheProxy) {
            this.proxy = cacheProxy;
            return this;
        }

        public VideoPlayerConfig build() {
            this.playerFactory.logEnable(this.logEnable);
            if (this.playerFactory == null) {
                this.playerFactory = new MediaPlayerFactory();
            }
            if (this.cacheEnable && this.proxy == null) {
                this.proxy = buildCacheProxy();
            }
            return new VideoPlayerConfig(this);
        }

        private HttpProxyCacheServer buildCacheProxy() {
            return new HttpProxyCacheServer.Builder(this.context.getApplicationContext()).headerInjector(new HeaderInjector() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.config.VideoPlayerConfig.Builder.2
                @Override // com.danikula.videocache.headers.HeaderInjector
                public Map<String, String> addHeaders(String url) {
                    Map<String, String> map = new HashMap<>();
                    map.put("user-agent", HttpUtils.getInstance().getUserAgentFC());
                    return map;
                }
            }).cacheDirectory(new File(Utils.getCacheDir(this.context))).fileNameGenerator(new Md5FileNameGenerator() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.config.VideoPlayerConfig.Builder.1
                @Override // com.danikula.videocache.file.Md5FileNameGenerator, com.danikula.videocache.file.FileNameGenerator
                public String generate(String url) {
                    return ProxyCacheUtils.computeMD5(url);
                }
            }).maxCacheFilesCount(10).build();
        }
    }
}
